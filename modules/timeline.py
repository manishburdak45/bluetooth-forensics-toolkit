"""
modules/timeline.py
====================

Forensic timeline engine for **BlueTrace Forensic Suite**.

This module contains the :class:`ForensicTimeline` class, whose sole
responsibility is to take already-collected, already-structured
evidence events -- typically produced by
:class:`modules.connection_history.ConnectionHistoryAnalyzer` and/or
:mod:`modules.linux_artifacts` -- and organize them into a clean,
deterministic, chronological timeline suitable for investigation and
reporting.

This module performs **no** subprocess execution, **no** live
Bluetooth scanning, **no** connection to any Bluetooth device, and
**no** file I/O of its own. It never prints terminal output and never
modifies the evidence records it is given. It is a pure timeline
*organization/normalization* layer: callers gather structured events
elsewhere and hand them to this module, which validates, normalizes,
deduplicates, orders, and summarizes them. Presentation to a human
(CLI, PDF, JSON, etc.) is the responsibility of ``app.py`` and
``modules/report.py``.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool
intended for lawful digital forensics and incident-response use cases
involving Bluetooth Classic and Bluetooth Low Energy (BLE) devices on
Linux.

Forensic limitations
---------------------
* Timeline quality is entirely bounded by the evidence supplied to
  this module; missing or rotated logs produce an incomplete
  timeline, not a complete one with gaps silently filled in.
* Some evidence carries no reliable timestamp at all (e.g. static
  BlueZ persisted-state artifacts). Such events are preserved in the
  timeline but are never assigned a fabricated date/time, and are
  never sorted as if their position in time were known.
* Bluetooth Low Energy devices using Resolvable/Non-Resolvable
  Private Addresses can rotate their advertised MAC address, which
  can fragment or obscure a single physical device's activity across
  multiple apparent addresses. This module does not attempt any
  cross-address correlation.
* The absence of an event for a given MAC address or time period does
  NOT prove that no activity occurred -- only that no supporting
  evidence for it was found among the sources supplied to this
  module.
* Chronological ordering of events does NOT, by itself, establish the
  physical location of any device or person.
* This timeline does NOT establish human identity or ownership of any
  device. Associating a MAC address with a person is an investigative
  conclusion outside the scope of this module.
* This module never draws or implies investigative conclusions; it
  only organizes evidence that has already been collected and
  structured elsewhere.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from typing import Any, Final

from config import LOG_LEVEL
from modules.utils import is_valid_mac_address, normalize_mac_address

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Value used for fields whose value could not be determined from evidence.
_UNKNOWN_VALUE: Final[str] = "Unknown"

#: The set of event types this module recognizes on input. Kept
#: identical to :data:`modules.connection_history.EVENT_TYPES` so that
#: timeline construction never silently invents a new taxonomy -- and,
#: just as importantly, never silently *collapses* a distinct upstream
#: event type (e.g. ``connection_failed``) down into ``"unknown"``
#: merely because this set failed to keep up with that taxonomy.
EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "connected",
        "disconnected",
        "connection_attempt",
        "connection_failed",
        "authentication_failure",
        "paired",
        "trusted",
        "blocked",
        "discovered",
        "advertised",
        "unknown",
    }
)

#: The set of confidence levels this module recognizes on input.
CONFIDENCE_LEVELS: Final[frozenset[str]] = frozenset(
    {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}
)

#: Keys, in priority order, that may carry a source event's MAC address.
_MAC_KEYS: Final[tuple[str, ...]] = ("mac_address", "mac")

#: Keys, in priority order, that may carry a source event's timestamp.
_TIMESTAMP_KEYS: Final[tuple[str, ...]] = ("timestamp", "date_time", "datetime")


class ForensicTimeline:
    """Organize already-structured forensic evidence into a timeline.

    This class never scans for, connects to, or otherwise communicates
    with any Bluetooth device, and it performs no filesystem or
    subprocess I/O. It only accepts structured event dictionaries
    (such as those produced by
    :class:`modules.connection_history.ConnectionHistoryAnalyzer` or
    :class:`modules.linux_artifacts.LinuxArtifactsCollector`),
    normalizes them into a single consistent schema, safely
    deduplicates exact repeats while preserving independent
    corroboration, and orders the result newest-first for display or
    reporting.

    Input event dictionaries are treated as read-only: this class
    never mutates a caller-supplied event dictionary in place. All
    normalized output records are newly constructed dictionaries.
    """

    def __init__(self) -> None:
        """Initialize the timeline engine's logger and operational configuration."""
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # ----------------------------------------------------------------- #
    # Timestamp handling
    # ----------------------------------------------------------------- #

    def _parse_timestamp(self, raw_value: Any) -> tuple[datetime | None, str | None]:
        """Safely parse a candidate timestamp value into a datetime.

        Never fabricates a timestamp: any value that cannot be
        unambiguously parsed is treated as "no reliable timestamp"
        rather than guessed at.

        Args:
            raw_value: The candidate timestamp, expected to be an
                ISO-8601 string (e.g. ``"2026-08-13T22:41:18+00:00"``)
                or already a :class:`datetime.datetime` instance.

        Returns:
            A tuple of ``(parsed_datetime, iso_timestamp)``, both
            ``None`` if ``raw_value`` could not be safely parsed.
        """
        if isinstance(raw_value, datetime):
            return raw_value, raw_value.isoformat()

        if isinstance(raw_value, str) and raw_value.strip():
            try:
                parsed = datetime.fromisoformat(raw_value.strip().replace("Z", "+00:00"))
                return parsed, parsed.isoformat()
            except ValueError:
                self._logger.warning(
                    "Could not parse timestamp value; leaving event "
                    "unordered by time: %r", raw_value,
                )
                return None, None

        return None, None

    # ----------------------------------------------------------------- #
    # Event normalization
    # ----------------------------------------------------------------- #

    @staticmethod
    def _make_timeline_id(
        event_id: str,
        mac_address: str,
        event_type: str,
        timestamp: str | None,
        source_type: str,
        source_reference: str,
        raw_reference: str,
    ) -> str:
        """Generate a deterministic identifier for a normalized timeline entry.

        Derived from the entry's own content so that re-running
        timeline construction on the same evidence produces stable,
        comparable identifiers.

        Args:
            event_id: The original event's identifier, if any.
            mac_address: Normalized MAC address associated with the event.
            event_type: One of :data:`EVENT_TYPES`.
            timestamp: The event's ISO-8601 timestamp, or ``None``.
            source_type: A label identifying the evidence source category.
            source_reference: A label identifying the specific evidence
                source instance.
            raw_reference: The raw evidence text/value the event was
                derived from.

        Returns:
            A short, stable, hex-encoded identifier prefixed with ``TL-``.
        """
        digest_input = "|".join(
            [
                event_id,
                mac_address,
                event_type,
                timestamp or "",
                source_type,
                source_reference,
                raw_reference,
            ]
        ).encode("utf-8", errors="replace")
        digest = hashlib.sha256(digest_input).hexdigest()[:16]
        return f"TL-{digest}"

    def normalize_event(self, event: Any, index: int = 0) -> dict[str, Any] | None:
        """Normalize a single caller-supplied event into the timeline schema.

        Accepts events compatible with
        :class:`modules.connection_history.ConnectionHistoryAnalyzer`
        output (or any other module producing dictionaries with
        equivalent keys) and converts them into this module's
        consistent normalized event schema. The input dictionary is
        never modified.

        Args:
            event: A candidate event record. Expected to be a
                dictionary containing at least a MAC address and an
                event type; all other fields are optional.
            index: The event's position in the caller's original input
                sequence. Used only to preserve stable, deterministic
                ordering for events that have no usable timestamp; it
                is not stored on the returned record.

        Returns:
            A normalized timeline event dictionary (see module
            docstring for the schema), or ``None`` if ``event`` is not
            a dictionary or has no usable MAC address. Malformed or
            missing optional fields never cause this method to raise;
            they simply fall back to documented default values.
        """
        if not isinstance(event, dict):
            self._logger.warning(
                "Skipping non-dictionary evidence record at index %d.", index
            )
            return None

        raw_mac: Any = None
        for key in _MAC_KEYS:
            if event.get(key):
                raw_mac = event.get(key)
                break

        if not isinstance(raw_mac, str) or not is_valid_mac_address(raw_mac):
            self._logger.warning(
                "Skipping evidence record at index %d: missing or "
                "invalid MAC address (%r).", index, raw_mac,
            )
            return None

        mac_address = normalize_mac_address(raw_mac) or raw_mac.strip().upper()

        event_type = event.get("event_type", "unknown")
        if event_type not in EVENT_TYPES:
            self._logger.info(
                "Unrecognized event_type %r at index %d; recording as "
                "'unknown' rather than discarding the event.",
                event_type, index,
            )
            event_type = "unknown"

        confidence = event.get("confidence", "UNKNOWN")
        if confidence not in CONFIDENCE_LEVELS:
            confidence = "UNKNOWN"

        raw_timestamp_value: Any = None
        for key in _TIMESTAMP_KEYS:
            if event.get(key):
                raw_timestamp_value = event.get(key)
                break

        parsed_dt, iso_ts = self._parse_timestamp(raw_timestamp_value)

        date_str = event.get("date")
        time_str = event.get("time")
        if parsed_dt is not None:
            date_str = date_str or parsed_dt.strftime("%Y-%m-%d")
            time_str = time_str or parsed_dt.strftime("%H:%M:%S")

        device_name = event.get("device_name")
        if not isinstance(device_name, str) or not device_name.strip():
            device_name = None

        source_type = str(event.get("source_type") or _UNKNOWN_VALUE)
        source_reference = str(event.get("source_reference") or _UNKNOWN_VALUE)
        raw_reference = str(event.get("raw_reference") or "")
        original_event_id = str(event.get("event_id") or "")

        timeline_id = self._make_timeline_id(
            original_event_id,
            mac_address,
            event_type,
            iso_ts,
            source_type,
            source_reference,
            raw_reference,
        )

        corroboration_sources: set[tuple[str, str]] = {(source_type, source_reference)}

        return {
            "timeline_id": timeline_id,
            "event_id": original_event_id or None,
            "timestamp": iso_ts,
            "date": date_str,
            "time": time_str,
            "timestamp_available": iso_ts is not None,
            "event_type": event_type,
            "mac_address": mac_address,
            "device_name": device_name,
            "source_type": source_type,
            "source_reference": source_reference,
            "confidence": confidence,
            "raw_reference": raw_reference,
            "corroboration_count": 1,
            "_corroboration_sources": corroboration_sources,
            "_sort_datetime": parsed_dt,
            "_input_index": index,
        }

    # ----------------------------------------------------------------- #
    # Deduplication and corroboration
    # ----------------------------------------------------------------- #

    @staticmethod
    def _dedup_key(entry: dict[str, Any]) -> tuple[str, str, str, str, str]:
        """Build the exact-duplicate comparison key for a timeline entry.

        Two entries are treated as exact duplicates only when they
        share the same normalized MAC, event type, timestamp, source
        type, and raw reference -- i.e. they almost certainly
        represent the same underlying evidence observed twice. Entries
        that describe the same real-world occurrence but originate
        from genuinely different sources are intentionally *not*
        collapsed; see :meth:`_merge_corroboration`.

        Args:
            entry: A normalized timeline event dictionary.

        Returns:
            A tuple usable as a dictionary/set key.
        """
        return (
            entry["mac_address"],
            entry["event_type"],
            entry["timestamp"] or "",
            entry["source_type"],
            entry["raw_reference"],
        )

    @staticmethod
    def _corroboration_key(entry: dict[str, Any]) -> tuple[str, str, str]:
        """Build the corroboration grouping key for a timeline entry.

        Entries sharing MAC, event type, and timestamp are considered
        potential independent corroboration of the same apparent
        occurrence, provided they come from distinct sources.

        Args:
            entry: A normalized timeline event dictionary.

        Returns:
            A tuple usable as a dictionary key.
        """
        return (entry["mac_address"], entry["event_type"], entry["timestamp"] or "")

    def _deduplicate_and_annotate(
        self, entries: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Remove exact-duplicate entries and annotate source corroboration.

        Only removes entries that are effective exact duplicates of
        another entry already kept (first occurrence wins). Entries
        that merely share a MAC address and/or device name are never
        collapsed on that basis alone. When surviving entries share a
        MAC, event type, and timestamp but come from distinct sources,
        each is annotated with a ``"corroboration_count"`` reflecting
        the number of distinct sources involved; no entry is removed
        or altered in claim as a result.

        Args:
            entries: The combined, normalized, un-deduplicated list of
                timeline entries.

        Returns:
            A new list with exact duplicates removed and corroboration
            counts annotated. Entries without a usable timestamp are
            never merged for corroboration purposes with other
            timestamp-less entries, since "same missing timestamp"
            is not meaningful corroboration.
        """
        seen: set[tuple[str, str, str, str, str]] = set()
        deduplicated: list[dict[str, Any]] = []

        for entry in entries:
            key = self._dedup_key(entry)
            if key in seen:
                self._logger.info(
                    "Dropping exact-duplicate timeline entry for %s "
                    "(%s, source=%s/%s).",
                    entry["mac_address"], entry["event_type"],
                    entry["source_type"], entry["source_reference"],
                )
                continue
            seen.add(key)
            deduplicated.append(entry)

        groups: dict[tuple[str, str, str], set[tuple[str, str]]] = {}
        for entry in deduplicated:
            if not entry["timestamp"]:
                # A shared "no timestamp" is not meaningful corroboration;
                # each timestamp-less entry stands on its own.
                continue
            key = self._corroboration_key(entry)
            groups.setdefault(key, set()).update(entry["_corroboration_sources"])

        for entry in deduplicated:
            if not entry["timestamp"]:
                entry["corroboration_count"] = len(entry["_corroboration_sources"])
                continue
            key = self._corroboration_key(entry)
            entry["corroboration_count"] = len(groups.get(key, entry["_corroboration_sources"]))

        return deduplicated

    # ----------------------------------------------------------------- #
    # Sorting
    # ----------------------------------------------------------------- #

    @staticmethod
    def _sort_descending(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Order timeline entries newest-first, deterministically.

        Entries with a known timestamp are ordered strictly
        newest-first. Entries without a usable timestamp are placed
        after all timestamped entries, in stable insertion order --
        never randomly and never guessed into a false position in the
        timeline. Internal bookkeeping keys are stripped from the
        returned records.

        Args:
            entries: The deduplicated, annotated list of timeline
                entries.

        Returns:
            A newly ordered list of clean, public-schema timeline
            entries (numbered via a ``"sequence"`` key reflecting
            display position, newest first).
        """
        def sort_key(entry: dict[str, Any]) -> tuple[int, float, int]:
            dt = entry.get("_sort_datetime")
            fallback_index = entry.get("_input_index", 0)
            if dt is None:
                return (1, 0.0, fallback_index)
            return (0, -dt.timestamp(), fallback_index)

        ordered_source = sorted(entries, key=sort_key)

        internal_keys = {"_sort_datetime", "_input_index", "_corroboration_sources"}
        ordered: list[dict[str, Any]] = []
        for position, entry in enumerate(ordered_source, start=1):
            clean_entry = {k: v for k, v in entry.items() if k not in internal_keys}
            clean_entry["sequence"] = position
            ordered.append(clean_entry)
        return ordered

    # ----------------------------------------------------------------- #
    # Public API
    # ----------------------------------------------------------------- #

    def build_timeline(self, events: Any) -> dict[str, Any]:
        """Build a normalized, deduplicated, chronologically ordered timeline.

        This is the module's main entry point. It accepts a list of
        already-structured evidence events (from
        :class:`modules.connection_history.ConnectionHistoryAnalyzer`,
        :mod:`modules.linux_artifacts`, or any other module producing
        compatible dictionaries), normalizes each into a consistent
        schema, safely deduplicates exact repeats while preserving
        corroboration, and orders the result newest-first. Malformed
        individual events are skipped and logged; they never abort
        construction of the overall timeline.

        Args:
            events: A list of event dictionaries. A non-list input (or
                an empty list) is handled gracefully and simply yields
                an empty timeline rather than raising.

        Returns:
            A dictionary with keys:

            * ``"success"`` (bool): ``True`` unless ``events`` itself
              is a fundamentally unusable type.
            * ``"timeline"`` (list[dict]): the normalized entries,
              newest-first, timestamp-less entries last.
            * ``"total_events"`` (int): length of ``"timeline"``.
            * ``"skipped_events"`` (int): number of input records that
              could not be normalized (not dictionaries, or missing a
              valid MAC address).
            * ``"error"`` (str | None): a short error code, or
              ``None`` on success.
        """
        if events is None:
            events = []

        if not isinstance(events, list):
            self._logger.error(
                "build_timeline requires a list of events; received %s.",
                type(events).__name__,
            )
            return {
                "success": False,
                "timeline": [],
                "total_events": 0,
                "skipped_events": 0,
                "error": "invalid_input_type",
            }

        normalized: list[dict[str, Any]] = []
        skipped = 0

        for index, raw_event in enumerate(events):
            try:
                normalized_entry = self.normalize_event(raw_event, index)
            except (TypeError, ValueError, AttributeError, KeyError) as exc:
                self._logger.error(
                    "Unexpected error normalizing event at index %d: %s",
                    index, exc,
                )
                normalized_entry = None

            if normalized_entry is None:
                skipped += 1
                continue
            normalized.append(normalized_entry)

        deduplicated = self._deduplicate_and_annotate(normalized)
        ordered = self._sort_descending(deduplicated)

        return {
            "success": True,
            "timeline": ordered,
            "total_events": len(ordered),
            "skipped_events": skipped,
            "error": None,
        }

    def get_case_timeline(self, events: Any) -> dict[str, Any]:
        """Build a full, case-wide timeline spanning all devices.

        Thin, semantically named wrapper around :meth:`build_timeline`
        for callers assembling an investigation-wide view before
        narrowing in on a specific device. Also reports the distinct
        set of devices observed.

        Args:
            events: See :meth:`build_timeline`.

        Returns:
            The same dictionary shape as :meth:`build_timeline`, plus
            a ``"devices"`` key: a sorted list of distinct normalized
            MAC addresses present in the resulting timeline.
        """
        result = self.build_timeline(events)
        devices = sorted({entry["mac_address"] for entry in result["timeline"]})
        result["devices"] = devices
        return result

    def get_device_timeline(self, events: Any, target_mac: str) -> dict[str, Any]:
        """Build a timeline filtered to a single target device.

        Args:
            events: See :meth:`build_timeline`.
            target_mac: The MAC address to filter to. Accepts
                colon- or hyphen-delimited form.

        Returns:
            The same dictionary shape as :meth:`build_timeline`, plus
            ``"target_mac"`` (the normalized target MAC address, or
            the original input if it could not be normalized). If
            ``target_mac`` is not validly formatted, returns
            ``"success": False`` with an empty timeline rather than
            raising.
        """
        if not is_valid_mac_address(target_mac):
            self._logger.warning("Invalid target MAC address supplied: %r", target_mac)
            return {
                "success": False,
                "timeline": [],
                "total_events": 0,
                "skipped_events": 0,
                "target_mac": target_mac,
                "error": "invalid_mac_address",
            }

        normalized_target = normalize_mac_address(target_mac) or target_mac

        full_result = self.build_timeline(events)
        if not full_result["success"]:
            full_result["target_mac"] = normalized_target
            return full_result

        filtered = [
            entry for entry in full_result["timeline"]
            if entry["mac_address"] == normalized_target
        ]
        for position, entry in enumerate(filtered, start=1):
            entry["sequence"] = position

        return {
            "success": True,
            "timeline": filtered,
            "total_events": len(filtered),
            "skipped_events": full_result["skipped_events"],
            "target_mac": normalized_target,
            "error": None,
        }

    def summarize_timeline(self, timeline: list[dict[str, Any]]) -> dict[str, Any]:
        """Produce a structured forensic summary of a built timeline.

        Only counts events actually present in ``timeline``; this
        method never infers or fabricates missing events (e.g. it will
        not assume a ``disconnected`` event exists just because a
        ``connected`` event does).

        Args:
            timeline: A list of normalized timeline entries, typically
                the ``"timeline"`` value returned by
                :meth:`build_timeline`, :meth:`get_case_timeline`, or
                :meth:`get_device_timeline`.

        Returns:
            A dictionary with keys: ``"total_events"``,
            ``"connected_events"``, ``"disconnected_events"``,
            ``"connection_attempt_events"``,
            ``"connection_failed_events"``,
            ``"authentication_failure_events"``,
            ``"paired_events"``, ``"trusted_events"``,
            ``"blocked_events"``, ``"discovered_events"``,
            ``"advertised_events"``, ``"unknown_events"``,
            ``"devices_involved"``, ``"events_without_timestamp"``,
            ``"first_timestamp"`` (oldest known timestamp, or
            ``None``), and ``"last_timestamp"`` (newest known
            timestamp, or ``None``). Returns an all-zero/empty summary
            if ``timeline`` is empty or not a list.
        """
        if not isinstance(timeline, list) or not timeline:
            return {
                "total_events": 0,
                "connected_events": 0,
                "disconnected_events": 0,
                "connection_attempt_events": 0,
                "connection_failed_events": 0,
                "authentication_failure_events": 0,
                "paired_events": 0,
                "trusted_events": 0,
                "blocked_events": 0,
                "discovered_events": 0,
                "advertised_events": 0,
                "unknown_events": 0,
                "devices_involved": 0,
                "events_without_timestamp": 0,
                "first_timestamp": None,
                "last_timestamp": None,
            }

        counts: dict[str, int] = {event_type: 0 for event_type in EVENT_TYPES}
        devices: set[str] = set()
        timestamps: list[str] = []
        missing_timestamp = 0

        for entry in timeline:
            if not isinstance(entry, dict):
                continue
            event_type = entry.get("event_type")
            if event_type in counts:
                counts[event_type] += 1
            mac_address = entry.get("mac_address")
            if mac_address:
                devices.add(mac_address)
            timestamp = entry.get("timestamp")
            if timestamp:
                timestamps.append(timestamp)
            else:
                missing_timestamp += 1

        timestamps.sort()

        return {
            "total_events": len(timeline),
            "connected_events": counts["connected"],
            "disconnected_events": counts["disconnected"],
            "connection_attempt_events": counts["connection_attempt"],
            "connection_failed_events": counts["connection_failed"],
            "authentication_failure_events": counts["authentication_failure"],
            "paired_events": counts["paired"],
            "trusted_events": counts["trusted"],
            "blocked_events": counts["blocked"],
            "discovered_events": counts["discovered"],
            "advertised_events": counts["advertised"],
            "unknown_events": counts["unknown"],
            "devices_involved": len(devices),
            "events_without_timestamp": missing_timestamp,
            "first_timestamp": timestamps[0] if timestamps else None,
            "last_timestamp": timestamps[-1] if timestamps else None,
        }


__all__: Final[list[str]] = [
    "ForensicTimeline",
    "EVENT_TYPES",
    "CONFIDENCE_LEVELS",
]
