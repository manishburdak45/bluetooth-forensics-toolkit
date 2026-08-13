"""
modules/connection_history.py
==============================

Bluetooth connection-history reconstruction module for
**BlueTrace Forensic Suite**.

This module contains the :class:`ConnectionHistoryAnalyzer` class, whose
sole responsibility is to reconstruct a *historical* timeline of
Bluetooth connection/association events for a target device from
evidence that has already been collected elsewhere in the framework
(e.g. by :mod:`modules.linux_artifacts`) or from local Linux log text
supplied by the caller (e.g. ``bluetoothd``/``journalctl`` output).

This module performs **no** subprocess execution, **no** live Bluetooth
scanning, and **no** file I/O of its own. It is a pure evidence
*interpretation* layer: callers gather raw evidence (log text, BlueZ
artifact records, or already-structured events from other forensic
modules) and hand it to this module, which parses, classifies,
deduplicates, and orders that evidence into a structured connection
history. It never prints output; presentation is the responsibility of
``app.py`` / ``modules/report.py``.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and Bluetooth Low Energy (BLE) devices on Linux.

Forensic limitations
---------------------
* Historical Bluetooth connection records may not exist at all on a
  given system; Linux log rotation/retention policy directly limits how
  far back this module can reconstruct history.
* BlueZ's persisted state under ``/var/lib/bluetooth`` reflects the
  *current* paired/trusted/blocked status of a device, not a complete
  historical connection log. A device being paired or trusted today
  does not mean this module can say when (or how many times) it was
  ever actually connected.
* BLE devices using Resolvable/Non-Resolvable Private Addresses can
  rotate their advertised MAC address, which can fragment or obscure a
  single physical device's history across multiple apparent addresses.
  This module does not attempt cross-address correlation.
* The absence of a historical record for a MAC address does NOT prove
  that device was never connected -- only that no supporting evidence
  was found among the sources supplied to this module.
* This module reconstructs history exclusively from the evidence it is
  given. It never fabricates timestamps, device names, or connection
  events, and it never upgrades weaker evidence (discovery, pairing,
  trust) into a "connected" event.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime
from typing import Any, Final

from config import LOG_LEVEL
from modules.utils import is_valid_mac_address, normalize_mac_address

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Value used for fields whose value could not be determined from evidence.
_UNKNOWN_VALUE: Final[str] = "Unknown"

#: The set of event types this module will ever assign to a reconstructed
#: history entry. Kept deliberately distinct so that discovery/pairing/
#: trust evidence is never conflated with an actual connection event.
EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "connected",
        "disconnected",
        "paired",
        "trusted",
        "discovered",
        "advertised",
        "unknown",
    }
)

#: The set of confidence levels this module will ever assign to a
#: reconstructed history entry.
CONFIDENCE_LEVELS: Final[frozenset[str]] = frozenset(
    {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}
)

#: Evidence source-type labels recognized by this module's built-in
#: ingestion helpers. Callers may also supply their own labels for
#: pre-structured events (see :meth:`ConnectionHistoryAnalyzer.get_connection_history`).
SOURCE_TYPE_BLUETOOTHD_LOG: Final[str] = "bluetoothd_log"
SOURCE_TYPE_JOURNALCTL: Final[str] = "journalctl"
SOURCE_TYPE_BLUEZ_ARTIFACT: Final[str] = "bluez_artifact"
SOURCE_TYPE_STRUCTURED: Final[str] = "structured_evidence"

#: Regular expression matching a MAC address anywhere within a line.
_MAC_SEARCH_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
)

#: Matches an ISO-8601-style timestamp at the start of a log line, e.g.
#: ``"2026-08-13T22:41:18+00:00 "`` or ``"2026-08-13 22:41:18 "``.
_ISO_TIMESTAMP_PREFIX_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)\s+"
)

#: Matches a classic syslog-style timestamp with no year, e.g.
#: ``"Aug 13 22:41:18 "``.
_SYSLOG_TIMESTAMP_PREFIX_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
)

#: Maps abbreviated month names to their numeric value, for parsing
#: :data:`_SYSLOG_TIMESTAMP_PREFIX_PATTERN` matches.
_MONTH_ABBREVIATIONS: Final[dict[str, int]] = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

#: Matches a ``bluetoothctl``/``bluetoothd``-style device property line,
#: optionally prefixed with a monitor-mode marker such as ``[CHG]`` or
#: ``[NEW]``, e.g. ``"[CHG] Device AA:BB:CC:DD:EE:FF Connected: yes"``.
_DEVICE_FIELD_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"Device\s+(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+"
    r"(?P<field>[A-Za-z]+):\s*(?P<value>.+?)\s*$"
)

#: Matches a ``bluetoothctl`` scan-discovery marker line, e.g.
#: ``"[NEW] Device AA:BB:CC:DD:EE:FF Galaxy S24"``.
_NEW_DEVICE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\[NEW\]\s+Device\s+(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
    r"(?:\s+(?P<name>.+?))?\s*$"
)

#: Field names (from :data:`_DEVICE_FIELD_PATTERN`) that map directly to a
#: connection-history event type, and the boolean value ("yes"/"no") that
#: triggers each event type.
_CONNECTED_FIELD_NAMES: Final[frozenset[str]] = frozenset({"Connected"})
_PAIRED_FIELD_NAMES: Final[frozenset[str]] = frozenset({"Paired"})
_TRUSTED_FIELD_NAMES: Final[frozenset[str]] = frozenset({"Trusted"})
_NAME_FIELD_NAMES: Final[frozenset[str]] = frozenset({"Name", "Alias"})


class ConnectionHistoryAnalyzer:
    """Reconstruct historical Bluetooth connection events from evidence.

    This class never contacts, scans, or modifies any Bluetooth device
    and performs no filesystem or subprocess I/O of its own. It only
    interprets evidence supplied by the caller: raw local log text
    (e.g. ``bluetoothd``/``journalctl`` output) and/or already-structured
    evidence records produced by other BlueTrace modules (such as
    :class:`modules.linux_artifacts.LinuxArtifactsCollector`).

    Discovery, pairing, and trust evidence are always kept as distinct
    event types from an actual ``connected``/``disconnected`` event; this
    class never infers a connection from weaker evidence.
    """

    def __init__(self) -> None:
        """Initialize the analyzer's logger and operational configuration."""
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # ----------------------------------------------------------------- #
    # Timestamp handling
    # ----------------------------------------------------------------- #

    def _parse_timestamp_prefix(
        self, line: str, assume_year: int | None
    ) -> tuple[datetime | None, str | None, str]:
        """Extract and normalize a timestamp from the start of a log line.

        Attempts an ISO-8601 prefix first, then falls back to a classic
        syslog-style ``"Mon DD HH:MM:SS"`` prefix (which carries no year).
        Never fabricates a timezone or a year: a syslog-style prefix is
        only converted into a concrete timestamp if ``assume_year`` is
        explicitly supplied by the caller.

        Args:
            line: The raw log line to inspect.
            assume_year: A year to combine with a year-less syslog-style
                timestamp, if the caller has independent knowledge of it
                (e.g. from file metadata). ``None`` disables this fallback.

        Returns:
            A tuple of ``(parsed_datetime, iso_timestamp_or_none,
            remainder_of_line)``. ``parsed_datetime`` and
            ``iso_timestamp_or_none`` are both ``None`` if no timestamp
            could be safely determined; the raw line is preserved
            unmodified via the caller's ``raw_reference`` field in that
            case.
        """
        iso_match = _ISO_TIMESTAMP_PREFIX_PATTERN.match(line)
        if iso_match:
            raw_ts = iso_match.group("ts")
            normalized = raw_ts.replace("Z", "+00:00")
            try:
                parsed = datetime.fromisoformat(normalized)
            except ValueError:
                return None, None, line
            iso_out = parsed.isoformat()
            return parsed, iso_out, line[iso_match.end():]

        syslog_match = _SYSLOG_TIMESTAMP_PREFIX_PATTERN.match(line)
        if syslog_match and assume_year is not None:
            month = _MONTH_ABBREVIATIONS.get(syslog_match.group("mon"))
            if month is not None:
                try:
                    day = int(syslog_match.group("day"))
                    hour, minute, second = (
                        int(part) for part in syslog_match.group("time").split(":")
                    )
                    parsed = datetime(assume_year, month, day, hour, minute, second)
                    return parsed, parsed.isoformat(), line[syslog_match.end():]
                except ValueError:
                    self._logger.warning(
                        "Could not construct a timestamp from syslog-style "
                        "prefix in line: %s", line.strip()
                    )
                    return None, None, line

        return None, None, line

    # ----------------------------------------------------------------- #
    # Event construction
    # ----------------------------------------------------------------- #

    @staticmethod
    def _make_event_id(
        mac_address: str,
        event_type: str,
        timestamp: str | None,
        source_type: str,
        source_reference: str,
        raw_reference: str,
    ) -> str:
        """Generate a deterministic identifier for a reconstructed event.

        The identifier is derived from the event's own content (rather
        than randomly generated) so that re-running analysis on the same
        evidence produces stable, comparable event identifiers.

        Args:
            mac_address: Normalized MAC address associated with the event.
            event_type: One of :data:`EVENT_TYPES`.
            timestamp: The event's ISO-8601 timestamp, or ``None``.
            source_type: A label identifying the evidence source category.
            source_reference: A label identifying the specific evidence
                source instance (e.g. a file path or artifact name).
            raw_reference: The raw evidence text/value the event was
                derived from.

        Returns:
            A short, stable, hex-encoded identifier prefixed with ``CH-``.
        """
        digest_input = "|".join(
            [
                mac_address,
                event_type,
                timestamp or "",
                source_type,
                source_reference,
                raw_reference,
            ]
        ).encode("utf-8", errors="replace")
        digest = hashlib.sha256(digest_input).hexdigest()[:16]
        return f"CH-{digest}"

    def _build_event(
        self,
        *,
        mac_address: str,
        device_name: str | None,
        event_type: str,
        parsed_timestamp: datetime | None,
        iso_timestamp: str | None,
        raw_timestamp: str | None,
        source_type: str,
        source_reference: str,
        confidence: str,
        raw_reference: str,
    ) -> dict[str, Any]:
        """Assemble a single structured connection-history event record.

        Args:
            mac_address: Normalized MAC address (already validated).
            device_name: Observed device name/alias, or ``None`` if not
                present in the supporting evidence.
            event_type: One of :data:`EVENT_TYPES`.
            parsed_timestamp: A parsed :class:`datetime.datetime`, or
                ``None`` if no timestamp could be safely determined.
            iso_timestamp: The ISO-8601 string form of ``parsed_timestamp``,
                or ``None``.
            raw_timestamp: The original, unparsed timestamp text from the
                evidence, preserved when parsing failed or was ambiguous.
            source_type: A label identifying the evidence source category
                (e.g. ``"bluetoothd_log"``, ``"bluez_artifact"``).
            source_reference: A label identifying the specific evidence
                source instance (e.g. a file path or artifact description).
            confidence: One of :data:`CONFIDENCE_LEVELS`.
            raw_reference: The raw evidence text/value the event was
                derived from, preserved verbatim for provenance.

        Returns:
            A structured event dictionary. Internal-only key
            ``"_sort_datetime"`` is included to support deterministic
            ordering and is stripped before results are returned to
            callers.
        """
        safe_confidence = confidence if confidence in CONFIDENCE_LEVELS else "UNKNOWN"
        safe_event_type = event_type if event_type in EVENT_TYPES else "unknown"

        date_str = parsed_timestamp.strftime("%Y-%m-%d") if parsed_timestamp else None
        time_str = parsed_timestamp.strftime("%H:%M:%S") if parsed_timestamp else None

        return {
            "event_id": self._make_event_id(
                mac_address,
                safe_event_type,
                iso_timestamp,
                source_type,
                source_reference,
                raw_reference,
            ),
            "mac_address": mac_address,
            "device_name": device_name or None,
            "event_type": safe_event_type,
            "timestamp": iso_timestamp,
            "date": date_str,
            "time": time_str,
            "raw_timestamp": raw_timestamp,
            "source_type": source_type,
            "source_reference": source_reference,
            "confidence": safe_confidence,
            "raw_reference": raw_reference,
            "corroboration_count": 1,
            "_sort_datetime": parsed_timestamp,
        }

    # ----------------------------------------------------------------- #
    # Evidence source: raw log text (bluetoothd / journalctl style)
    # ----------------------------------------------------------------- #

    def parse_log_text(
        self,
        content: str,
        source_type: str,
        source_reference: str,
        assume_year: int | None = None,
    ) -> list[dict[str, Any]]:
        """Parse raw local log text into structured connection-history events.

        Recognizes ``bluetoothctl``/``bluetoothd``-style device property
        lines (optionally prefixed with monitor-mode markers such as
        ``[CHG]`` or ``[NEW]``), which is the common shape of both direct
        ``bluetoothd`` log output and ``journalctl`` output filtered to
        the Bluetooth daemon. Lines that do not match a recognized,
        unambiguous pattern are skipped rather than guessed at.

        Only explicit property transitions are treated as evidence of an
        event:

        * ``Connected: yes`` / ``Connected: no`` -> ``connected`` /
          ``disconnected`` (HIGH confidence -- a direct connection event
          from a reliable system source).
        * ``Paired: yes`` -> ``paired`` (MEDIUM confidence -- strong
          corroborating artifact, but not itself a connection event).
        * ``Trusted: yes`` -> ``trusted`` (MEDIUM confidence).
        * ``[NEW] Device <mac> ...`` -> ``discovered`` (LOW confidence --
          weak/ambiguous; a discovered device may never have connected).

        ``Connected: no``, ``Paired: no``, and ``Trusted: no`` for
        paired/trusted are not emitted as separate negative events beyond
        the explicit ``disconnected`` case, since a bare "no" on its own
        is not reliable evidence of a specific historical transition.

        Args:
            content: The raw text content of the log evidence (may span
                multiple lines).
            source_type: A short label identifying the kind of source,
                e.g. :data:`SOURCE_TYPE_BLUETOOTHD_LOG` or
                :data:`SOURCE_TYPE_JOURNALCTL`.
            source_reference: A label identifying the specific evidence
                instance, e.g. a file path such as ``"/var/log/syslog"``.
            assume_year: Optional year to combine with year-less
                syslog-style timestamps. Left as ``None`` (the default),
                such lines are still parsed as events but their
                timestamp/date/time fields remain ``None`` and the raw
                timestamp text is preserved in ``"raw_timestamp"``.

        Returns:
            A list of structured event dictionaries. Returns an empty
            list if ``content`` is empty or contains no recognizable
            device-event lines. Never raises.
        """
        if not isinstance(content, str) or not content.strip():
            return []

        events: list[dict[str, Any]] = []

        for line in content.splitlines():
            if not line.strip():
                continue

            try:
                parsed_dt, iso_ts, remainder = self._parse_timestamp_prefix(
                    line, assume_year
                )
            except (ValueError, TypeError) as exc:
                self._logger.warning(
                    "Failed to parse timestamp from line, skipping "
                    "timestamp only: %s", exc
                )
                parsed_dt, iso_ts, remainder = None, None, line

            raw_timestamp: str | None = None
            if parsed_dt is None:
                ts_match = _ISO_TIMESTAMP_PREFIX_PATTERN.match(
                    line
                ) or _SYSLOG_TIMESTAMP_PREFIX_PATTERN.match(line)
                if ts_match:
                    raw_timestamp = ts_match.group(0).strip()

            new_match = _NEW_DEVICE_PATTERN.search(remainder)
            if new_match:
                mac = normalize_mac_address(new_match.group("mac"))
                if mac is None:
                    continue
                device_name = (new_match.group("name") or "").strip() or None
                events.append(
                    self._build_event(
                        mac_address=mac,
                        device_name=device_name,
                        event_type="discovered",
                        parsed_timestamp=parsed_dt,
                        iso_timestamp=iso_ts,
                        raw_timestamp=raw_timestamp,
                        source_type=source_type,
                        source_reference=source_reference,
                        confidence="LOW",
                        raw_reference=line.strip(),
                    )
                )
                continue

            field_match = _DEVICE_FIELD_PATTERN.search(remainder)
            if not field_match:
                continue

            mac = normalize_mac_address(field_match.group("mac"))
            if mac is None:
                continue

            field_name = field_match.group("field")
            field_value = field_match.group("value").strip()
            value_is_yes = field_value.strip().lower() == "yes"

            event_type: str | None = None
            confidence = "UNKNOWN"

            if field_name in _CONNECTED_FIELD_NAMES:
                event_type = "connected" if value_is_yes else "disconnected"
                confidence = "HIGH"
            elif field_name in _PAIRED_FIELD_NAMES and value_is_yes:
                event_type = "paired"
                confidence = "MEDIUM"
            elif field_name in _TRUSTED_FIELD_NAMES and value_is_yes:
                event_type = "trusted"
                confidence = "MEDIUM"
            elif field_name == "RSSI":
                event_type = "advertised"
                confidence = "LOW"

            if event_type is None:
                # Fields such as bare Name/Alias/Class updates on their
                # own are not treated as connection-history events; they
                # carry no reliable evidence of a state transition.
                continue

            events.append(
                self._build_event(
                    mac_address=mac,
                    device_name=None,
                    event_type=event_type,
                    parsed_timestamp=parsed_dt,
                    iso_timestamp=iso_ts,
                    raw_timestamp=raw_timestamp,
                    source_type=source_type,
                    source_reference=source_reference,
                    confidence=confidence,
                    raw_reference=line.strip(),
                )
            )

        return events

    # ----------------------------------------------------------------- #
    # Evidence source: BlueZ persisted device artifacts
    # ----------------------------------------------------------------- #

    def ingest_bluez_known_devices(
        self,
        known_devices: list[dict[str, Any]],
        source_reference: str = "/var/lib/bluetooth",
    ) -> list[dict[str, Any]]:
        """Convert BlueZ persisted device records into structured events.

        Accepts device records as produced by
        :meth:`modules.linux_artifacts.LinuxArtifactsCollector.get_known_devices`
        (or ``get_paired_devices`` / ``get_trusted_devices``). Only
        explicit ``"paired": True`` or ``"trusted": True`` flags are
        converted into events -- never a ``"connected"`` event, since
        BlueZ's per-device ``info`` file does not record connection
        history, only current pairing/trust/link-key state.

        Args:
            known_devices: A list of device dictionaries as returned by
                :class:`modules.linux_artifacts.LinuxArtifactsCollector`.
            source_reference: A label identifying where these records
                came from. Defaults to the standard BlueZ state directory
                path.

        Returns:
            A list of structured event dictionaries with ``timestamp``,
            ``date``, and ``time`` all ``None`` (BlueZ does not persist
            when a device was paired/trusted), and ``confidence`` set to
            ``"MEDIUM"``. Returns an empty list if ``known_devices`` is
            empty or contains no valid records. Never raises.
        """
        if not known_devices:
            return []

        events: list[dict[str, Any]] = []

        for device in known_devices:
            if not isinstance(device, dict):
                continue

            raw_mac = device.get("mac")
            if not isinstance(raw_mac, str):
                continue
            mac = normalize_mac_address(raw_mac)
            if mac is None:
                self._logger.warning(
                    "Skipping BlueZ artifact with invalid MAC address: %r",
                    raw_mac,
                )
                continue

            device_name = device.get("name")
            if device_name in (None, _UNKNOWN_VALUE, ""):
                device_name = None

            raw_reference = (
                f"controller={device.get('controller_mac', _UNKNOWN_VALUE)} "
                f"device={mac} paired={device.get('paired')} "
                f"trusted={device.get('trusted')} "
                f"blocked={device.get('blocked')}"
            )

            if device.get("paired") is True:
                events.append(
                    self._build_event(
                        mac_address=mac,
                        device_name=device_name,
                        event_type="paired",
                        parsed_timestamp=None,
                        iso_timestamp=None,
                        raw_timestamp=None,
                        source_type=SOURCE_TYPE_BLUEZ_ARTIFACT,
                        source_reference=source_reference,
                        confidence="MEDIUM",
                        raw_reference=raw_reference,
                    )
                )

            if device.get("trusted") is True:
                events.append(
                    self._build_event(
                        mac_address=mac,
                        device_name=device_name,
                        event_type="trusted",
                        parsed_timestamp=None,
                        iso_timestamp=None,
                        raw_timestamp=None,
                        source_type=SOURCE_TYPE_BLUEZ_ARTIFACT,
                        source_reference=source_reference,
                        confidence="MEDIUM",
                        raw_reference=raw_reference,
                    )
                )

        return events

    # ----------------------------------------------------------------- #
    # Evidence source: pre-structured events from other modules
    # ----------------------------------------------------------------- #

    def ingest_structured_events(
        self, structured_events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Validate and normalize already-structured event records.

        Supports future evidence-producing modules (e.g. an HCI/btmon
        parser) supplying pre-built event dictionaries directly, without
        requiring this module to understand their original file format.
        Each input record is defensively validated; malformed records
        are skipped (and logged) rather than raising or corrupting the
        overall history.

        Args:
            structured_events: A list of dictionaries, each expected to
                contain at least ``"mac_address"`` and ``"event_type"``.
                Recognized optional keys: ``"device_name"``,
                ``"timestamp"`` (ISO-8601 string), ``"source_type"``,
                ``"source_reference"``, ``"confidence"``,
                ``"raw_reference"``.

        Returns:
            A list of normalized, structured event dictionaries in this
            module's standard event shape. Records with a missing or
            invalid ``"mac_address"`` are skipped. Never raises.
        """
        if not structured_events:
            return []

        events: list[dict[str, Any]] = []

        for index, record in enumerate(structured_events):
            if not isinstance(record, dict):
                self._logger.warning(
                    "Skipping non-dict structured evidence record at index %d.",
                    index,
                )
                continue

            raw_mac = record.get("mac_address") or record.get("mac")
            if not isinstance(raw_mac, str):
                self._logger.warning(
                    "Skipping structured evidence record at index %d: "
                    "missing mac_address.", index,
                )
                continue
            mac = normalize_mac_address(raw_mac)
            if mac is None:
                self._logger.warning(
                    "Skipping structured evidence record with invalid "
                    "MAC address: %r", raw_mac,
                )
                continue

            event_type = record.get("event_type", "unknown")
            if event_type not in EVENT_TYPES:
                event_type = "unknown"

            confidence = record.get("confidence", "UNKNOWN")
            if confidence not in CONFIDENCE_LEVELS:
                confidence = "UNKNOWN"

            parsed_dt: datetime | None = None
            iso_ts: str | None = None
            raw_ts_value = record.get("timestamp")
            if isinstance(raw_ts_value, str) and raw_ts_value.strip():
                try:
                    parsed_dt = datetime.fromisoformat(
                        raw_ts_value.replace("Z", "+00:00")
                    )
                    iso_ts = parsed_dt.isoformat()
                except ValueError:
                    self._logger.warning(
                        "Structured evidence record at index %d has an "
                        "unparsable timestamp; preserving as raw value.",
                        index,
                    )

            source_type = record.get("source_type") or SOURCE_TYPE_STRUCTURED
            source_reference = record.get("source_reference") or _UNKNOWN_VALUE
            raw_reference = record.get("raw_reference") or record.get(
                "raw_timestamp"
            ) or ""

            events.append(
                self._build_event(
                    mac_address=mac,
                    device_name=record.get("device_name"),
                    event_type=event_type,
                    parsed_timestamp=parsed_dt,
                    iso_timestamp=iso_ts,
                    raw_timestamp=None if parsed_dt else raw_ts_value,
                    source_type=str(source_type),
                    source_reference=str(source_reference),
                    confidence=confidence,
                    raw_reference=str(raw_reference),
                )
            )

        return events

    # ----------------------------------------------------------------- #
    # Deduplication and ordering
    # ----------------------------------------------------------------- #

    @staticmethod
    def _dedup_key(event: dict[str, Any]) -> tuple[str, str, str, str, str]:
        """Build the exact-duplicate comparison key for a single event.

        Two events are treated as exact duplicates only when they share
        the same normalized MAC, event type, timestamp, source type, and
        raw reference -- i.e. they almost certainly represent the same
        underlying evidence observed twice (e.g. a log line re-parsed).
        Events that merely describe the same real-world occurrence but
        originate from genuinely different sources are intentionally
        *not* collapsed; see :meth:`_annotate_corroboration`.

        Args:
            event: A structured event dictionary.

        Returns:
            A tuple usable as a dictionary/set key.
        """
        return (
            event["mac_address"],
            event["event_type"],
            event["timestamp"] or "",
            event["source_type"],
            event["raw_reference"],
        )

    @staticmethod
    def _annotate_corroboration(events: list[dict[str, Any]]) -> None:
        """Count independent sources supporting the same apparent event.

        Groups events by (MAC, event type, timestamp) and, for groups
        spanning more than one distinct ``source_type``/``source_reference``
        pair, sets each member's ``"corroboration_count"`` to the number
        of distinct sources involved. This surfaces corroboration to an
        investigator without silently merging or discarding any record.

        Args:
            events: The list of structured events to annotate in place.
        """
        groups: dict[tuple[str, str, str], set[tuple[str, str]]] = {}
        for event in events:
            key = (event["mac_address"], event["event_type"], event["timestamp"] or "")
            groups.setdefault(key, set()).add(
                (event["source_type"], event["source_reference"])
            )

        for event in events:
            key = (event["mac_address"], event["event_type"], event["timestamp"] or "")
            event["corroboration_count"] = len(groups.get(key, set()))

    def _deduplicate(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove exact-duplicate events while preserving corroboration.

        Args:
            events: The raw, combined list of structured events.

        Returns:
            A new list with exact duplicates removed (first occurrence
            kept) and corroboration counts annotated.
        """
        seen: set[tuple[str, str, str, str, str]] = set()
        deduplicated: list[dict[str, Any]] = []

        for event in events:
            key = self._dedup_key(event)
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(event)

        self._annotate_corroboration(deduplicated)
        return deduplicated

    @staticmethod
    def _sort_events_descending(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Order events newest-first, deterministically.

        Events with a known timestamp are ordered strictly newest-first.
        Events without a usable timestamp (evidence that supports an
        event but not a reliable time, e.g. static BlueZ artifacts) are
        placed after all timestamped events, in their original,
        stable, insertion order -- never randomly and never guessed into
        a false position in the timeline.

        Args:
            events: The deduplicated list of structured events.

        Returns:
            A newly ordered list. The internal ``"_sort_datetime"`` key
            used to drive ordering is stripped from each returned record.
        """
        indexed = list(enumerate(events))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, float, int]:
            index, event = item
            dt = event.get("_sort_datetime")
            if dt is None:
                return (1, 0.0, index)
            return (0, -dt.timestamp(), index)

        indexed.sort(key=sort_key)

        ordered: list[dict[str, Any]] = []
        for _, event in indexed:
            clean_event = {k: v for k, v in event.items() if k != "_sort_datetime"}
            ordered.append(clean_event)
        return ordered

    # ----------------------------------------------------------------- #
    # Public API
    # ----------------------------------------------------------------- #

    def get_connection_history(
        self, target_mac: str, evidence: dict[str, Any]
    ) -> dict[str, Any]:
        """Reconstruct the connection history of a single target device.

        This is the module's main entry point. It validates the target
        MAC address, ingests every evidence source supplied, filters the
        combined events down to the target device, deduplicates exact
        repeats, orders the result newest-first, and returns a single
        structured result. Never raises; all failure modes are captured
        and returned as a structured error response.

        Args:
            target_mac: The MAC address of the device to reconstruct
                history for. Accepts colon- or hyphen-delimited form.
            evidence: A dictionary describing the available evidence,
                with any of the following optional keys:

                * ``"log_sources"``: a list of dictionaries, each with
                  keys ``"content"`` (raw log text), ``"source_type"``,
                  ``"source_reference"``, and optionally ``"assume_year"``.
                  Parsed via :meth:`parse_log_text`.
                * ``"bluez_known_devices"``: a list of device dictionaries
                  as returned by
                  :class:`modules.linux_artifacts.LinuxArtifactsCollector`.
                  Parsed via :meth:`ingest_bluez_known_devices`.
                * ``"structured_events"``: a list of already-structured
                  event dictionaries from other forensic modules. Parsed
                  via :meth:`ingest_structured_events`.

                An empty or partially-populated ``evidence`` dictionary
                is valid; missing keys are simply treated as "no evidence
                of that kind was supplied".

        Returns:
            A dictionary with keys:

            * ``"success"`` (bool): ``False`` only if ``target_mac`` is
              not a validly formatted MAC address.
            * ``"target_mac"`` (str): the normalized target MAC address
              (or the original input, if it could not be normalized).
            * ``"events"`` (list[dict]): the reconstructed history,
              newest event first.
            * ``"total_events"`` (int): length of ``"events"``.
            * ``"connection_events"`` (int): count of events with
              ``event_type == "connected"``.
            * ``"error"`` (str | None): a short error code, or ``None``
              on success.
        """
        if not is_valid_mac_address(target_mac):
            self._logger.warning("Invalid target MAC address supplied: %r", target_mac)
            return {
                "success": False,
                "target_mac": target_mac,
                "events": [],
                "total_events": 0,
                "connection_events": 0,
                "error": "invalid_mac_address",
            }

        normalized_target = normalize_mac_address(target_mac) or target_mac

        try:
            all_events = self._collect_all_events(evidence)
        except (TypeError, ValueError, AttributeError, KeyError) as exc:
            self._logger.error(
                "Unexpected error while ingesting evidence for %s: %s",
                normalized_target, exc,
            )
            return {
                "success": False,
                "target_mac": normalized_target,
                "events": [],
                "total_events": 0,
                "connection_events": 0,
                "error": "evidence_processing_error",
            }

        target_events = [
            event for event in all_events if event["mac_address"] == normalized_target
        ]

        deduplicated = self._deduplicate(target_events)
        ordered = self._sort_events_descending(deduplicated)

        connection_event_count = sum(
            1 for event in ordered if event["event_type"] == "connected"
        )

        return {
            "success": True,
            "target_mac": normalized_target,
            "events": ordered,
            "total_events": len(ordered),
            "connection_events": connection_event_count,
            "error": None,
        }

    def get_full_connection_timeline(
        self, evidence: dict[str, Any]
    ) -> dict[str, Any]:
        """Reconstruct a connection-history timeline across all devices.

        Same evidence-ingestion and ordering behavior as
        :meth:`get_connection_history`, but without filtering to a
        single target MAC address. Useful for a case-wide overview
        before an investigator narrows in on a specific device.

        Args:
            evidence: See :meth:`get_connection_history`.

        Returns:
            A dictionary with keys ``"success"``, ``"events"``
            (newest-first, across all devices found in the evidence),
            ``"total_events"``, ``"connection_events"``, ``"devices"``
            (a sorted list of distinct normalized MAC addresses observed),
            and ``"error"``.
        """
        try:
            all_events = self._collect_all_events(evidence)
        except (TypeError, ValueError, AttributeError, KeyError) as exc:
            self._logger.error(
                "Unexpected error while ingesting evidence: %s", exc
            )
            return {
                "success": False,
                "events": [],
                "total_events": 0,
                "connection_events": 0,
                "devices": [],
                "error": "evidence_processing_error",
            }

        deduplicated = self._deduplicate(all_events)
        ordered = self._sort_events_descending(deduplicated)

        connection_event_count = sum(
            1 for event in ordered if event["event_type"] == "connected"
        )
        devices = sorted({event["mac_address"] for event in ordered})

        return {
            "success": True,
            "events": ordered,
            "total_events": len(ordered),
            "connection_events": connection_event_count,
            "devices": devices,
            "error": None,
        }

    # ----------------------------------------------------------------- #
    # Internal orchestration
    # ----------------------------------------------------------------- #

    def _collect_all_events(self, evidence: dict[str, Any]) -> list[dict[str, Any]]:
        """Ingest every recognized evidence category into one event list.

        Args:
            evidence: See :meth:`get_connection_history`.

        Returns:
            The combined, un-deduplicated, unordered list of structured
            events from every supplied evidence source. Returns an empty
            list if ``evidence`` is empty or ``None``.
        """
        if not evidence:
            return []

        events: list[dict[str, Any]] = []

        log_sources = evidence.get("log_sources") or []
        for log_source in log_sources:
            if not isinstance(log_source, dict):
                self._logger.warning("Skipping malformed log_source entry.")
                continue
            content = log_source.get("content", "")
            source_type = log_source.get("source_type", SOURCE_TYPE_BLUETOOTHD_LOG)
            source_reference = log_source.get("source_reference", _UNKNOWN_VALUE)
            assume_year = log_source.get("assume_year")
            events.extend(
                self.parse_log_text(
                    content, str(source_type), str(source_reference), assume_year
                )
            )

        bluez_known_devices = evidence.get("bluez_known_devices") or []
        if bluez_known_devices:
            events.extend(self.ingest_bluez_known_devices(bluez_known_devices))

        structured_events = evidence.get("structured_events") or []
        if structured_events:
            events.extend(self.ingest_structured_events(structured_events))

        return events


__all__: Final[list[str]] = [
    "ConnectionHistoryAnalyzer",
    "EVENT_TYPES",
    "CONFIDENCE_LEVELS",
    "SOURCE_TYPE_BLUETOOTHD_LOG",
    "SOURCE_TYPE_JOURNALCTL",
    "SOURCE_TYPE_BLUEZ_ARTIFACT",
    "SOURCE_TYPE_STRUCTURED",
]
