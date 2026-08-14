"""
modules/report.py
==================

Forensic report generation module for **BlueTrace Forensic Suite**.

This module contains the :class:`ForensicReportGenerator` class, whose
sole responsibility is to format evidence data already collected and
analyzed by other modules (:mod:`modules.linux_artifacts`,
:mod:`modules.connection_history`, :mod:`modules.timeline`,
:mod:`modules.analyzer`, and :mod:`modules.hashing`) into human-readable
and machine-readable forensic reports.

This module never scans, connects to, or analyzes Bluetooth devices,
never reads local Linux Bluetooth artifacts, never calculates hashes,
never captures packets, and never modifies evidence in any way. It only
reads data that is passed in and writes formatted report files to disk
(or returns formatted text for display). It performs no forensic
*interpretation* beyond presenting whatever the other modules already
concluded -- it never upgrades weaker evidence into a stronger claim,
and it never invents information that was not supplied.

EPISTEMIC FIELD LABELING
-------------------------
Where the supplied data distinguishes it (e.g. the ``"field_classification"``
produced by :meth:`modules.analyzer.BluetoothAnalyzer.build_forensic_profile`),
this module tags each field with how it was established:

* ``OBSERVED`` -- directly supported by collected evidence.
* ``REPORTED`` -- supplied by another trusted module/source rather than
  directly observed by this analysis pass.
* ``DERIVED``  -- calculated or reconstructed by BlueTrace from other
  evidence (e.g. connection history, timeline).
* ``UNKNOWN``  -- not established from the available evidence.

Missing values are never silently rendered as blank or ``"N/A"`` where
doing so would hide this distinction; instead this module uses explicit
labels such as ``UNKNOWN``, ``NOT AVAILABLE``, or
``NOT ESTABLISHED FROM AVAILABLE EVIDENCE`` depending on context.

RAW VS DERIVED EVIDENCE
------------------------
This module also distinguishes evidence *categories* when presenting
sources and integrity results, consistent with
:mod:`modules.hashing`: ``raw`` (e.g. journalctl output, BlueZ
artifacts), ``derived`` (e.g. connection history, timeline, device
forensic profiles -- BlueTrace's own analysis output), ``metadata``,
and ``report`` (this report itself). Derived analysis is never
presented as if it were an original/raw forensic source.

NO DATA COLLECTION
--------------------
This module never invokes ``bluetoothctl``, ``journalctl``, ``hcitool``,
``btmon``, or any other external command, and never performs Bluetooth
scanning or network access of any kind. It strictly formats and writes
data that is handed to it.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and BLE devices on Linux.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Final

from config import CLI_MENU_WIDTH, LOG_LEVEL, PROJECT_NAME, PROJECT_VERSION
from modules.hashing import (
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_FAIL,
    STATUS_MISSING,
    STATUS_NOT_VERIFIABLE,
    STATUS_PASS,
)
from modules.utils import (
    bytes_to_human,
    current_datetime_iso,
    ensure_directory,
    format_rssi,
    get_platform_information,
    safe_write_text,
)

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Value displayed for fields with no available data.
_UNKNOWN_VALUE: Final[str] = "Unknown"

#: Text displayed for report sections with no available data.
_NO_DATA_MESSAGE: Final[str] = "No data available."

#: Character used to draw section separator rules in text reports.
_SECTION_RULE_CHAR: Final[str] = "-"

#: Character used to draw the top-level report banner rule.
_BANNER_RULE_CHAR: Final[str] = "="

# --- New forensic-presentation constants ----------------------------------#

#: Display value used when a field could not be established from the
#: available evidence at all (as opposed to simply being empty).
_NOT_ESTABLISHED: Final[str] = "NOT ESTABLISHED FROM AVAILABLE EVIDENCE"

#: Display value used when a section/field is not available because no
#: relevant data was supplied to the report.
_NOT_AVAILABLE: Final[str] = "NOT AVAILABLE"

#: Display value used for genuinely unknown scalar fields.
_UNKNOWN_DISPLAY: Final[str] = "UNKNOWN"

#: Column width used for aligned ``label : value`` lines in forensic
#: report sections.
_LABEL_WIDTH: Final[int] = 18

#: Human-readable display label for the hashing algorithm, used only for
#: presentation. The authoritative algorithm value always comes from the
#: supplied hashing/integrity data when available.
_DEFAULT_HASH_ALGORITHM_DISPLAY: Final[str] = "SHA-256"

#: Maps the lowercase epistemic status values produced by
#: :meth:`modules.analyzer.BluetoothAnalyzer.build_forensic_profile`
#: (``"observed"``, ``"reported"``, ``"derived"``, ``"unknown"``) to
#: their report-display form.
_CLASSIFICATION_DISPLAY: Final[dict[str, str]] = {
    "observed": "OBSERVED",
    "reported": "REPORTED",
    "derived": "DERIVED",
    "unknown": "UNKNOWN",
}

#: Maps the structured verification statuses produced by
#: :mod:`modules.hashing` to their report-display form. Values not
#: present in this mapping (e.g. ``"INCOMPLETE"``, which
#: :meth:`modules.hashing.EvidenceHasher.verify_evidence_manifest` may
#: return) are displayed exactly as supplied.
_INTEGRITY_STATUS_DISPLAY: Final[dict[str, str]] = {
    STATUS_PASS: "PASS",
    STATUS_FAIL: "FAIL",
    STATUS_MISSING: "MISSING",
    STATUS_NOT_VERIFIABLE: "NOT_VERIFIABLE",
    STATUS_DISABLED: "DISABLED",
    STATUS_ERROR: "ERROR",
}

#: Recognized report types for :meth:`ForensicReportGenerator.render_forensic_report`
#: and :meth:`ForensicReportGenerator.generate_forensic_report`.
REPORT_TYPE_SUMMARY: Final[str] = "summary"
REPORT_TYPE_DETAILED: Final[str] = "detailed"
REPORT_TYPE_CONNECTION_HISTORY: Final[str] = "connection_history"
REPORT_TYPE_INTEGRITY: Final[str] = "integrity"

_VALID_REPORT_TYPES: Final[frozenset[str]] = frozenset(
    {
        REPORT_TYPE_SUMMARY,
        REPORT_TYPE_DETAILED,
        REPORT_TYPE_CONNECTION_HISTORY,
        REPORT_TYPE_INTEGRITY,
    }
)


class ForensicReportGenerator:
    """Format previously-collected evidence data into forensic reports.

    This class consumes structured data already produced by other
    BlueTrace modules and renders it as JSON or plain-text reports. It
    performs no Bluetooth communication, device analysis, artifact
    collection, or hashing of its own; it strictly formats and writes
    data that is handed to it, and never modifies the input data it is
    given.
    """

    def __init__(self) -> None:
        """Initialize the report generator's logger and configuration."""
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # ----------------------------------------------------------------- #
    # Metadata and summary (existing, preserved API)
    # ----------------------------------------------------------------- #

    def generate_metadata(self) -> dict[str, Any]:
        """Generate metadata describing this report's generation context.

        Returns:
            A dictionary with keys ``"report_time"`` (ISO 8601 timestamp),
            ``"generator"`` (the project name), ``"project_version"``,
            and ``"platform"`` (host platform details, from
            :func:`modules.utils.get_platform_information`).
        """
        return {
            "report_time": current_datetime_iso(),
            "generator": PROJECT_NAME,
            "project_version": PROJECT_VERSION,
            "platform": get_platform_information(),
        }

    def generate_case_summary(self, data: dict[str, Any]) -> dict[str, Any]:
        """Generate a concise summary of a collected evidence dataset.

        Args:
            data: The aggregated evidence dictionary, optionally
                containing ``"case_information"``, ``"discovered_devices"``,
                ``"device_analysis"``, ``"linux_artifacts"``, and
                ``"evidence_hashes"`` keys, as produced by the other
                BlueTrace modules.

        Returns:
            A dictionary with keys ``"case_id"``, ``"report_generated"``,
            ``"total_devices_discovered"``, ``"total_devices_analyzed"``,
            ``"paired_devices"``, ``"trusted_devices"``, and
            ``"total_files_hashed"``. Returns ``{"error": "missing_data"}``
            if ``data`` is not a dictionary.
        """
        if not isinstance(data, dict):
            self._logger.warning("No data supplied for case summary.")
            return {"error": "missing_data"}

        case_information = data.get("case_information")
        case_information = case_information if isinstance(case_information, dict) else {}

        discovered_devices = data.get("discovered_devices")
        discovered_devices = discovered_devices if isinstance(discovered_devices, list) else []

        device_analysis = data.get("device_analysis")
        if isinstance(device_analysis, dict):
            device_analysis = [device_analysis]
        elif not isinstance(device_analysis, list):
            device_analysis = []

        linux_artifacts = data.get("linux_artifacts")
        linux_artifacts = linux_artifacts if isinstance(linux_artifacts, dict) else {}

        evidence_hashes = data.get("evidence_hashes")
        evidence_hashes = evidence_hashes if isinstance(evidence_hashes, dict) else {}

        hashed_files = evidence_hashes.get("files")
        hashed_files = hashed_files if isinstance(hashed_files, list) else []

        paired_devices = linux_artifacts.get("paired_devices")
        paired_devices = paired_devices if isinstance(paired_devices, list) else []

        trusted_devices = linux_artifacts.get("trusted_devices")
        trusted_devices = trusted_devices if isinstance(trusted_devices, list) else []

        return {
            "case_id": case_information.get("case_id", _UNKNOWN_VALUE),
            "report_generated": current_datetime_iso(),
            "total_devices_discovered": len(discovered_devices),
            "total_devices_analyzed": len(device_analysis),
            "paired_devices": len(paired_devices),
            "trusted_devices": len(trusted_devices),
            "total_files_hashed": len(hashed_files),
        }

    # ----------------------------------------------------------------- #
    # Text report formatting helpers (existing, preserved API)
    # ----------------------------------------------------------------- #

    def _format_banner(self, title: str) -> str:
        """Build a top-level banner block for the text report.

        Args:
            title: The banner title text.

        Returns:
            A multi-line banner string bordered by
            :data:`_BANNER_RULE_CHAR`.
        """
        rule = _BANNER_RULE_CHAR * CLI_MENU_WIDTH
        return f"{rule}\n{title.center(CLI_MENU_WIDTH)}\n{rule}\n"

    def _format_section_title(self, title: str) -> str:
        """Build a section heading block for the text report.

        Args:
            title: The section title text.

        Returns:
            A multi-line section heading string bordered by
            :data:`_SECTION_RULE_CHAR`.
        """
        rule = _SECTION_RULE_CHAR * CLI_MENU_WIDTH
        return f"\n{rule}\n{title}\n{rule}\n"

    def _format_mapping(self, mapping: dict[str, Any]) -> str:
        """Format a flat mapping as ``key: value`` lines.

        Args:
            mapping: The dictionary to format.

        Returns:
            A newline-joined string of ``"key: value"`` lines, or
            :data:`_NO_DATA_MESSAGE` if ``mapping`` is empty.
        """
        if not mapping:
            return _NO_DATA_MESSAGE
        return "\n".join(f"{key}: {value}" for key, value in mapping.items())

    def _format_discovered_devices(self, devices: list[dict[str, Any]]) -> str:
        """Format a list of scanner-discovered devices.

        Args:
            devices: A list of device dictionaries (see
                :meth:`modules.scanner.BluetoothScanner.scan`).

        Returns:
            A newline-joined, numbered listing of devices, or
            :data:`_NO_DATA_MESSAGE` if ``devices`` is empty.
        """
        if not devices:
            return _NO_DATA_MESSAGE

        lines: list[str] = []
        for index, device in enumerate(devices, start=1):
            lines.append(
                f"{index}. {device.get('name', _UNKNOWN_VALUE)} | "
                f"MAC: {device.get('mac', _UNKNOWN_VALUE)} | "
                f"Type: {device.get('type', _UNKNOWN_VALUE)} | "
                f"RSSI: {device.get('rssi', 'N/A')}"
            )
        return "\n".join(lines)

    def _format_device_analysis(self, analysis: Any) -> str:
        """Format one or more analyzer results.

        Args:
            analysis: A single device analysis dictionary or a list of
                them (see
                :meth:`modules.analyzer.BluetoothAnalyzer.build_summary`).

        Returns:
            A blank-line-separated listing of device analysis blocks, or
            :data:`_NO_DATA_MESSAGE` if no analysis data is available.
        """
        if isinstance(analysis, dict):
            analysis_entries = [analysis]
        elif isinstance(analysis, list):
            analysis_entries = analysis
        else:
            analysis_entries = []

        blocks: list[str] = []
        for entry in analysis_entries:
            if not isinstance(entry, dict):
                continue
            services = entry.get("services") or []
            uuids = entry.get("uuids") or []
            blocks.append(
                "\n".join(
                    [
                        f"Device: {entry.get('device_name', _UNKNOWN_VALUE)}",
                        f"  MAC: {entry.get('mac', _UNKNOWN_VALUE)}",
                        f"  Vendor: {entry.get('vendor', _UNKNOWN_VALUE)}",
                        f"  Device Class: {entry.get('device_class', _UNKNOWN_VALUE)}",
                        f"  RSSI: {entry.get('rssi', 'N/A')}",
                        f"  Services: {', '.join(services) if services else 'None'}",
                        f"  Advertised UUIDs: {len(uuids)}",
                    ]
                )
            )

        return "\n\n".join(blocks) if blocks else _NO_DATA_MESSAGE

    def _format_linux_artifacts(self, artifacts: dict[str, Any]) -> str:
        """Format local Linux Bluetooth artifact data.

        Args:
            artifacts: The artifact dictionary produced by
                :meth:`modules.linux_artifacts.LinuxArtifactsCollector.collect_all`.

        Returns:
            A multi-line summary of the Bluetooth state directory and
            cached device counts, or :data:`_NO_DATA_MESSAGE` if
            ``artifacts`` is empty.
        """
        if not artifacts:
            return _NO_DATA_MESSAGE

        directory = artifacts.get("bluetooth_directory")
        directory = directory if isinstance(directory, dict) else {}
        known_devices = artifacts.get("known_devices")
        known_devices = known_devices if isinstance(known_devices, list) else []
        paired_devices = artifacts.get("paired_devices")
        paired_devices = paired_devices if isinstance(paired_devices, list) else []
        trusted_devices = artifacts.get("trusted_devices")
        trusted_devices = trusted_devices if isinstance(trusted_devices, list) else []

        lines = [
            f"Bluetooth State Directory: {directory.get('path', _UNKNOWN_VALUE)}",
            f"  Exists: {directory.get('exists', False)}",
            f"  Accessible: {directory.get('accessible', False)}",
            f"Known Devices Cached: {len(known_devices)}",
            f"Paired Devices: {len(paired_devices)}",
            f"Trusted Devices: {len(trusted_devices)}",
        ]

        for device in known_devices:
            if not isinstance(device, dict):
                continue
            lines.append(
                f"  - {device.get('name', _UNKNOWN_VALUE)} "
                f"({device.get('mac', _UNKNOWN_VALUE)}) "
                f"paired={device.get('paired', False)} "
                f"trusted={device.get('trusted', False)}"
            )

        return "\n".join(lines)

    def _format_evidence_hashes(self, hashes: dict[str, Any]) -> str:
        """Format an evidence integrity/hash record.

        Args:
            hashes: The hash/integrity dictionary produced by
                :meth:`modules.hashing.EvidenceHasher.generate_integrity_record`
                or
                :meth:`modules.hashing.EvidenceHasher.calculate_directory_hash`.

        Returns:
            A multi-line listing of hashed files and their digests, or
            :data:`_NO_DATA_MESSAGE` if ``hashes`` is empty.
        """
        if not hashes:
            return _NO_DATA_MESSAGE

        lines = [
            f"Algorithm: {hashes.get('algorithm', _UNKNOWN_VALUE)}",
            f"Timestamp: {hashes.get('timestamp', _UNKNOWN_VALUE)}",
        ]

        files = hashes.get("files")
        files = files if isinstance(files, list) else []
        if not files:
            lines.append("No files hashed.")
        else:
            for entry in files:
                if not isinstance(entry, dict):
                    continue
                lines.append(
                    f"  {entry.get('file', _UNKNOWN_VALUE)}: "
                    f"{entry.get('sha256', _UNKNOWN_VALUE)}"
                )

        return "\n".join(lines)

    # ----------------------------------------------------------------- #
    # Report generation (existing, preserved API)
    # ----------------------------------------------------------------- #

    def generate_text_report(
        self, data: dict[str, Any], output_path: Path
    ) -> dict[str, Any]:
        """Generate a human-readable forensic report in TXT format.

        Includes, in order: report metadata, Case Information, Host
        Information, Bluetooth Controller, Discovered Devices, Device
        Analysis, Linux Artifacts, Evidence Hashes, and Summary.

        Args:
            data: The aggregated evidence dictionary, optionally
                containing ``"case_information"``, ``"host_information"``,
                ``"bluetooth_controller"``, ``"discovered_devices"``,
                ``"device_analysis"``, ``"linux_artifacts"``, and
                ``"evidence_hashes"`` keys. Missing sections are rendered
                with :data:`_NO_DATA_MESSAGE` rather than causing failure.
            output_path: The destination file path for the report.

        Returns:
            The structured result dictionary produced by
            :meth:`save_report`.
        """
        if not isinstance(data, dict) or not data:
            self._logger.warning("No data supplied for text report generation.")
            return {"success": False, "path": None, "error": "missing_data"}

        metadata = self.generate_metadata()
        summary = self.generate_case_summary(data)

        case_information = data.get("case_information")
        case_information = case_information if isinstance(case_information, dict) else {}

        host_information = data.get("host_information")
        host_information = host_information if isinstance(host_information, dict) else {}

        bluetooth_controller = data.get("bluetooth_controller")
        bluetooth_controller = (
            bluetooth_controller if isinstance(bluetooth_controller, dict) else {}
        )

        discovered_devices = data.get("discovered_devices")
        discovered_devices = discovered_devices if isinstance(discovered_devices, list) else []

        linux_artifacts = data.get("linux_artifacts")
        linux_artifacts = linux_artifacts if isinstance(linux_artifacts, dict) else {}

        evidence_hashes = data.get("evidence_hashes")
        evidence_hashes = evidence_hashes if isinstance(evidence_hashes, dict) else {}

        sections: list[str] = [
            self._format_banner(f"{PROJECT_NAME} - Forensic Report"),
            self._format_mapping(metadata),
            self._format_section_title("Case Information"),
            self._format_mapping(case_information),
            self._format_section_title("Host Information"),
            self._format_mapping(host_information),
            self._format_section_title("Bluetooth Controller"),
            self._format_mapping(bluetooth_controller),
            self._format_section_title("Discovered Devices"),
            self._format_discovered_devices(discovered_devices),
            self._format_section_title("Device Analysis"),
            self._format_device_analysis(data.get("device_analysis")),
            self._format_section_title("Linux Artifacts"),
            self._format_linux_artifacts(linux_artifacts),
            self._format_section_title("Evidence Hashes"),
            self._format_evidence_hashes(evidence_hashes),
            self._format_section_title("Summary"),
            self._format_mapping(summary),
        ]

        content = "\n".join(sections) + "\n"
        return self.save_report(content, output_path)

    def generate_json_report(self, data: Any, output_path: Path) -> dict[str, Any]:
        """Save a structured JSON report of the collected evidence data.

        Args:
            data: The JSON-serializable evidence data to save.
            output_path: The destination file path for the report.

        Returns:
            A dictionary with keys ``"success"`` (bool), ``"path"`` (str
            or ``None``), and ``"error"`` (str or ``None``). Never
            raises; serialization failures, missing data, and write
            failures are all reported as structured errors.
        """
        if data is None:
            self._logger.warning("No data supplied for JSON report generation.")
            return {"success": False, "path": None, "error": "missing_data"}

        try:
            serialized = json.dumps(data, indent=4, default=str, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            self._logger.warning("Could not serialize report data: %s", exc)
            return {"success": False, "path": None, "error": "serialization_failed"}

        return self.save_report(serialized, output_path)

    def save_report(self, content: str, output_path: Path) -> dict[str, Any]:
        """Safely write report content to disk, creating directories as needed.

        Args:
            content: The fully-rendered report content to write.
            output_path: The destination file path.

        Returns:
            A dictionary with keys ``"success"`` (bool), ``"path"`` (str
            or ``None``), and ``"error"`` (str or ``None``, one of
            ``"missing_data"``, ``"invalid_directory"``, or
            ``"write_failed"`` on failure). Never raises.
        """
        result: dict[str, Any] = {"success": False, "path": None, "error": None}

        if not isinstance(content, str) or not content:
            self._logger.warning("No report content supplied to save.")
            result["error"] = "missing_data"
            return result

        if not ensure_directory(output_path.parent):
            self._logger.error(
                "Could not create or access report directory: %s",
                output_path.parent,
            )
            result["error"] = "invalid_directory"
            return result

        if output_path.exists():
            self._logger.info("Overwriting existing report file: %s", output_path)

        if not safe_write_text(output_path, content):
            self._logger.error("Failed to write report to %s.", output_path)
            result["error"] = "write_failed"
            return result

        result["success"] = True
        result["path"] = str(output_path)
        return result

    # ----------------------------------------------------------------- #
    # Small presentation utilities (new)
    # ----------------------------------------------------------------- #

    @staticmethod
    def _field(label: str, value: Any) -> str:
        """Format one aligned ``label : value`` report line.

        Args:
            label: The field label (will be left-padded to
                :data:`_LABEL_WIDTH`).
            value: The value to display, already resolved to its final
                display form (e.g. via :meth:`_display_value`).

        Returns:
            A single formatted line, e.g. ``"MAC Address       : AA:BB:..."``.
        """
        return f"{label:<{_LABEL_WIDTH}}: {value}"

    @staticmethod
    def _display_value(value: Any, empty_display: str = _UNKNOWN_DISPLAY) -> Any:
        """Resolve a raw field value to its report display form.

        Treats ``None``, empty strings, and the conventional
        ``"Unknown"`` sentinel used by other BlueTrace modules as
        "not established", replacing them with an explicit display
        value rather than a blank or ``"N/A"``.

        Args:
            value: The raw value from supplied evidence data.
            empty_display: The display string to use when ``value`` is
                empty/unknown. Defaults to :data:`_UNKNOWN_DISPLAY`.

        Returns:
            ``value`` unchanged if it is meaningfully present, otherwise
            ``empty_display``.
        """
        if value is None:
            return empty_display
        if isinstance(value, str) and (not value.strip() or value.strip() == _UNKNOWN_VALUE):
            return empty_display
        return value

    @staticmethod
    def _display_tri_bool(value: Any) -> str:
        """Format a tri-state boolean (``True``/``False``/``None``) for display.

        Args:
            value: ``True``, ``False``, or ``None`` (unknown/not
                established).

        Returns:
            ``"YES"``, ``"NO"``, or :data:`_UNKNOWN_DISPLAY`.
        """
        if value is True:
            return "YES"
        if value is False:
            return "NO"
        return _UNKNOWN_DISPLAY

    def _classification_tag(
        self, field_classification: dict[str, str] | None, field_name: str
    ) -> str:
        """Build a bracketed epistemic-status tag for a profile field.

        Args:
            field_classification: The ``"field_classification"`` mapping
                from
                :meth:`modules.analyzer.BluetoothAnalyzer.build_forensic_profile`,
                or ``None`` if unavailable (e.g. a legacy
                :meth:`~modules.analyzer.BluetoothAnalyzer.build_summary`
                result was supplied instead).
            field_name: The field key to look up.

        Returns:
            A string like ``" (OBSERVED)"``, or an empty string if no
            classification is available for this field.
        """
        if not isinstance(field_classification, dict):
            return ""
        status = field_classification.get(field_name)
        display = _CLASSIFICATION_DISPLAY.get(status) if status else None
        return f" ({display})" if display else ""

    # ----------------------------------------------------------------- #
    # Forensic report section builders (new)
    # ----------------------------------------------------------------- #

    def _format_case_header(self, case_data: dict[str, Any]) -> str:
        """Build the "CASE / EVIDENCE INFORMATION" section.

        Args:
            case_data: The report's top-level input dictionary. Reads
                the optional keys ``"evidence_id"`` and
                ``"hash_algorithm"``.

        Returns:
            A multi-line formatted section body (without heading rule;
            the caller adds the section title separately).
        """
        evidence_id = self._display_value(case_data.get("evidence_id"), _NOT_AVAILABLE)
        hash_algorithm = case_data.get("hash_algorithm") or _DEFAULT_HASH_ALGORITHM_DISPLAY

        lines = [
            self._field("Evidence ID", evidence_id),
            self._field("Generated At", current_datetime_iso()),
            self._field("Hash Algorithm", hash_algorithm),
        ]
        return "\n".join(lines)

    def _resolve_device_profile(self, case_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize either analyzer output schema into one presentation shape.

        Accepts either the richer, epistemically-labeled output of
        :meth:`modules.analyzer.BluetoothAnalyzer.build_forensic_profile`
        (under the ``"device_profile"`` key) or the flatter legacy
        output of
        :meth:`modules.analyzer.BluetoothAnalyzer.build_summary`/``analyze_device``
        (under ``"device_summary"`` or ``"device_analysis"``), without
        mutating either input.

        Args:
            case_data: The report's top-level input dictionary.

        Returns:
            A normalized dictionary with keys ``"mac_address"``,
            ``"name"``, ``"alias"``, ``"vendor"``, ``"address_type"``,
            ``"device_type"``, ``"device_class"``, ``"rssi"``,
            ``"tx_power"``, ``"appearance"``, ``"service_uuids"``,
            ``"service_data"``, ``"manufacturer_data"``,
            ``"sdp_services"``, ``"local_relationship"`` (dict or
            ``None``), ``"field_classification"`` (dict or ``None``),
            and ``"available"`` (bool, ``False`` if no profile data was
            supplied at all).
        """
        forensic_profile = case_data.get("device_profile")
        if isinstance(forensic_profile, dict) and forensic_profile.get("mac_address"):
            return {
                "mac_address": forensic_profile.get("mac_address"),
                "name": forensic_profile.get("name"),
                "alias": forensic_profile.get("alias"),
                "vendor": forensic_profile.get("vendor"),
                "address_type": forensic_profile.get("address_type"),
                "device_type": forensic_profile.get("device_type"),
                "device_class": forensic_profile.get("device_class"),
                "rssi": forensic_profile.get("rssi"),
                "tx_power": forensic_profile.get("tx_power"),
                "appearance": forensic_profile.get("appearance"),
                "service_uuids": forensic_profile.get("service_uuids") or [],
                "service_data": forensic_profile.get("service_data") or {},
                "manufacturer_data": forensic_profile.get("manufacturer_data") or {},
                "sdp_services": forensic_profile.get("sdp_services") or [],
                "local_relationship": forensic_profile.get("local_relationship"),
                "field_classification": forensic_profile.get("field_classification"),
                "available": True,
            }

        legacy_summary = case_data.get("device_summary") or case_data.get("device_analysis")
        if isinstance(legacy_summary, dict) and legacy_summary.get("mac"):
            uuids = legacy_summary.get("uuids") or []
            service_uuid_values = [
                entry.get("uuid") for entry in uuids
                if isinstance(entry, dict) and entry.get("uuid")
            ]
            return {
                "mac_address": legacy_summary.get("mac"),
                "name": legacy_summary.get("device_name"),
                "alias": None,
                "vendor": legacy_summary.get("vendor"),
                "address_type": None,
                "device_type": None,
                "device_class": legacy_summary.get("device_class"),
                "rssi": legacy_summary.get("rssi"),
                "tx_power": None,
                "appearance": None,
                "service_uuids": service_uuid_values,
                "service_data": {},
                "manufacturer_data": legacy_summary.get("manufacturer_data") or {},
                "sdp_services": legacy_summary.get("services") or [],
                "local_relationship": None,
                "field_classification": None,
                "available": True,
            }

        return {
            "mac_address": None,
            "name": None,
            "alias": None,
            "vendor": None,
            "address_type": None,
            "device_type": None,
            "device_class": None,
            "rssi": None,
            "tx_power": None,
            "appearance": None,
            "service_uuids": [],
            "service_data": {},
            "manufacturer_data": {},
            "sdp_services": [],
            "local_relationship": None,
            "field_classification": None,
            "available": False,
        }

    def _format_target_device(self, profile: dict[str, Any]) -> str:
        """Build the "TARGET DEVICE" section.

        Args:
            profile: A normalized profile dictionary from
                :meth:`_resolve_device_profile`.

        Returns:
            A multi-line formatted section body, or
            :data:`_NO_DATA_MESSAGE` if no profile data is available.
        """
        if not profile.get("available"):
            return _NO_DATA_MESSAGE

        classification = profile.get("field_classification")
        lines = [
            self._field(
                "MAC Address",
                self._display_value(profile.get("mac_address")),
            ),
            self._field(
                f"Device Name{self._classification_tag(classification, 'name')}",
                self._display_value(profile.get("name")),
            ),
            self._field(
                f"Vendor{self._classification_tag(classification, 'vendor')}",
                self._display_value(profile.get("vendor")),
            ),
            self._field(
                f"Address Type{self._classification_tag(classification, 'address_type')}",
                self._display_value(profile.get("address_type")),
            ),
            self._field(
                f"Device Type{self._classification_tag(classification, 'device_type')}",
                self._display_value(profile.get("device_type")),
            ),
        ]
        return "\n".join(lines)

    def _format_device_information(self, profile: dict[str, Any]) -> str:
        """Build the "DEVICE INFORMATION" section.

        Args:
            profile: A normalized profile dictionary from
                :meth:`_resolve_device_profile`.

        Returns:
            A multi-line formatted section body, or
            :data:`_NO_DATA_MESSAGE` if no profile data is available.
        """
        if not profile.get("available"):
            return _NO_DATA_MESSAGE

        classification = profile.get("field_classification")
        sdp_services = profile.get("sdp_services") or []
        service_uuids = profile.get("service_uuids") or []
        manufacturer_data = profile.get("manufacturer_data") or {}
        rssi_value = profile.get("rssi")

        lines = [
            self._field(
                f"Class of Device{self._classification_tag(classification, 'device_class')}",
                self._display_value(profile.get("device_class")),
            ),
            self._field(
                f"Services{self._classification_tag(classification, 'sdp_services')}",
                ", ".join(sdp_services) if sdp_services else _UNKNOWN_DISPLAY,
            ),
            self._field(
                "Service UUIDs",
                str(len(service_uuids)) if service_uuids else "0",
            ),
            self._field(
                f"Manufacturer Data{self._classification_tag(classification, 'manufacturer_data')}",
                f"{len(manufacturer_data)} entr{'y' if len(manufacturer_data) == 1 else 'ies'}"
                if manufacturer_data else _UNKNOWN_DISPLAY,
            ),
            self._field(
                f"RSSI{self._classification_tag(classification, 'rssi')}",
                format_rssi(rssi_value) if isinstance(rssi_value, (int, float)) else _UNKNOWN_DISPLAY,
            ),
        ]

        tx_power = profile.get("tx_power")
        if tx_power is not None:
            lines.append(
                self._field(
                    f"TX Power{self._classification_tag(classification, 'tx_power')}",
                    f"{tx_power} dBm",
                )
            )

        appearance = profile.get("appearance")
        if appearance:
            lines.append(
                self._field(
                    f"Appearance{self._classification_tag(classification, 'appearance')}",
                    appearance,
                )
            )

        return "\n".join(lines)

    def _format_local_relationship(self, profile: dict[str, Any]) -> str:
        """Build the "LOCAL RELATIONSHIP" section.

        Presents the locally-cached BlueZ relationship state (known,
        paired, trusted, blocked) exactly as reported by the supplied
        evidence, without inferring a stronger claim (e.g. "paired"
        never implies "currently connected" or "owned by").

        Args:
            profile: A normalized profile dictionary from
                :meth:`_resolve_device_profile`.

        Returns:
            A multi-line formatted section body, or
            :data:`_NO_DATA_MESSAGE` if no local relationship evidence
            is available.
        """
        relationship = profile.get("local_relationship")
        if not isinstance(relationship, dict):
            return _NO_DATA_MESSAGE

        lines = [
            self._field("Known", self._display_tri_bool(relationship.get("known"))),
            self._field("Paired", self._display_tri_bool(relationship.get("paired"))),
            self._field("Trusted", self._display_tri_bool(relationship.get("trusted"))),
            self._field("Blocked", self._display_tri_bool(relationship.get("blocked"))),
        ]

        note = relationship.get("note")
        if note:
            lines.append("")
            lines.append(f"Note: {note}")

        return "\n".join(lines)

    def _format_connection_history_event(self, event: dict[str, Any], index: int) -> str:
        """Format a single reconstructed connection-history event.

        Args:
            event: An event dictionary as produced by
                :class:`modules.connection_history.ConnectionHistoryAnalyzer`.
            index: The 1-based display sequence number.

        Returns:
            A multi-line, numbered block for this event.
        """
        event_type = str(event.get("event_type") or "unknown").upper()
        lines = [f"[{index}] {event_type}"]
        lines.append(self._field("MAC Address", self._display_value(event.get("mac_address"))))
        lines.append(self._field("Device Name", self._display_value(event.get("device_name"))))
        lines.append(self._field("Date", self._display_value(event.get("date"), _NOT_ESTABLISHED)))
        lines.append(self._field("Time", self._display_value(event.get("time"), _NOT_ESTABLISHED)))
        lines.append(self._field("Source", self._display_value(event.get("source_type"))))
        lines.append(
            self._field("Source Ref.", self._display_value(event.get("source_reference")))
        )
        lines.append(self._field("Confidence", self._display_value(event.get("confidence"))))
        corroboration = event.get("corroboration_count")
        if isinstance(corroboration, int) and corroboration > 1:
            lines.append(self._field("Corroborated By", f"{corroboration} sources"))
        return "\n".join(lines)

    def _format_connection_history(
        self, history: dict[str, Any] | None, max_events: int | None = None
    ) -> str:
        """Build the "CONNECTION HISTORY" section.

        Args:
            history: The result of
                :meth:`modules.connection_history.ConnectionHistoryAnalyzer.get_connection_history`
                or ``get_full_connection_timeline``, or ``None``/empty if
                no connection-history evidence was supplied.
            max_events: If given, only the first ``max_events`` events
                (newest-first, as already ordered by the source module)
                are shown, with a note about how many were omitted.

        Returns:
            A multi-line formatted section body. Never claims a "last
            connected" event exists unless the data actually contains
            one.
        """
        if not isinstance(history, dict) or not history:
            return (
                "No historical connection event could be established "
                "from the available evidence."
            )

        if not history.get("success", False):
            error = history.get("error", "unknown_error")
            return f"Connection history could not be reconstructed. Error: {error}"

        events = history.get("events")
        events = events if isinstance(events, list) else []
        total_events = history.get("total_events", len(events))
        connection_events = history.get("connection_events", 0)

        last_connected_event = next(
            (event for event in events if event.get("event_type") == "connected"), None
        )
        last_connected_display = (
            last_connected_event.get("timestamp") or _NOT_ESTABLISHED
            if last_connected_event
            else _NOT_ESTABLISHED
        )

        summary_lines = [
            self._field("Last Connected", last_connected_display),
            self._field("Total Events", str(total_events)),
            self._field("Connection Events", str(connection_events)),
        ]

        if not events:
            summary_lines.append("")
            summary_lines.append(
                "No historical connection event could be established "
                "from the available evidence."
            )
            return "\n".join(summary_lines)

        display_events = events if max_events is None else events[:max_events]
        event_blocks = [
            self._format_connection_history_event(event, index)
            for index, event in enumerate(display_events, start=1)
            if isinstance(event, dict)
        ]

        omitted = len(events) - len(display_events)
        sections = ["\n".join(summary_lines), ""] + event_blocks
        if omitted > 0:
            sections.append(f"... {omitted} additional event(s) omitted from this summary.")

        return "\n".join(sections)

    def _format_timeline_entry(self, entry: dict[str, Any], index: int) -> str:
        """Format a single normalized forensic timeline entry.

        Args:
            entry: A timeline entry as produced by
                :class:`modules.timeline.ForensicTimeline`.
            index: The 1-based display sequence number (unused in the
                rendered text but accepted for symmetry with
                :meth:`_format_connection_history_event`).

        Returns:
            A multi-line block for this timeline entry.
        """
        timestamp = entry.get("timestamp") or _NOT_ESTABLISHED
        event_type = str(entry.get("event_type") or "unknown").upper()
        lines = [f"{timestamp} | {event_type}"]
        lines.append(f"  MAC: {self._display_value(entry.get('mac_address'))}")
        device_name = entry.get("device_name")
        if device_name:
            lines.append(f"  Device: {device_name}")
        lines.append(f"  Source: {self._display_value(entry.get('source_type'))}")
        lines.append(f"  Confidence: {self._display_value(entry.get('confidence'))}")
        corroboration = entry.get("corroboration_count")
        if isinstance(corroboration, int) and corroboration > 1:
            lines.append(f"  Corroborated By: {corroboration} sources")
        return "\n".join(lines)

    def _format_timeline(
        self, timeline_result: dict[str, Any] | None, max_entries: int | None = None
    ) -> str:
        """Build the "FORENSIC TIMELINE" section.

        Args:
            timeline_result: The result of
                :meth:`modules.timeline.ForensicTimeline.build_timeline`,
                ``get_case_timeline``, or ``get_device_timeline``, or
                ``None``/empty if no timeline evidence was supplied.
            max_entries: If given, only the first ``max_entries`` entries
                (already newest-first) are shown.

        Returns:
            A multi-line formatted section body. Events are never
            reordered from the sequence supplied by the timeline
            module.
        """
        if not isinstance(timeline_result, dict) or not timeline_result:
            return "No forensic timeline could be established from the available evidence."

        if not timeline_result.get("success", False):
            error = timeline_result.get("error", "unknown_error")
            return f"Forensic timeline could not be built. Error: {error}"

        entries = timeline_result.get("timeline")
        entries = entries if isinstance(entries, list) else []
        total_events = timeline_result.get("total_events", len(entries))
        skipped_events = timeline_result.get("skipped_events", 0)

        header_lines = [
            self._field("Total Events", str(total_events)),
        ]
        if skipped_events:
            header_lines.append(self._field("Skipped Events", str(skipped_events)))

        if not entries:
            header_lines.append("")
            header_lines.append(
                "No timeline events are available from the supplied evidence."
            )
            return "\n".join(header_lines)

        display_entries = entries if max_entries is None else entries[:max_entries]
        entry_blocks = [
            self._format_timeline_entry(entry, index)
            for index, entry in enumerate(display_entries, start=1)
            if isinstance(entry, dict)
        ]

        omitted = len(entries) - len(display_entries)
        rendered = "\n".join(header_lines) + "\n\n" + "\n\n".join(entry_blocks)
        if omitted > 0:
            rendered += f"\n\n... {omitted} additional event(s) omitted from this summary."

        return rendered

    def _resolve_evidence_sources(self, case_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract the list of raw evidence source records from case data.

        Args:
            case_data: The report's top-level input dictionary. Prefers
                an explicit ``"evidence_sources"`` list; otherwise falls
                back to ``linux_artifacts["connection_log_evidence"]``
                (see
                :meth:`modules.linux_artifacts.LinuxArtifactsCollector.collect_all`).

        Returns:
            A list of source-record dictionaries (each typically with
            ``"source_type"``, ``"source_reference"``, ``"success"``,
            and ``"error"``). Never fabricates a source that was not
            actually present in the supplied data.
        """
        explicit_sources = case_data.get("evidence_sources")
        if isinstance(explicit_sources, list):
            return [entry for entry in explicit_sources if isinstance(entry, dict)]

        linux_artifacts = case_data.get("linux_artifacts")
        if isinstance(linux_artifacts, dict):
            log_evidence = linux_artifacts.get("connection_log_evidence")
            if isinstance(log_evidence, list):
                return [entry for entry in log_evidence if isinstance(entry, dict)]

        return []

    def _format_evidence_sources(self, sources: list[dict[str, Any]]) -> str:
        """Build the "EVIDENCE SOURCES" section.

        Args:
            sources: A list of evidence-source records, as returned by
                :meth:`_resolve_evidence_sources`.

        Returns:
            A multi-line, numbered listing of sources actually present
            in the supplied data, or :data:`_NO_DATA_MESSAGE` if none
            were supplied.
        """
        if not sources:
            return _NO_DATA_MESSAGE

        lines: list[str] = []
        for index, source in enumerate(sources, start=1):
            source_type = self._display_value(source.get("source_type"))
            source_reference = self._display_value(source.get("source_reference"))
            success = source.get("success")
            status = "COLLECTED" if success else "UNAVAILABLE" if success is False else _UNKNOWN_DISPLAY
            line = f"[{index}] {source_type} ({source_reference}) - {status}"
            error = source.get("error")
            if error and not success:
                line += f" - {error}"
            lines.append(line)

        return "\n".join(lines)

    def _format_integrity(self, integrity: dict[str, Any] | None) -> str:
        """Build the "EVIDENCE INTEGRITY" section.

        Args:
            integrity: The structured verification result produced by
                :meth:`modules.hashing.EvidenceHasher.verify_evidence_manifest`
                or :meth:`~modules.hashing.EvidenceHasher.verify_integrity_record`,
                or ``None``/empty if hashing/verification was not
                performed. Statuses are displayed exactly as reported --
                ``NOT_VERIFIABLE`` is never presented as ``PASS``.

        Returns:
            A multi-line formatted section body.
        """
        if not isinstance(integrity, dict) or not integrity:
            return self._field("Status", STATUS_DISABLED)

        overall_status = integrity.get("integrity_status", STATUS_ERROR)
        overall_display = _INTEGRITY_STATUS_DISPLAY.get(overall_status, str(overall_status))

        if overall_status == STATUS_DISABLED:
            return self._field("Status", overall_display)

        evidence_count = integrity.get("evidence_count", integrity.get("file_count", 0))
        verified_count = integrity.get("verified_count", 0)
        failed_count = integrity.get("failed_count", 0)
        not_verifiable_count = integrity.get("not_verifiable_count", 0)

        lines = [
            self._field("Algorithm", _DEFAULT_HASH_ALGORITHM_DISPLAY),
            self._field("Evidence Items", str(evidence_count)),
            self._field("Verified", str(verified_count)),
            self._field("Failed", str(failed_count)),
            self._field("Not Verifiable", str(not_verifiable_count)),
            "",
            self._field("FINAL INTEGRITY", overall_display),
        ]

        results = integrity.get("results")
        if isinstance(results, list):
            failing = [
                entry for entry in results
                if isinstance(entry, dict) and entry.get("status") not in (STATUS_PASS,)
            ]
            if failing:
                lines.append("")
                lines.append("Items requiring attention:")
                for entry in failing:
                    status_display = _INTEGRITY_STATUS_DISPLAY.get(
                        entry.get("status"), str(entry.get("status"))
                    )
                    identifier = entry.get("evidence_id") or entry.get("path") or _UNKNOWN_DISPLAY
                    lines.append(f"  - {identifier}: {status_display}")

        return "\n".join(lines)

    def _format_limitations(self) -> str:
        """Build the standard "FORENSIC LIMITATIONS" section.

        This text is static and describes the inherent evidentiary
        limits of Bluetooth forensic reconstruction; it never varies
        based on supplied data and never makes accusations or draws
        conclusions about any person.

        Returns:
            A multi-line, bulleted list of forensic limitations.
        """
        limitations = [
            "Historical connection data depends entirely on the logs "
            "and artifacts that were actually available for analysis.",
            "Paired, known, or trusted status reflects locally cached "
            "BlueZ state only; it is not automatic proof of a "
            "historical or current connection.",
            "Missing or rotated logs can produce an incomplete "
            "connection history or timeline, not a complete one with "
            "gaps silently filled in.",
            "BLE devices using private/random addresses may rotate "
            "their advertised MAC address, which can complicate "
            "correlation across observations.",
            "RSSI reflects relative signal strength only and does not "
            "establish exact physical distance.",
            "A device name or vendor label does not establish the "
            "identity or ownership of the device or its user.",
            "SHA-256 hashes verify data integrity only -- that hashed "
            "content matches what was originally hashed. They do not "
            "verify the truthfulness, authenticity, or ownership of "
            "the underlying evidence.",
        ]
        return "\n".join(f"- {item}" for item in limitations)

    # ----------------------------------------------------------------- #
    # Forensic report rendering and generation (new)
    # ----------------------------------------------------------------- #

    def render_forensic_report(
        self, case_data: dict[str, Any], report_type: str = REPORT_TYPE_DETAILED
    ) -> str:
        """Render a complete forensic report as plain text (in memory).

        This does not write anything to disk; use
        :meth:`generate_forensic_report` (or one of its
        report-type-specific wrappers) to also persist the result.

        Args:
            case_data: A dictionary describing the case, with any of the
                following optional keys:

                * ``"evidence_id"`` (str), ``"hash_algorithm"`` (str)
                * ``"device_profile"``: output of
                  :meth:`modules.analyzer.BluetoothAnalyzer.build_forensic_profile`
                * ``"device_summary"`` / ``"device_analysis"``: output
                  of :meth:`~modules.analyzer.BluetoothAnalyzer.build_summary`
                  (legacy fallback if ``"device_profile"`` is absent)
                * ``"connection_history"``: output of
                  :meth:`modules.connection_history.ConnectionHistoryAnalyzer.get_connection_history`
                  or ``get_full_connection_timeline``
                * ``"timeline"``: output of
                  :meth:`modules.timeline.ForensicTimeline.build_timeline`
                  (or ``get_case_timeline``/``get_device_timeline``)
                * ``"linux_artifacts"``: output of
                  :meth:`modules.linux_artifacts.LinuxArtifactsCollector.collect_all`
                * ``"evidence_sources"``: an explicit list of source
                  records (overrides deriving them from
                  ``"linux_artifacts"``)
                * ``"integrity"``: output of
                  :meth:`modules.hashing.EvidenceHasher.verify_evidence_manifest`
                  or ``verify_integrity_record``

                Every key is optional; missing sections are rendered
                with an explicit "not established"/"no data" message
                rather than causing failure.
            report_type: One of :data:`REPORT_TYPE_SUMMARY`,
                :data:`REPORT_TYPE_DETAILED`,
                :data:`REPORT_TYPE_CONNECTION_HISTORY`, or
                :data:`REPORT_TYPE_INTEGRITY`. Unrecognized values fall
                back to :data:`REPORT_TYPE_DETAILED`.

        Returns:
            The fully rendered report text.
        """
        if not isinstance(case_data, dict):
            case_data = {}
        safe_report_type = report_type if report_type in _VALID_REPORT_TYPES else REPORT_TYPE_DETAILED

        profile = self._resolve_device_profile(case_data)
        connection_history = case_data.get("connection_history")
        timeline_result = case_data.get("timeline")
        integrity = case_data.get("integrity")
        evidence_sources = self._resolve_evidence_sources(case_data)

        sections: list[str] = [self._format_banner("BLUETOOTH FORENSIC REPORT")]

        sections.append(self._format_section_title("CASE / EVIDENCE INFORMATION"))
        sections.append(self._format_case_header(case_data))

        if safe_report_type in (REPORT_TYPE_SUMMARY, REPORT_TYPE_DETAILED):
            sections.append(self._format_section_title("TARGET DEVICE"))
            sections.append(self._format_target_device(profile))

        if safe_report_type == REPORT_TYPE_DETAILED:
            sections.append(self._format_section_title("DEVICE INFORMATION"))
            sections.append(self._format_device_information(profile))
            sections.append(self._format_section_title("LOCAL RELATIONSHIP"))
            sections.append(self._format_local_relationship(profile))

        if safe_report_type in (
            REPORT_TYPE_SUMMARY, REPORT_TYPE_DETAILED, REPORT_TYPE_CONNECTION_HISTORY,
        ):
            max_events = 3 if safe_report_type == REPORT_TYPE_SUMMARY else None
            sections.append(self._format_section_title("CONNECTION HISTORY"))
            sections.append(self._format_connection_history(connection_history, max_events))

        if safe_report_type in (REPORT_TYPE_DETAILED, REPORT_TYPE_CONNECTION_HISTORY):
            max_entries = None
            sections.append(self._format_section_title("FORENSIC TIMELINE"))
            sections.append(self._format_timeline(timeline_result, max_entries))

        if safe_report_type == REPORT_TYPE_DETAILED:
            sections.append(self._format_section_title("EVIDENCE SOURCES"))
            sections.append(self._format_evidence_sources(evidence_sources))

        if safe_report_type in (
            REPORT_TYPE_SUMMARY, REPORT_TYPE_DETAILED, REPORT_TYPE_INTEGRITY,
        ):
            sections.append(self._format_section_title("EVIDENCE INTEGRITY"))
            sections.append(self._format_integrity(integrity))

        if safe_report_type in (REPORT_TYPE_SUMMARY, REPORT_TYPE_DETAILED):
            sections.append(self._format_section_title("FORENSIC LIMITATIONS"))
            sections.append(self._format_limitations())

        banner_rule = _BANNER_RULE_CHAR * CLI_MENU_WIDTH
        sections.append(f"\n{banner_rule}")
        sections.append("END OF REPORT".center(CLI_MENU_WIDTH))
        sections.append(banner_rule)

        return "\n".join(sections) + "\n"

    def generate_forensic_report(
        self,
        case_data: dict[str, Any],
        output_path: Path,
        report_type: str = REPORT_TYPE_DETAILED,
    ) -> dict[str, Any]:
        """Render and save a complete forensic report as a text file.

        Args:
            case_data: See :meth:`render_forensic_report`.
            output_path: The destination file path for the report.
            report_type: See :meth:`render_forensic_report`.

        Returns:
            The structured result dictionary produced by
            :meth:`save_report`.
        """
        content = self.render_forensic_report(case_data, report_type)
        return self.save_report(content, output_path)

    def generate_summary_report(
        self, case_data: dict[str, Any], output_path: Path
    ) -> dict[str, Any]:
        """Generate a short, examiner-friendly forensic summary report.

        Includes: case/evidence information, target device, the most
        recent connection-history events, and integrity status. Omits
        detailed technical metadata and the full timeline for
        readability -- see :meth:`generate_detailed_forensic_report` for
        the complete version.

        Args:
            case_data: See :meth:`render_forensic_report`.
            output_path: The destination file path for the report.

        Returns:
            The structured result dictionary produced by
            :meth:`save_report`.
        """
        return self.generate_forensic_report(case_data, output_path, REPORT_TYPE_SUMMARY)

    def generate_detailed_forensic_report(
        self, case_data: dict[str, Any], output_path: Path
    ) -> dict[str, Any]:
        """Generate the complete, technically detailed forensic report.

        Includes every available section: case/evidence information,
        target device, device information, local relationship,
        connection history, forensic timeline, evidence sources,
        evidence integrity, and forensic limitations.

        Args:
            case_data: See :meth:`render_forensic_report`.
            output_path: The destination file path for the report.

        Returns:
            The structured result dictionary produced by
            :meth:`save_report`.
        """
        return self.generate_forensic_report(case_data, output_path, REPORT_TYPE_DETAILED)

    def generate_connection_history_report(
        self, case_data: dict[str, Any], output_path: Path
    ) -> dict[str, Any]:
        """Generate a report focused on connection history and timeline.

        Args:
            case_data: See :meth:`render_forensic_report`.
            output_path: The destination file path for the report.

        Returns:
            The structured result dictionary produced by
            :meth:`save_report`.
        """
        return self.generate_forensic_report(
            case_data, output_path, REPORT_TYPE_CONNECTION_HISTORY
        )

    def generate_integrity_report(
        self, case_data: dict[str, Any], output_path: Path
    ) -> dict[str, Any]:
        """Generate a report focused solely on SHA-256 evidence integrity.

        Args:
            case_data: See :meth:`render_forensic_report`. Only the
                ``"evidence_id"``, ``"hash_algorithm"``, and
                ``"integrity"`` keys are used.
            output_path: The destination file path for the report.

        Returns:
            The structured result dictionary produced by
            :meth:`save_report`.
        """
        return self.generate_forensic_report(case_data, output_path, REPORT_TYPE_INTEGRITY)


__all__: Final[list[str]] = [
    "ForensicReportGenerator",
    "REPORT_TYPE_SUMMARY",
    "REPORT_TYPE_DETAILED",
    "REPORT_TYPE_CONNECTION_HISTORY",
    "REPORT_TYPE_INTEGRITY",
]
