"""
modules/report.py
==================

Forensic report generation module for **BlueTrace Forensic Suite**.

This module contains the :class:`ForensicReportGenerator` class, whose
sole responsibility is to format evidence data already collected by other
modules (:mod:`modules.scanner`, :mod:`modules.analyzer`,
:mod:`modules.linux_artifacts`, and :mod:`modules.hashing`) into
human-readable and machine-readable forensic reports.

This module never scans, connects to, or analyzes Bluetooth devices,
never reads local Linux Bluetooth artifacts, never calculates hashes,
never captures packets, and never modifies evidence in any way. It only
reads data that is passed in and writes formatted report files to disk.

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
from modules.utils import (
    current_datetime_iso,
    ensure_directory,
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


class ForensicReportGenerator:
    """Format previously-collected evidence data into forensic reports.

    This class consumes structured data already produced by other
    BlueTrace modules and renders it as JSON or plain-text reports. It
    performs no Bluetooth communication, device analysis, artifact
    collection, or hashing of its own; it strictly formats and writes
    data that is handed to it.
    """

    def __init__(self) -> None:
        """Initialize the report generator's logger and configuration."""
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # ----------------------------------------------------------------- #
    # Metadata and summary
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
    # Text report formatting helpers
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
    # Report generation
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


__all__: Final[list[str]] = ["ForensicReportGenerator"]
