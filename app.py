"""
app.py
======

Main entry point for **BlueTrace Forensic Suite**.

This module contains the :class:`BlueTraceApplication` class, a
professional Linux terminal application that coordinates every module in
the framework -- :mod:`modules.scanner`, :mod:`modules.analyzer`,
:mod:`modules.linux_artifacts`, :mod:`modules.connection_history`,
:mod:`modules.timeline`, :mod:`modules.hashing`, and
:mod:`modules.report` -- into a single, menu-driven forensic
investigation workflow:

    Case / Evidence Setup
        -> Bluetooth Device Discovery
        -> Target Device Selection
        -> Evidence Collection (local Linux Bluetooth artifacts)
        -> Device Analysis
        -> Connection History Reconstruction
        -> Forensic Timeline
        -> SHA-256 Evidence Hashing / Integrity Verification
        -> Forensic Report Generation

This module contains no Bluetooth communication logic, no analysis
logic, no artifact-collection logic, no connection-history
reconstruction logic, no timeline-building logic, no hashing logic, and
no report-formatting logic of its own; it strictly orchestrates the
existing modules and holds the in-memory state of the current
investigation session.

GROUP PROJECT NOTE
-------------------
This is a group academic project. No examiner name, individual student
name, or fabricated investigator/organization identity is displayed
anywhere in this application. Only neutral labels (Case ID, Evidence ID,
Investigation) are used.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and BLE devices on Linux.

Usage:
    python3 app.py
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Final

from config import (
    CLI_BANNER_TITLE,
    CLI_MENU_WIDTH,
    CLIColors,
    LOG_LEVEL,
    PROJECT_VERSION,
    REPORTS_DIR,
)
from modules.analyzer import BluetoothAnalyzer
from modules.connection_history import ConnectionHistoryAnalyzer
from modules.hashing import (
    CATEGORY_DERIVED,
    CATEGORY_RAW,
    EvidenceHasher,
)
from modules.linux_artifacts import LinuxArtifactsCollector
from modules.report import (
    REPORT_TYPE_CONNECTION_HISTORY,
    REPORT_TYPE_DETAILED,
    REPORT_TYPE_INTEGRITY,
    REPORT_TYPE_SUMMARY,
    ForensicReportGenerator,
)
from modules.scanner import BluetoothScanner
from modules.timeline import ForensicTimeline
from modules.utils import (
    create_case_directory,
    current_timestamp,
    generate_case_id,
    is_valid_mac_address,
    normalize_mac_address,
    safe_json_dump,
    sanitize_filename,
)

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Filename format string for the text-based forensic reports produced
#: by this application. ``config.py`` defines PDF/JSON/CSV formats but no
#: TXT counterpart, so a local format is used here (consistent with the
#: project's existing convention of case_id + timestamp filenames).
_REPORT_FILENAME_FORMAT: Final[str] = (
    "bluetrace_{report_type}_report_{case_id}_{timestamp}.txt"
)

#: Filename used for the JSON snapshot of raw local Bluetooth artifacts
#: written into the case evidence directory so it can be hashed and
#: independently re-verified from disk (rather than only hashed
#: in-memory, which cannot later be re-verified without the original
#: data).
_EVIDENCE_BUNDLE_FILENAME: Final[str] = "linux_artifacts_bundle.json"

#: Main menu option labels, in display order.
_MENU_OPTIONS: Final[tuple[str, ...]] = (
    "Start New Investigation",
    "Review Current Investigation",
    "Generate Forensic Report",
    "Verify Evidence Integrity",
    "Exit",
)

#: Report-type submenu: (input key, report_type constant, display label).
_REPORT_TYPE_CHOICES: Final[tuple[tuple[str, str, str], ...]] = (
    ("1", REPORT_TYPE_SUMMARY, "Summary Report"),
    ("2", REPORT_TYPE_DETAILED, "Detailed Forensic Report"),
    ("3", REPORT_TYPE_CONNECTION_HISTORY, "Connection History Report"),
    ("4", REPORT_TYPE_INTEGRITY, "Integrity Report"),
)

#: Maps :meth:`modules.hashing.EvidenceHasher.verify_evidence_manifest`'s
#: ``"integrity_status"`` values to the terminal-facing final status
#: labels described by the project's workflow requirements. Values are
#: never remapped in a way that turns a failure or an unverifiable
#: result into a false "PASS".
_FINAL_INTEGRITY_DISPLAY: Final[dict[str, str]] = {
    "PASS": "PASS",
    "FAIL": "FAIL",
    "DISABLED": "DISABLED",
    "ERROR": "ERROR",
    "INCOMPLETE": "NOT_VERIFIABLE",
}


class BlueTraceApplication:
    """Menu-driven terminal application coordinating the forensic workflow.

    This class wires together :class:`modules.scanner.BluetoothScanner`,
    :class:`modules.analyzer.BluetoothAnalyzer`,
    :class:`modules.linux_artifacts.LinuxArtifactsCollector`,
    :class:`modules.connection_history.ConnectionHistoryAnalyzer`,
    :class:`modules.timeline.ForensicTimeline`,
    :class:`modules.hashing.EvidenceHasher`, and
    :class:`modules.report.ForensicReportGenerator` into a single
    investigation session, holding all collected evidence in memory for
    the duration of the run. It performs no forensic collection,
    analysis, hashing, or reporting logic itself.
    """

    def __init__(self) -> None:
        """Initialize the application, its modules, and its case state."""
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

        self._scanner = BluetoothScanner()
        self._analyzer = BluetoothAnalyzer()
        self._artifacts_collector = LinuxArtifactsCollector()
        self._connection_history_analyzer = ConnectionHistoryAnalyzer()
        self._timeline_engine = ForensicTimeline()
        self._hasher = EvidenceHasher()
        self._report_generator = ForensicReportGenerator()

        self._case_id = generate_case_id()
        self._evidence_id = f"EVID-{self._case_id}"
        self._case_directory = create_case_directory(self._case_id)

        # In-memory investigation state, shared across menu actions so
        # that previously collected results can be reused.
        self._investigation_note: str | None = None
        self._target_mac: str | None = None
        self._discovered_devices: list[dict[str, Any]] = []
        self._linux_artifacts: dict[str, Any] = {}
        self._device_profile: dict[str, Any] | None = None
        self._connection_history: dict[str, Any] | None = None
        self._timeline_result: dict[str, Any] | None = None
        self._evidence_manifest: dict[str, Any] | None = None
        self._integrity_result: dict[str, Any] | None = None
        self._reports: dict[str, Any] = {}
        self._investigation_active = False

        self._running = True

    # ----------------------------------------------------------------- #
    # Terminal presentation helpers
    # ----------------------------------------------------------------- #

    def _print_rule(self, character: str = "=") -> None:
        """Print a full-width horizontal rule.

        Args:
            character: The single character used to draw the rule.
        """
        print(character * CLI_MENU_WIDTH)

    def _print_section(self, title: str) -> None:
        """Print a section heading bordered by a horizontal rule.

        Args:
            title: The section title text.
        """
        print(f"\n{CLIColors.BOLD}{CLIColors.CYAN}{title}{CLIColors.RESET}")
        self._print_rule("-")

    def display_banner(self) -> None:
        """Display the application's startup banner and case identifiers.

        No examiner, student, or organization name is displayed, per the
        group-project requirement; only neutral case/evidence labels.
        """
        self._print_rule("=")
        print(f"{CLIColors.BOLD}{CLIColors.CYAN}{CLI_BANNER_TITLE.center(CLI_MENU_WIDTH)}{CLIColors.RESET}")
        print(f"Version {PROJECT_VERSION}".center(CLI_MENU_WIDTH))
        self._print_rule("=")
        print("Bluetooth Digital Forensics & Evidence Acquisition")
        print(f"Case ID:      {self._case_id}")
        print(f"Evidence ID:  {self._evidence_id}")
        if self._case_directory is not None:
            print(f"Case Dir:     {self._case_directory}")
        else:
            print(
                f"{CLIColors.YELLOW}Case Dir:     unavailable "
                f"(could not create evidence directory){CLIColors.RESET}"
            )
        self._print_rule("=")

    def display_menu(self) -> None:
        """Display the main menu."""
        self._print_section("Main Menu")
        for index, label in enumerate(_MENU_OPTIONS, start=1):
            print(f"  {CLIColors.GREEN}{index}.{CLIColors.RESET} {label}")
        self._print_rule("-")

    # ----------------------------------------------------------------- #
    # Investigation setup
    # ----------------------------------------------------------------- #

    def setup_case_information(self) -> None:
        """Collect basic, non-personal case/evidence information from the user.

        Only case-level metadata is requested: an optional investigation
        note and an optional target MAC address. No personal, examiner,
        or organizational information is collected.
        """
        self._print_section("Case / Evidence Setup")
        print(f"Case ID:      {self._case_id}")
        print(f"Evidence ID:  {self._evidence_id}")

        note = input("Investigation note (optional): ").strip()
        self._investigation_note = note or None

        manual_target = input(
            "Target MAC address (optional, press Enter to skip): "
        ).strip()
        if manual_target:
            if is_valid_mac_address(manual_target):
                self._target_mac = manual_target
            else:
                print(
                    f"{CLIColors.YELLOW}The provided MAC address is not "
                    f"validly formatted and will be ignored.{CLIColors.RESET}"
                )

    # ----------------------------------------------------------------- #
    # Bluetooth discovery and target selection
    # ----------------------------------------------------------------- #

    def discover_devices(self) -> None:
        """Scan for nearby Bluetooth devices using :class:`BluetoothScanner`.

        Uses the project's existing scanner implementation exclusively;
        no scanning logic is duplicated here. If discovery fails, the
        investigation continues with manual target selection rather than
        aborting.
        """
        self._print_section("Bluetooth Device Discovery")
        print("Scanning for nearby Bluetooth devices...")

        try:
            devices = asyncio.run(self._scanner.scan())
        except (RuntimeError, OSError) as exc:
            self._logger.error("Bluetooth scan failed unexpectedly: %s", exc)
            print(f"{CLIColors.RED}[!] Bluetooth discovery failed: {exc}{CLIColors.RESET}")
            print(
                f"{CLIColors.YELLOW}[!] Continuing with manual target "
                f"selection.{CLIColors.RESET}"
            )
            self._discovered_devices = []
            return

        self._discovered_devices = devices

        if not devices:
            print(f"{CLIColors.YELLOW}No Bluetooth devices were discovered.{CLIColors.RESET}")
            return

        print("\nBLUETOOTH DEVICES DISCOVERED")
        self._print_rule("-")
        for index, device in enumerate(devices, start=1):
            print(
                f"[{index}] {device.get('name', 'Unknown')}\n"
                f"    MAC  : {device.get('mac', 'Unknown')}\n"
                f"    RSSI : {device.get('rssi', 'N/A')}\n"
                f"    Type : {device.get('type', 'Unknown')}"
            )

        statistics = self._scanner.get_statistics(devices)
        print(
            f"\n{CLIColors.GREEN}Total: {statistics['total_devices']} "
            f"(BLE: {statistics['ble_devices']}, "
            f"Classic: {statistics['classic_devices']}, "
            f"Unknown: {statistics['unknown_devices']}){CLIColors.RESET}"
        )

    def select_target(self) -> None:
        """Select the investigation's target device.

        If a target MAC was already supplied during case setup, it is
        reused as-is. Otherwise the user may choose a discovered device
        or enter a MAC address manually. A manually entered MAC is only
        validated for correct formatting -- entering it does not confirm
        that such a device actually exists or was ever observed.
        """
        self._print_section("Target Device Selection")

        if self._target_mac:
            print(f"Using previously provided target MAC: {self._target_mac}")
            return

        manual_option = str(len(self._discovered_devices) + 1)

        if self._discovered_devices:
            for index, device in enumerate(self._discovered_devices, start=1):
                print(
                    f"  {index}. {device.get('name', 'Unknown')} "
                    f"({device.get('mac', 'Unknown')})"
                )
            print(f"  {manual_option}. Enter MAC address manually")
        else:
            print(f"{CLIColors.YELLOW}No devices were discovered.{CLIColors.RESET}")

        selection = input("\nSelect target device: ").strip()
        if not selection:
            print(f"{CLIColors.RED}No selection made.{CLIColors.RESET}")
            return

        if not self._discovered_devices or selection == manual_option:
            manual_mac = input("Enter target MAC address: ").strip()
            if not is_valid_mac_address(manual_mac):
                print(f"{CLIColors.RED}Invalid MAC address format.{CLIColors.RESET}")
                return
            self._target_mac = manual_mac
            print(
                f"{CLIColors.YELLOW}Note: manual entry does not confirm this "
                f"device actually exists or was observed.{CLIColors.RESET}"
            )
            return

        try:
            selected_index = int(selection) - 1
        except ValueError:
            print(f"{CLIColors.RED}Invalid selection.{CLIColors.RESET}")
            return

        if not 0 <= selected_index < len(self._discovered_devices):
            print(f"{CLIColors.RED}Selection out of range.{CLIColors.RESET}")
            return

        candidate_mac = self._discovered_devices[selected_index].get("mac", "")
        if not is_valid_mac_address(candidate_mac):
            print(
                f"{CLIColors.RED}Selected device has no valid MAC "
                f"address.{CLIColors.RESET}"
            )
            return

        self._target_mac = candidate_mac

    # ----------------------------------------------------------------- #
    # Evidence collection and analysis
    # ----------------------------------------------------------------- #

    def collect_evidence(self) -> None:
        """Collect local Linux Bluetooth artifacts using :class:`LinuxArtifactsCollector`.

        Displays only evidence that was actually collected; no counts or
        fields are fabricated.
        """
        self._print_section("Evidence Collection")

        self._linux_artifacts = self._artifacts_collector.collect_all()

        host_information = self._linux_artifacts.get("host_information", {})
        controller = self._linux_artifacts.get("bluetooth_controller", {})
        known_devices = self._linux_artifacts.get("known_devices", [])
        paired_devices = self._linux_artifacts.get("paired_devices", [])
        trusted_devices = self._linux_artifacts.get("trusted_devices", [])
        blocked_devices = self._linux_artifacts.get("blocked_devices", [])
        log_evidence = self._linux_artifacts.get("connection_log_evidence", [])
        collected_logs = [entry for entry in log_evidence if entry.get("success")]

        print(f"Hostname:        {host_information.get('hostname', 'Unknown')}")
        print(f"Distribution:    {host_information.get('distribution', 'Unknown')}")
        print(f"Controller MAC:  {controller.get('mac', 'Unknown')}")
        print(f"Controller Name: {controller.get('name', 'Unknown')}")
        print(
            f"\nKnown devices: {len(known_devices)}  |  "
            f"Paired: {len(paired_devices)}  |  "
            f"Trusted: {len(trusted_devices)}  |  "
            f"Blocked: {len(blocked_devices)}"
        )
        print(
            f"Bluetooth log sources attempted: {len(log_evidence)}  |  "
            f"Collected: {len(collected_logs)}"
        )

    def analyze_target(self) -> None:
        """Analyze the target device using :class:`BluetoothAnalyzer`.

        Passes any matching local BlueZ relationship state already
        collected by :class:`LinuxArtifactsCollector` as supplementary
        evidence, so the analyzer can label such fields as "reported"
        rather than "observed" -- never converting a paired/trusted
        relationship into a claim of ownership or connection.
        """
        self._print_section("Target Device Analysis")

        if not self._target_mac:
            print(
                f"{CLIColors.YELLOW}No target device selected; skipping "
                f"analysis.{CLIColors.RESET}"
            )
            return

        known_devices = self._linux_artifacts.get("known_devices", [])
        normalized_target = normalize_mac_address(self._target_mac) or self._target_mac
        local_relationship = next(
            (device for device in known_devices if device.get("mac") == normalized_target),
            None,
        )

        evidence: dict[str, Any] = {
            "source": {"type": "bluetrace_investigation", "reference": self._case_id},
        }
        if local_relationship:
            evidence["local_relationship"] = local_relationship

        self._device_profile = self._analyzer.build_forensic_profile(
            self._target_mac, evidence=evidence
        )

        if self._device_profile.get("error"):
            print(
                f"{CLIColors.RED}Analysis failed: "
                f"{self._device_profile['error']}{CLIColors.RESET}"
            )
            return

        print("TARGET DEVICE")
        self._print_rule("-")
        print(f"MAC Address : {self._device_profile.get('mac_address')}")
        print(f"Name        : {self._device_profile.get('name')}")
        print(f"Vendor      : {self._device_profile.get('vendor')}")
        print(f"Device Type : {self._device_profile.get('device_type')}")
        print(f"RSSI        : {self._device_profile.get('rssi')}")

    # ----------------------------------------------------------------- #
    # Connection history and timeline
    # ----------------------------------------------------------------- #

    def build_connection_history(self) -> None:
        """Reconstruct connection history using :class:`ConnectionHistoryAnalyzer`.

        Consumes the evidence bundle already prepared by
        :class:`LinuxArtifactsCollector`
        (``linux_artifacts["connection_history_evidence"]``); no evidence
        parsing or reconstruction logic is duplicated here.
        """
        self._print_section("Connection History Reconstruction")

        if not self._target_mac:
            print(
                f"{CLIColors.YELLOW}No target device selected; skipping.{CLIColors.RESET}"
            )
            return

        ch_evidence = self._linux_artifacts.get("connection_history_evidence")
        if not ch_evidence:
            print(
                f"{CLIColors.YELLOW}[!] Connection history unavailable.\n"
                f"    Reason: no local evidence has been collected "
                f"yet.{CLIColors.RESET}"
            )
            return

        self._connection_history = self._connection_history_analyzer.get_connection_history(
            self._target_mac, ch_evidence
        )

        if not self._connection_history.get("success"):
            print(
                f"{CLIColors.YELLOW}[!] Connection history unavailable.\n"
                f"    Reason: {self._connection_history.get('error')}{CLIColors.RESET}"
            )
            return

        events = self._connection_history.get("events", [])
        if not events:
            print("LAST CONNECTED : NOT ESTABLISHED FROM AVAILABLE EVIDENCE")
            return

        print("CONNECTION HISTORY")
        self._print_rule("-")
        for index, event in enumerate(events, start=1):
            print(
                f"\n[{index}] {str(event.get('event_type', 'unknown')).upper()}\n"
                f"MAC       : {event.get('mac_address')}\n"
                f"Name      : {event.get('device_name') or 'Unknown'}\n"
                f"Date      : {event.get('date') or 'NOT ESTABLISHED FROM AVAILABLE EVIDENCE'}\n"
                f"Time      : {event.get('time') or 'NOT ESTABLISHED FROM AVAILABLE EVIDENCE'}\n"
                f"Source    : {event.get('source_type')}"
            )

    def build_forensic_timeline(self) -> None:
        """Build the forensic timeline using :class:`ForensicTimeline`.

        Uses the timeline module's own ordering exclusively; events are
        never re-sorted or reformatted by this application.
        """
        self._print_section("Forensic Timeline")

        if not self._connection_history or not self._connection_history.get("success"):
            print(
                f"{CLIColors.YELLOW}No connection-history evidence available "
                f"to build a timeline.{CLIColors.RESET}"
            )
            return

        events = self._connection_history.get("events", [])
        self._timeline_result = self._timeline_engine.get_device_timeline(
            events, self._target_mac
        )

        if not self._timeline_result.get("success"):
            print(
                f"{CLIColors.RED}Timeline construction failed: "
                f"{self._timeline_result.get('error')}{CLIColors.RESET}"
            )
            return

        entries = self._timeline_result.get("timeline", [])
        if not entries:
            print("No timeline events are available from the supplied evidence.")
            return

        print("FORENSIC TIMELINE")
        self._print_rule("-")
        for entry in entries:
            print(
                f"\n{entry.get('timestamp') or 'NOT ESTABLISHED'} | "
                f"{str(entry.get('event_type', 'unknown')).upper()}\n"
                f"MAC    : {entry.get('mac_address')}\n"
                f"Name   : {entry.get('device_name') or 'Unknown'}\n"
                f"Source : {entry.get('source_type')}"
            )

    # ----------------------------------------------------------------- #
    # SHA-256 evidence integrity
    # ----------------------------------------------------------------- #

    def calculate_integrity(self) -> None:
        """Hash and verify collected evidence using :class:`EvidenceHasher`.

        Writes the raw local-artifact bundle to the case evidence
        directory so it has an on-disk file that can be independently
        re-verified, then hashes the derived analysis results (device
        profile, connection history, timeline) in place. Builds an
        evidence manifest and verifies it, never presenting a failed or
        unverifiable result as a false "PASS".
        """
        self._print_section("Evidence Integrity (SHA-256)")

        if self._case_directory is None:
            print(
                f"{CLIColors.RED}No case evidence directory is available "
                f"to hash.{CLIColors.RESET}"
            )
            return

        manifest_items: list[dict[str, Any]] = []

        if self._linux_artifacts:
            bundle_path = self._case_directory / _EVIDENCE_BUNDLE_FILENAME
            if safe_json_dump(self._linux_artifacts, bundle_path):
                manifest_items.append(
                    self._hasher.hash_evidence_file(
                        bundle_path,
                        category=CATEGORY_RAW,
                        source_type="linux_artifacts_bundle",
                        source_reference=str(bundle_path),
                    )
                )
            else:
                print(
                    f"{CLIColors.YELLOW}Could not write the evidence bundle "
                    f"to disk for hashing.{CLIColors.RESET}"
                )

        if self._device_profile:
            manifest_items.append(
                self._hasher.hash_structured_evidence(
                    self._device_profile,
                    label="device_profile",
                    category=CATEGORY_DERIVED,
                )
            )
        if self._connection_history:
            manifest_items.append(
                self._hasher.hash_structured_evidence(
                    self._connection_history,
                    label="connection_history",
                    category=CATEGORY_DERIVED,
                )
            )
        if self._timeline_result:
            manifest_items.append(
                self._hasher.hash_structured_evidence(
                    self._timeline_result,
                    label="timeline",
                    category=CATEGORY_DERIVED,
                )
            )

        if not manifest_items:
            print(
                f"{CLIColors.YELLOW}No evidence is available yet to hash. "
                f"Collect evidence first.{CLIColors.RESET}"
            )
            return

        self._evidence_manifest = self._hasher.create_evidence_manifest(manifest_items)
        self._integrity_result = self._hasher.verify_evidence_manifest(
            self._evidence_manifest
        )

        overall_status = self._integrity_result.get("integrity_status", "DISABLED")
        final_status = _FINAL_INTEGRITY_DISPLAY.get(overall_status, overall_status)

        print("EVIDENCE INTEGRITY")
        self._print_rule("-")
        print("Algorithm      : SHA-256")
        print(f"Evidence Items : {self._integrity_result.get('evidence_count', 0)}")
        print(f"Verified       : {self._integrity_result.get('verified_count', 0)}")
        print(f"Failed         : {self._integrity_result.get('failed_count', 0)}")
        print(f"Not Verifiable : {self._integrity_result.get('not_verifiable_count', 0)}")
        print()
        print(f"FINAL STATUS   : {final_status}")

    # ----------------------------------------------------------------- #
    # Reporting
    # ----------------------------------------------------------------- #

    def _build_case_data(self) -> dict[str, Any]:
        """Assemble the in-memory investigation state for report generation.

        Returns:
            A dictionary matching the input schema expected by
            :meth:`modules.report.ForensicReportGenerator.render_forensic_report`.
            ``"evidence_sources"`` is intentionally omitted so the report
            generator derives it directly from ``"linux_artifacts"``
            rather than duplicating that data here.
        """
        return {
            "evidence_id": self._evidence_id,
            "hash_algorithm": "SHA-256",
            "device_profile": self._device_profile,
            "connection_history": self._connection_history,
            "timeline": self._timeline_result,
            "linux_artifacts": self._linux_artifacts,
            "integrity": self._integrity_result,
        }

    def _generate_report(self, report_type: str) -> None:
        """Render and save one forensic report using :class:`ForensicReportGenerator`.

        Args:
            report_type: One of the ``REPORT_TYPE_*`` constants from
                :mod:`modules.report`.
        """
        case_data = self._build_case_data()
        safe_case_id = sanitize_filename(self._case_id) or "case"
        timestamp = current_timestamp()

        output_path = REPORTS_DIR / _REPORT_FILENAME_FORMAT.format(
            report_type=report_type, case_id=safe_case_id, timestamp=timestamp
        )

        result = self._report_generator.generate_forensic_report(
            case_data, output_path, report_type
        )
        self._reports[report_type] = result

        if result.get("success"):
            print(f"{CLIColors.GREEN}Report saved: {result['path']}{CLIColors.RESET}")
        else:
            print(
                f"{CLIColors.RED}Report generation failed: "
                f"{result.get('error')}{CLIColors.RESET}"
            )

    def generate_report_menu(self) -> None:
        """Let the user choose and generate one of the available report types."""
        self._print_section("Generate Forensic Report")

        if self._case_directory is None:
            print(f"{CLIColors.RED}No case directory is available.{CLIColors.RESET}")
            return

        for key, _report_type, label in _REPORT_TYPE_CHOICES:
            print(f"  {key}. {label}")

        choice = input("\nSelect report type: ").strip()
        match = next(
            (report_type for key, report_type, _label in _REPORT_TYPE_CHOICES if key == choice),
            None,
        )
        if match is None:
            print(f"{CLIColors.RED}Invalid report choice: {choice}{CLIColors.RESET}")
            return

        self._generate_report(match)

    # ----------------------------------------------------------------- #
    # Summary and review
    # ----------------------------------------------------------------- #

    def display_summary(self) -> None:
        """Display a concise, examiner-friendly summary of the investigation.

        Every displayed value is read directly from already-computed
        results; nothing is invented or estimated here.
        """
        self._print_rule("=")
        print("FORENSIC ANALYSIS COMPLETE".center(CLI_MENU_WIDTH))
        self._print_rule("=")

        profile = self._device_profile or {}
        connection_history = self._connection_history or {}
        events = connection_history.get("events", [])
        connected_count = sum(1 for event in events if event.get("event_type") == "connected")

        timeline_entries = (self._timeline_result or {}).get("timeline", [])

        integrity_status = "DISABLED"
        if self._integrity_result:
            integrity_status = _FINAL_INTEGRITY_DISPLAY.get(
                self._integrity_result.get("integrity_status"), "DISABLED"
            )

        log_evidence = self._linux_artifacts.get("connection_log_evidence", [])
        collected_sources = [entry for entry in log_evidence if entry.get("success")]
        manifest_item_count = (
            len(self._evidence_manifest.get("items", [])) if self._evidence_manifest else 0
        )

        print("\nTARGET DEVICE")
        print(f"MAC       : {profile.get('mac_address') or self._target_mac or 'Unknown'}")
        print(f"Name      : {profile.get('name', 'Unknown')}")
        print(f"Vendor    : {profile.get('vendor', 'Unknown')}")

        print("\nCONNECTION EVENTS")
        print(f"Total     : {connection_history.get('total_events', 0)}")
        print(f"Connected : {connected_count}")

        print("\nTIMELINE")
        print(f"Events    : {len(timeline_entries)}")

        print("\nEVIDENCE")
        print(f"Sources   : {len(collected_sources)}")
        print(f"Files     : {manifest_item_count}")

        print("\nINTEGRITY")
        print(f"SHA-256   : {integrity_status}")

        self._print_rule("=")

    def review_investigation(self) -> None:
        """Display the current, in-memory state of the active investigation.

        There is no case-loading/persistence API in the underlying
        modules, so this reflects the current session's collected
        results rather than reading a saved case back from disk.
        """
        self._print_section("Current Investigation")

        if not self._investigation_active:
            print(
                f"{CLIColors.YELLOW}No investigation has been started yet "
                f"in this session.{CLIColors.RESET}"
            )
            return

        print(f"Case ID:           {self._case_id}")
        print(f"Evidence ID:       {self._evidence_id}")
        print(f"Investigation:     {self._investigation_note or 'Unknown'}")
        print(f"Target MAC:        {self._target_mac or 'Unknown'}")
        print(f"Discovered:        {len(self._discovered_devices)}")
        print(f"Artifacts:         {'Yes' if self._linux_artifacts else 'No'}")
        print(f"Device Profile:    {'Yes' if self._device_profile else 'No'}")
        print(f"Connection Hist.:  {'Yes' if self._connection_history else 'No'}")
        print(f"Timeline:          {'Yes' if self._timeline_result else 'No'}")
        print(f"Integrity Result:  {'Yes' if self._integrity_result else 'No'}")
        print(f"Reports Generated: {len(self._reports)}")

    # ----------------------------------------------------------------- #
    # Full investigation workflow
    # ----------------------------------------------------------------- #

    def start_investigation(self) -> None:
        """Run the complete guided investigation workflow end to end.

        Executes, in order: case/evidence setup, Bluetooth discovery,
        target selection, evidence collection, device analysis,
        connection-history reconstruction, forensic timeline
        construction, evidence integrity hashing, optional report
        generation, and a final investigation summary. Each stage relies
        on the underlying module methods, which already fail safely and
        report their own errors; a failure in one stage does not prevent
        later stages from running where that is still meaningful.
        """
        self._print_section("Starting New Investigation")

        self.setup_case_information()
        self.discover_devices()
        self.select_target()
        self.collect_evidence()
        self.analyze_target()
        self.build_connection_history()
        self.build_forensic_timeline()
        self.calculate_integrity()

        generate_now = input(
            "\nGenerate a forensic report now? (y/N): "
        ).strip().lower()
        if generate_now == "y":
            self.generate_report_menu()

        self._investigation_active = True
        self.display_summary()

    # ----------------------------------------------------------------- #
    # Main loop
    # ----------------------------------------------------------------- #

    def run(self) -> None:
        """Run the main menu loop until the user exits.

        Handles :class:`KeyboardInterrupt`, invalid menu input, and
        unexpected operating-system errors from underlying modules
        without ever crashing the application. Technical errors are
        logged; the terminal itself stays clean and examiner-friendly.
        """
        self.display_banner()

        while self._running:
            try:
                self.display_menu()
                choice = input("Select option: ").strip()

                if choice == "1":
                    self.start_investigation()
                elif choice == "2":
                    self.review_investigation()
                elif choice == "3":
                    self.generate_report_menu()
                elif choice == "4":
                    self.calculate_integrity()
                elif choice == "5":
                    print(f"{CLIColors.CYAN}Exiting BlueTrace Forensic Suite.{CLIColors.RESET}")
                    self._running = False
                else:
                    print(f"{CLIColors.RED}Invalid option: {choice}{CLIColors.RESET}")

            except KeyboardInterrupt:
                print(f"\n{CLIColors.YELLOW}Interrupted by user. Exiting.{CLIColors.RESET}")
                self._running = False
            except EOFError:
                print(f"\n{CLIColors.YELLOW}No further input. Exiting.{CLIColors.RESET}")
                self._running = False
            except OSError as exc:
                self._logger.error("Unexpected error in main menu loop: %s", exc)
                print(f"{CLIColors.RED}An unexpected error occurred: {exc}{CLIColors.RESET}")


def main() -> None:
    """Application entry point."""
    application = BlueTraceApplication()
    application.run()


if __name__ == "__main__":
    main()
