"""
app.py
======

Main entry point for **BlueTrace Forensic Suite**.

This module contains the :class:`BlueTraceApplication` class, a
professional Linux terminal application that coordinates every other
module in the framework (:mod:`modules.scanner`, :mod:`modules.analyzer`,
:mod:`modules.linux_artifacts`, :mod:`modules.hashing`, and
:mod:`modules.report`) into a single, menu-driven forensic investigation
workflow.

This module contains no Bluetooth communication logic, no analysis
logic, no artifact-collection logic, no hashing logic, and no report
formatting logic of its own; it strictly orchestrates the existing
modules and holds the in-memory state of the current investigation.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and BLE devices on Linux.

Usage:
    python3 app.py
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Final

from config import (
    CLI_BANNER_TITLE,
    CLI_MENU_WIDTH,
    CLIColors,
    JSON_REPORT_FILENAME_FORMAT,
    LOG_LEVEL,
    PROJECT_VERSION,
    REPORTS_DIR,
)
from modules.analyzer import BluetoothAnalyzer
from modules.hashing import EvidenceHasher
from modules.linux_artifacts import LinuxArtifactsCollector
from modules.report import ForensicReportGenerator
from modules.scanner import BluetoothScanner
from modules.utils import (
    create_case_directory,
    current_timestamp,
    generate_case_id,
    get_current_username,
    sanitize_filename,
)

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Filename format string for plain-text forensic reports. Mirrors
#: :data:`config.JSON_REPORT_FILENAME_FORMAT`, which has no TXT
#: counterpart defined in ``config.py``.
_TXT_REPORT_FILENAME_FORMAT: Final[str] = "bluetrace_report_{case_id}_{timestamp}.txt"

#: Main menu option labels, in display order.
_MENU_OPTIONS: Final[tuple[str, ...]] = (
    "Scan Bluetooth Devices",
    "Analyze Bluetooth Device",
    "Collect Linux Bluetooth Artifacts",
    "Generate Evidence Hashes",
    "Generate Forensic Report",
    "Complete Investigation",
    "Exit",
)


class BlueTraceApplication:
    """Menu-driven terminal application coordinating the forensic workflow.

    This class wires together :class:`modules.scanner.BluetoothScanner`,
    :class:`modules.analyzer.BluetoothAnalyzer`,
    :class:`modules.linux_artifacts.LinuxArtifactsCollector`,
    :class:`modules.hashing.EvidenceHasher`, and
    :class:`modules.report.ForensicReportGenerator` into a single
    investigation session, holding all collected evidence in memory for
    the duration of the run.
    """

    def __init__(self) -> None:
        """Initialize the application, its modules, and its case state."""
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

        self._scanner = BluetoothScanner()
        self._analyzer = BluetoothAnalyzer()
        self._artifacts_collector = LinuxArtifactsCollector()
        self._hasher = EvidenceHasher()
        self._report_generator = ForensicReportGenerator()

        self._case_id = generate_case_id()
        self._case_directory: Path | None = create_case_directory(self._case_id)

        # In-memory investigation state, shared across menu actions so
        # that previously collected results can be reused.
        self._discovered_devices: list[dict[str, Any]] = []
        self._device_analysis: list[dict[str, Any]] = []
        self._linux_artifacts: dict[str, Any] = {}
        self._evidence_hashes: dict[str, Any] = {}
        self._reports: dict[str, Any] = {}

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
        """Display the application's startup banner and case information."""
        self._print_rule("=")
        print(f"{CLIColors.BOLD}{CLIColors.CYAN}{CLI_BANNER_TITLE.center(CLI_MENU_WIDTH)}{CLIColors.RESET}")
        print(f"Version {PROJECT_VERSION}".center(CLI_MENU_WIDTH))
        self._print_rule("=")
        print(f"Case ID:   {self._case_id}")
        print(f"Examiner:  {get_current_username()}")
        if self._case_directory is not None:
            print(f"Case Dir:  {self._case_directory}")
        else:
            print(
                f"{CLIColors.YELLOW}Case Dir:  unavailable "
                f"(could not create evidence directory){CLIColors.RESET}"
            )
        self._print_rule("=")

    def display_menu(self) -> None:
        """Display the main menu and the current investigation status."""
        self._print_section("Main Menu")
        status = (
            f"Discovered: {len(self._discovered_devices)}  |  "
            f"Analyzed: {len(self._device_analysis)}  |  "
            f"Artifacts: {'Yes' if self._linux_artifacts else 'No'}  |  "
            f"Hashes: {'Yes' if self._evidence_hashes else 'No'}  |  "
            f"Reports: {'Yes' if self._reports else 'No'}"
        )
        print(status)
        print()
        for index, label in enumerate(_MENU_OPTIONS, start=1):
            print(f"  {CLIColors.GREEN}{index}.{CLIColors.RESET} {label}")
        self._print_rule("-")

    # ----------------------------------------------------------------- #
    # Menu actions
    # ----------------------------------------------------------------- #

    def scan_devices(self) -> None:
        """Scan for nearby Bluetooth devices using :class:`BluetoothScanner`."""
        self._print_section("Scanning for Bluetooth Devices")
        print("This may take a moment...")

        try:
            devices = asyncio.run(self._scanner.scan())
        except (RuntimeError, OSError) as exc:
            self._logger.error("Bluetooth scan failed unexpectedly: %s", exc)
            print(f"{CLIColors.RED}Scan failed: {exc}{CLIColors.RESET}")
            return

        self._discovered_devices = devices
        statistics = self._scanner.get_statistics(devices)

        if not devices:
            print(f"{CLIColors.YELLOW}No Bluetooth devices were discovered.{CLIColors.RESET}")
            return

        for index, device in enumerate(devices, start=1):
            print(
                f"  {index}. {device.get('name', 'Unknown')} | "
                f"MAC: {device.get('mac', 'Unknown')} | "
                f"Type: {device.get('type', 'Unknown')} | "
                f"RSSI: {device.get('rssi', 'N/A')}"
            )

        print(
            f"\n{CLIColors.GREEN}Total: {statistics['total_devices']} "
            f"(BLE: {statistics['ble_devices']}, "
            f"Classic: {statistics['classic_devices']}, "
            f"Unknown: {statistics['unknown_devices']}){CLIColors.RESET}"
        )

    def _run_device_analysis(self, mac_address: str) -> dict[str, Any]:
        """Analyze a single device and merge the result into case state.

        Any existing analysis result for the same MAC address is
        replaced, so re-analyzing a device does not create duplicates.

        Args:
            mac_address: The MAC address of the device to analyze.

        Returns:
            The analysis result dictionary produced by
            :meth:`modules.analyzer.BluetoothAnalyzer.analyze_device`.
        """
        result = self._analyzer.analyze_device(mac_address)
        normalized_mac = str(result.get("mac", mac_address)).upper()

        self._device_analysis = [
            entry
            for entry in self._device_analysis
            if str(entry.get("mac", "")).upper() != normalized_mac
        ]
        self._device_analysis.append(result)
        return result

    def analyze_device(self) -> None:
        """Let the user choose a previously discovered device to analyze."""
        self._print_section("Analyze Bluetooth Device")

        if not self._discovered_devices:
            print(
                f"{CLIColors.YELLOW}No devices discovered yet. "
                f"Run a scan first.{CLIColors.RESET}"
            )
            return

        for index, device in enumerate(self._discovered_devices, start=1):
            print(
                f"  {index}. {device.get('name', 'Unknown')} "
                f"({device.get('mac', 'Unknown')})"
            )

        try:
            selection = input("\nSelect a device number to analyze: ").strip()
            selected_index = int(selection) - 1
        except (ValueError, EOFError):
            print(f"{CLIColors.RED}Invalid selection.{CLIColors.RESET}")
            return

        if not 0 <= selected_index < len(self._discovered_devices):
            print(f"{CLIColors.RED}Selection out of range.{CLIColors.RESET}")
            return

        mac_address = self._discovered_devices[selected_index].get("mac", "")
        print(f"\nAnalyzing {mac_address}...")
        result = self._run_device_analysis(mac_address)

        if result.get("error"):
            print(f"{CLIColors.RED}Analysis failed: {result['error']}{CLIColors.RESET}")
            return

        print(f"{CLIColors.GREEN}Device Name:{CLIColors.RESET} {result.get('device_name')}")
        print(f"{CLIColors.GREEN}Vendor:{CLIColors.RESET} {result.get('vendor')}")
        print(f"{CLIColors.GREEN}Device Class:{CLIColors.RESET} {result.get('device_class')}")
        print(f"{CLIColors.GREEN}Services:{CLIColors.RESET} {result.get('services')}")
        print(f"{CLIColors.GREEN}UUIDs:{CLIColors.RESET} {len(result.get('uuids') or [])}")
        print(f"{CLIColors.GREEN}RSSI:{CLIColors.RESET} {result.get('rssi')}")

    def collect_linux_artifacts(self) -> None:
        """Collect local Linux Bluetooth artifacts using :class:`LinuxArtifactsCollector`."""
        self._print_section("Collecting Local Linux Bluetooth Artifacts")

        self._linux_artifacts = self._artifacts_collector.collect_all()

        host_information = self._linux_artifacts.get("host_information", {})
        controller = self._linux_artifacts.get("bluetooth_controller", {})
        known_devices = self._linux_artifacts.get("known_devices", [])
        paired_devices = self._linux_artifacts.get("paired_devices", [])
        trusted_devices = self._linux_artifacts.get("trusted_devices", [])

        print(f"Hostname:        {host_information.get('hostname', 'Unknown')}")
        print(f"Distribution:    {host_information.get('distribution', 'Unknown')}")
        print(f"Controller MAC:  {controller.get('mac', 'Unknown')}")
        print(f"Controller Name: {controller.get('name', 'Unknown')}")
        print(
            f"\n{CLIColors.GREEN}Known devices: {len(known_devices)} | "
            f"Paired: {len(paired_devices)} | "
            f"Trusted: {len(trusted_devices)}{CLIColors.RESET}"
        )

    def generate_hashes(self) -> None:
        """Generate an evidence integrity record using :class:`EvidenceHasher`."""
        self._print_section("Generating Evidence Hashes")

        if self._case_directory is None:
            print(
                f"{CLIColors.RED}No case evidence directory is available "
                f"to hash.{CLIColors.RESET}"
            )
            return

        self._evidence_hashes = self._hasher.generate_integrity_record(
            self._case_directory
        )

        if self._evidence_hashes.get("error"):
            print(
                f"{CLIColors.YELLOW}Integrity record generated with "
                f"note: {self._evidence_hashes['error']}{CLIColors.RESET}"
            )
        else:
            print(f"{CLIColors.GREEN}Integrity record generated successfully.{CLIColors.RESET}")

        file_count = len(self._evidence_hashes.get("files", []))
        print(f"Algorithm: {self._evidence_hashes.get('algorithm')}")
        print(f"Files hashed: {file_count}")

    def _build_report_data(self) -> dict[str, Any]:
        """Assemble the in-memory investigation state into report input data.

        Returns:
            A dictionary matching the structure expected by
            :class:`modules.report.ForensicReportGenerator`.
        """
        return {
            "case_information": {
                "case_id": self._case_id,
                "examiner": get_current_username(),
            },
            "host_information": self._linux_artifacts.get("host_information", {}),
            "bluetooth_controller": self._linux_artifacts.get("bluetooth_controller", {}),
            "discovered_devices": self._discovered_devices,
            "device_analysis": self._device_analysis,
            "linux_artifacts": self._linux_artifacts,
            "evidence_hashes": self._evidence_hashes,
        }

    def generate_reports(self) -> None:
        """Generate JSON and TXT forensic reports using :class:`ForensicReportGenerator`."""
        self._print_section("Generating Forensic Reports")

        report_data = self._build_report_data()
        safe_case_id = sanitize_filename(self._case_id) or "case"
        timestamp = current_timestamp()

        json_path = REPORTS_DIR / JSON_REPORT_FILENAME_FORMAT.format(
            case_id=safe_case_id, timestamp=timestamp
        )
        text_path = REPORTS_DIR / _TXT_REPORT_FILENAME_FORMAT.format(
            case_id=safe_case_id, timestamp=timestamp
        )

        json_result = self._report_generator.generate_json_report(report_data, json_path)
        text_result = self._report_generator.generate_text_report(report_data, text_path)
        self._reports = {"json": json_result, "text": text_result}

        if json_result.get("success"):
            print(f"{CLIColors.GREEN}JSON report saved: {json_result['path']}{CLIColors.RESET}")
        else:
            print(f"{CLIColors.RED}JSON report failed: {json_result.get('error')}{CLIColors.RESET}")

        if text_result.get("success"):
            print(f"{CLIColors.GREEN}TXT report saved: {text_result['path']}{CLIColors.RESET}")
        else:
            print(f"{CLIColors.RED}TXT report failed: {text_result.get('error')}{CLIColors.RESET}")

    def _display_investigation_summary(self) -> None:
        """Print a final summary of the completed investigation."""
        self._print_section("Investigation Summary")
        summary = self._report_generator.generate_case_summary(self._build_report_data())

        for key, value in summary.items():
            print(f"{key}: {value}")

    def run_complete_investigation(self) -> None:
        """Automatically run the full investigation workflow end to end.

        Executes, in order: device scan, analysis of every discovered
        device, local Linux artifact collection, evidence hash
        generation, report generation, and a final investigation
        summary. Never raises; each stage relies on the underlying
        module methods, which already fail safely.
        """
        self._print_section("Running Complete Investigation")

        self.scan_devices()

        if self._discovered_devices:
            print(f"\n{CLIColors.CYAN}Analyzing all discovered devices...{CLIColors.RESET}")
            for device in self._discovered_devices:
                mac_address = device.get("mac", "")
                if not mac_address:
                    continue
                self._run_device_analysis(mac_address)
            print(f"{CLIColors.GREEN}Analyzed {len(self._device_analysis)} device(s).{CLIColors.RESET}")

        self.collect_linux_artifacts()
        self.generate_hashes()
        self.generate_reports()
        self._display_investigation_summary()

    # ----------------------------------------------------------------- #
    # Main loop
    # ----------------------------------------------------------------- #

    def run(self) -> None:
        """Run the main menu loop until the user exits.

        Handles :class:`KeyboardInterrupt`, invalid menu input, and
        unexpected operating-system errors from underlying modules
        without ever crashing the application.
        """
        self.display_banner()

        while self._running:
            try:
                self.display_menu()
                choice = input("Select an option: ").strip()

                if choice == "1":
                    self.scan_devices()
                elif choice == "2":
                    self.analyze_device()
                elif choice == "3":
                    self.collect_linux_artifacts()
                elif choice == "4":
                    self.generate_hashes()
                elif choice == "5":
                    self.generate_reports()
                elif choice == "6":
                    self.run_complete_investigation()
                elif choice == "7":
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
