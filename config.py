"""
config.py
=========

Central configuration module for **BlueTrace Forensic Suite**.

This module contains ONLY static configuration values: project metadata,
filesystem paths, external tool names, default operational parameters,
report/log formatting, evidence-handling policy flags, and CLI display
constants.

It intentionally contains **no business logic**, **no subprocess calls**,
and **no Bluetooth scanning/acquisition code**. All other modules in the
BlueTrace Forensic Suite should import configuration values from here
rather than hard-coding them, ensuring a single source of truth for the
entire framework.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and Bluetooth Low Energy (BLE) devices on Linux.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Final

# --------------------------------------------------------------------------- #
# 1. Project Metadata
# --------------------------------------------------------------------------- #

PROJECT_NAME: Final[str] = "BlueTrace Forensic Suite"
PROJECT_VERSION: Final[str] = "1.0.0"
PROJECT_AUTHOR: Final[str] = "Your Name <your.email@example.com>"
PROJECT_DESCRIPTION: Final[str] = (
    "A Linux-based Bluetooth Digital Forensics and Evidence Acquisition "
    "Framework for collecting legally obtainable artifacts from Bluetooth "
    "Classic and BLE devices, and generating structured forensic reports."
)

# --------------------------------------------------------------------------- #
# 2. Directory Paths
# --------------------------------------------------------------------------- #

#: Root directory of the BlueTrace Forensic Suite installation. All other
#: framework directories are resolved relative to this location.
ROOT_DIR: Final[Path] = Path(__file__).resolve().parent

#: Directory where generated forensic reports (PDF/JSON/CSV) are stored.
REPORTS_DIR: Final[Path] = ROOT_DIR / "reports"

#: Directory where acquired evidence artifacts are stored.
EVIDENCE_DIR: Final[Path] = ROOT_DIR / "evidence"

#: Directory where application and audit logs are stored.
LOGS_DIR: Final[Path] = ROOT_DIR / "logs"

#: Directory where raw Bluetooth packet captures (e.g. btmon/HCI dumps)
#: are stored.
CAPTURES_DIR: Final[Path] = ROOT_DIR / "captures"

#: Directory containing the case-tracking database file(s).
DATABASE_DIR: Final[Path] = ROOT_DIR / "database"

#: Directory containing bundled sample cases for demonstration, training,
#: and automated testing purposes.
SAMPLE_CASES_DIR: Final[Path] = ROOT_DIR / "sample_cases"

#: Collection of all managed framework directories, used for bulk creation
#: and for validation checks elsewhere in the codebase.
MANAGED_DIRECTORIES: Final[tuple[Path, ...]] = (
    REPORTS_DIR,
    EVIDENCE_DIR,
    LOGS_DIR,
    CAPTURES_DIR,
    DATABASE_DIR,
    SAMPLE_CASES_DIR,
)


def ensure_directories(directories: tuple[Path, ...] = MANAGED_DIRECTORIES) -> None:
    """Create all required framework directories if they do not already exist.

    This function is idempotent: directories that already exist are left
    untouched, and parent directories are created as needed. It performs
    only filesystem path creation and contains no business logic.

    Args:
        directories: A tuple of directory paths to create. Defaults to the
            full set of framework-managed directories.
    """
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


# Ensure the standard directory layout exists as soon as the configuration
# module is imported, so that dependent modules can rely on these paths
# being present.
ensure_directories()

# --------------------------------------------------------------------------- #
# 3. Bluetooth Command Configuration
# --------------------------------------------------------------------------- #

#: Names of the external Linux Bluetooth-related command-line utilities
#: used by the framework. Only command *names* are stored here; invocation
#: logic lives in dedicated acquisition modules, not in this file.
BLUETOOTH_COMMANDS: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "bluetoothctl": "bluetoothctl",
        "btmgmt": "btmgmt",
        "btmon": "btmon",
        "sdptool": "sdptool",
        "hciconfig": "hciconfig",
        "journalctl": "journalctl",
        "rfkill": "rfkill",
    }
)

# --------------------------------------------------------------------------- #
# 4. Default Scan Settings
# --------------------------------------------------------------------------- #

#: Default timeout, in seconds, for a standard Bluetooth Classic device scan.
DEFAULT_SCAN_TIMEOUT_SECONDS: Final[int] = 30

#: Default timeout, in seconds, for a Bluetooth Low Energy (BLE) device scan.
DEFAULT_BLE_SCAN_TIMEOUT_SECONDS: Final[int] = 20

#: Default timeout, in seconds, for raw packet capture sessions
#: (e.g. via btmon or HCI snoop logs).
DEFAULT_PACKET_CAPTURE_TIMEOUT_SECONDS: Final[int] = 60

#: Maximum number of retry attempts for a failed acquisition operation
#: before it is marked as unsuccessful.
MAX_RETRIES: Final[int] = 3

# --------------------------------------------------------------------------- #
# 5. Report Settings
# --------------------------------------------------------------------------- #

#: Filename format string for PDF forensic reports. Expects a ``case_id``
#: and a ``timestamp`` field to be supplied by the reporting module.
PDF_REPORT_FILENAME_FORMAT: Final[str] = "bluetrace_report_{case_id}_{timestamp}.pdf"

#: Filename format string for JSON forensic reports. Expects a ``case_id``
#: and a ``timestamp`` field to be supplied by the reporting module.
JSON_REPORT_FILENAME_FORMAT: Final[str] = "bluetrace_report_{case_id}_{timestamp}.json"

#: Filename format string for CSV forensic reports. Expects a ``case_id``
#: and a ``timestamp`` field to be supplied by the reporting module.
CSV_REPORT_FILENAME_FORMAT: Final[str] = "bluetrace_report_{case_id}_{timestamp}.csv"

#: Timestamp format used when generating report filenames, compatible with
#: ``datetime.strftime``.
REPORT_TIMESTAMP_FORMAT: Final[str] = "%Y%m%d_%H%M%S"

# --------------------------------------------------------------------------- #
# 6. Logging Configuration
# --------------------------------------------------------------------------- #

#: Full path to the primary application log file.
LOG_FILE: Final[Path] = LOGS_DIR / "bluetrace.log"

#: Default logging level, expressed as a standard ``logging`` module level
#: name (e.g. "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
LOG_LEVEL: Final[str] = "INFO"

#: Default log message format string, compatible with the standard
#: ``logging`` module's ``Formatter`` class.
LOG_FORMAT: Final[str] = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)

#: Date format used within log messages, compatible with
#: ``logging.Formatter``.
LOG_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"

# --------------------------------------------------------------------------- #
# 7. Evidence Configuration
# --------------------------------------------------------------------------- #

#: Whether SHA-256 hashing of collected evidence artifacts is enabled, to
#: support chain-of-custody integrity verification.
SHA256_HASHING_ENABLED: Final[bool] = True

#: Whether a chronological timeline of acquisition events is generated
#: alongside collected evidence.
TIMELINE_GENERATION_ENABLED: Final[bool] = True

#: Whether the framework operates strictly in read-only acquisition mode,
#: prohibiting any write/modify operations against target devices.
READ_ONLY_ACQUISITION_MODE: Final[bool] = True

# --------------------------------------------------------------------------- #
# 8. CLI Configuration
# --------------------------------------------------------------------------- #

#: Title banner displayed when the CLI application starts.
CLI_BANNER_TITLE: Final[str] = "BlueTrace Forensic Suite"

#: Fixed width, in characters, used for CLI menu rendering and separators.
CLI_MENU_WIDTH: Final[int] = 60


class CLIColors:
    """ANSI color code constants used for CLI text styling.

    These constants are immutable string values representing standard
    ANSI escape sequences. They contain no logic and are intended purely
    for use by presentation-layer CLI modules.
    """

    RESET: Final[str] = "\033[0m"
    BOLD: Final[str] = "\033[1m"
    GREEN: Final[str] = "\033[32m"
    RED: Final[str] = "\033[31m"
    YELLOW: Final[str] = "\033[33m"
    BLUE: Final[str] = "\033[34m"
    CYAN: Final[str] = "\033[36m"
    MAGENTA: Final[str] = "\033[35m"
    WHITE: Final[str] = "\033[37m"


# --------------------------------------------------------------------------- #
# 9. Public Export Surface
# --------------------------------------------------------------------------- #

__all__: Final[list[str]] = [
    # Metadata
    "PROJECT_NAME",
    "PROJECT_VERSION",
    "PROJECT_AUTHOR",
    "PROJECT_DESCRIPTION",
    # Paths
    "ROOT_DIR",
    "REPORTS_DIR",
    "EVIDENCE_DIR",
    "LOGS_DIR",
    "CAPTURES_DIR",
    "DATABASE_DIR",
    "SAMPLE_CASES_DIR",
    "MANAGED_DIRECTORIES",
    "ensure_directories",
    # Bluetooth commands
    "BLUETOOTH_COMMANDS",
    # Scan settings
    "DEFAULT_SCAN_TIMEOUT_SECONDS",
    "DEFAULT_BLE_SCAN_TIMEOUT_SECONDS",
    "DEFAULT_PACKET_CAPTURE_TIMEOUT_SECONDS",
    "MAX_RETRIES",
    # Report settings
    "PDF_REPORT_FILENAME_FORMAT",
    "JSON_REPORT_FILENAME_FORMAT",
    "CSV_REPORT_FILENAME_FORMAT",
    "REPORT_TIMESTAMP_FORMAT",
    # Logging
    "LOG_FILE",
    "LOG_LEVEL",
    "LOG_FORMAT",
    "LOG_DATE_FORMAT",
    # Evidence
    "SHA256_HASHING_ENABLED",
    "TIMELINE_GENERATION_ENABLED",
    "READ_ONLY_ACQUISITION_MODE",
    # CLI
    "CLI_BANNER_TITLE",
    "CLI_MENU_WIDTH",
    "CLIColors",
]
