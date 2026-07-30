"""
modules/utils.py
=================

Reusable helper utilities for **BlueTrace Forensic Suite**.

This module contains ONLY generic, side-effect-documented helper
functions that are shared across the framework: identifier generation,
date/time formatting, filesystem helpers, JSON I/O, hashing, MAC/UUID
validation, human-readable formatting, and basic system/environment
introspection.

It intentionally contains **no Bluetooth logic**, **no subprocess
execution**, **no report generation**, and **no forensic business
logic** (such as evidence-collection workflows or chain-of-custody
policy). Those responsibilities belong to dedicated modules elsewhere
in the framework. Functions here are pure helpers that other modules
compose to implement that logic.

All functions are defensive: they validate their inputs, catch and
handle expected exceptions, and return clearly documented sentinel
values (``None``, ``False``, empty containers, etc.) instead of
raising or crashing on invalid input, so that callers can rely on
predictable behavior throughout the suite.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from config import EVIDENCE_DIR, REPORT_TIMESTAMP_FORMAT

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Prefix used for all generated forensic case identifiers.
CASE_ID_PREFIX: Final[str] = "BTFS"

#: Date format used within case identifiers (e.g. "20260730").
CASE_ID_DATE_FORMAT: Final[str] = "%Y%m%d"

#: Number of zero-padded digits used for the per-day case sequence number.
CASE_ID_SEQUENCE_WIDTH: Final[int] = 4

#: Regular expression used to validate IEEE 802 MAC addresses in either
#: colon- or hyphen-delimited form (e.g. "AA:BB:CC:DD:EE:FF").
_MAC_ADDRESS_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
)

#: Characters considered unsafe within filenames across common filesystems
#: (Windows, macOS, Linux), replaced during filename sanitization.
_UNSAFE_FILENAME_CHARS: Final[re.Pattern[str]] = re.compile(r'[<>:"/\\|?*\x00-\x1F]')

#: Binary unit labels used by :func:`bytes_to_human`.
_BINARY_UNIT_LABELS: Final[tuple[str, ...]] = (
    "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"
)


# --------------------------------------------------------------------------- #
# Identifier generation
# --------------------------------------------------------------------------- #

def generate_case_id(base_directory: Path = EVIDENCE_DIR) -> str:
    """Generate a unique, human-readable forensic case identifier.

    The identifier has the form ``BTFS-YYYYMMDD-NNNN``, where ``YYYYMMDD``
    is today's date (UTC) and ``NNNN`` is a zero-padded sequence number
    that increments based on the number of existing case directories
    already created for the current date under ``base_directory``.

    Example:
        ``BTFS-20260730-0001``

    Args:
        base_directory: The directory under which existing case
            directories are counted to determine the next sequence
            number. Defaults to the framework's configured evidence
            directory.

    Returns:
        A newly generated, non-persisted case identifier string. If the
        sequence count cannot be determined (e.g. the directory is
        unreadable), sequence number ``0001`` is used.
    """
    date_component = datetime.now(timezone.utc).strftime(CASE_ID_DATE_FORMAT)
    prefix = f"{CASE_ID_PREFIX}-{date_component}-"

    existing_count = 0
    try:
        if base_directory.is_dir():
            existing_count = sum(
                1
                for entry in base_directory.iterdir()
                if entry.is_dir() and entry.name.startswith(prefix)
            )
    except OSError:
        existing_count = 0

    sequence_number = existing_count + 1
    return f"{prefix}{sequence_number:0{CASE_ID_SEQUENCE_WIDTH}d}"


def generate_random_identifier(length: int = 12) -> str:
    """Generate a random, URL-safe hexadecimal identifier.

    Args:
        length: The desired number of hexadecimal characters in the
            returned identifier. Must be a positive integer; values less
            than 1 are treated as 1.

    Returns:
        A lowercase hexadecimal string of the requested length, derived
        from a randomly generated UUID4.
    """
    safe_length = max(1, length)
    random_hex = uuid.uuid4().hex
    while len(random_hex) < safe_length:
        random_hex += uuid.uuid4().hex
    return random_hex[:safe_length]


# --------------------------------------------------------------------------- #
# Date and time helpers
# --------------------------------------------------------------------------- #

def current_timestamp() -> str:
    """Return the current UTC timestamp formatted for use in filenames.

    Returns:
        A timestamp string formatted according to
        :data:`config.REPORT_TIMESTAMP_FORMAT` (e.g. "20260730_142530").
    """
    return datetime.now(timezone.utc).strftime(REPORT_TIMESTAMP_FORMAT)


def current_datetime_iso() -> str:
    """Return the current UTC date and time in ISO 8601 format.

    Returns:
        An ISO 8601-formatted string including a UTC offset, e.g.
        ``"2026-07-30T14:25:30.123456+00:00"``.
    """
    return datetime.now(timezone.utc).isoformat()


def format_datetime(
    value: datetime, fmt: str = "%Y-%m-%d %H:%M:%S"
) -> str:
    """Format a :class:`datetime.datetime` object using a given pattern.

    Args:
        value: The datetime object to format.
        fmt: A ``strftime``-compatible format string. Defaults to
            ``"%Y-%m-%d %H:%M:%S"``.

    Returns:
        The formatted datetime string, or an empty string if ``value``
        is not a valid :class:`datetime.datetime` instance or formatting
        fails.
    """
    if not isinstance(value, datetime):
        return ""
    try:
        return value.strftime(fmt)
    except (ValueError, TypeError):
        return ""


# --------------------------------------------------------------------------- #
# Filesystem helpers
# --------------------------------------------------------------------------- #

def ensure_directory(path: Path) -> bool:
    """Ensure that a directory exists, creating it (and parents) if needed.

    Args:
        path: The directory path to create if it does not already exist.

    Returns:
        ``True`` if the directory exists (or was successfully created)
        after this call, ``False`` if creation failed due to an
        operating system error (e.g. permissions).
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path.is_dir()
    except OSError:
        return False


def create_case_directory(
    case_id: str, base_directory: Path = EVIDENCE_DIR
) -> Path | None:
    """Create a dedicated evidence directory for a specific forensic case.

    Args:
        case_id: The forensic case identifier (typically produced by
            :func:`generate_case_id`) used as the directory name.
        base_directory: The parent directory under which the case
            directory will be created. Defaults to the framework's
            configured evidence directory.

    Returns:
        The path to the created (or already existing) case directory,
        or ``None`` if the directory could not be created or if
        ``case_id`` is empty after sanitization.
    """
    sanitized_case_id = sanitize_filename(case_id)
    if not sanitized_case_id:
        return None

    case_directory = base_directory / sanitized_case_id
    if ensure_directory(case_directory):
        return case_directory
    return None


def sanitize_filename(filename: str) -> str:
    """Sanitize a string so it can be safely used as a filename or directory name.

    Removes characters that are unsafe on common filesystems (Windows,
    macOS, Linux), strips leading/trailing whitespace and periods, and
    collapses the result to a reasonable maximum length.

    Args:
        filename: The candidate filename or directory name to sanitize.

    Returns:
        A sanitized version of ``filename`` safe for filesystem use, or
        an empty string if ``filename`` is empty, not a string, or
        contains no valid characters after sanitization.
    """
    if not isinstance(filename, str) or not filename.strip():
        return ""

    sanitized = _UNSAFE_FILENAME_CHARS.sub("_", filename.strip())
    sanitized = sanitized.strip(". ")
    max_length = 255
    return sanitized[:max_length]


def safe_write_text(path: Path, content: str, encoding: str = "utf-8") -> bool:
    """Write text content to a file, creating parent directories as needed.

    Args:
        path: The destination file path.
        content: The text content to write.
        encoding: The text encoding to use. Defaults to ``"utf-8"``.

    Returns:
        ``True`` if the write succeeded, ``False`` if an OS-level error
        occurred (e.g. permissions, invalid path, disk full).
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding=encoding)
        return True
    except (OSError, UnicodeEncodeError):
        return False


def safe_read_text(path: Path, encoding: str = "utf-8") -> str | None:
    """Read text content from a file.

    Args:
        path: The source file path.
        encoding: The text encoding to use. Defaults to ``"utf-8"``.

    Returns:
        The file's text content, or ``None`` if the file does not exist,
        cannot be read, or cannot be decoded using ``encoding``.
    """
    try:
        return path.read_text(encoding=encoding)
    except (OSError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------------- #
# JSON helpers
# --------------------------------------------------------------------------- #

def safe_json_dump(data: Any, path: Path, indent: int = 4) -> bool:
    """Serialize a Python object to JSON and write it to a file.

    Args:
        data: The Python object to serialize. Must be JSON-serializable.
        path: The destination file path.
        indent: The number of spaces used for JSON indentation. Defaults
            to ``4``.

    Returns:
        ``True`` if serialization and writing both succeeded, ``False``
        if the data could not be serialized or the file could not be
        written.
    """
    try:
        serialized = json.dumps(data, indent=indent, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return False

    return safe_write_text(path, serialized)


def safe_json_load(path: Path) -> Any | None:
    """Read and deserialize JSON content from a file.

    Args:
        path: The source file path.

    Returns:
        The deserialized Python object, or ``None`` if the file does not
        exist, cannot be read, or does not contain valid JSON.
    """
    raw_content = safe_read_text(path)
    if raw_content is None:
        return None

    try:
        return json.loads(raw_content)
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------- #
# Hashing helpers
# --------------------------------------------------------------------------- #

def calculate_file_sha256(path: Path, chunk_size: int = 65536) -> str | None:
    """Calculate the SHA-256 hash of a file's contents.

    The file is read incrementally in fixed-size chunks so that large
    evidence files (e.g. packet captures) can be hashed without loading
    the entire file into memory.

    Args:
        path: The path to the file to hash.
        chunk_size: The number of bytes to read per chunk. Defaults to
            65536 (64 KiB).

    Returns:
        The lowercase hexadecimal SHA-256 digest of the file's contents,
        or ``None`` if the file does not exist or cannot be read.
    """
    sha256_hash = hashlib.sha256()
    try:
        with path.open("rb") as file_handle:
            while True:
                chunk = file_handle.read(chunk_size)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# Bluetooth-related value validation and formatting
#
# NOTE: These functions perform pure string validation/formatting only.
# They do not perform any Bluetooth communication, scanning, or device
# interaction of any kind.
# --------------------------------------------------------------------------- #

def is_valid_mac_address(value: str) -> bool:
    """Check whether a string is a validly formatted IEEE 802 MAC address.

    Accepts colon-delimited (``AA:BB:CC:DD:EE:FF``) or hyphen-delimited
    (``AA-BB-CC-DD-EE-FF``) forms, case-insensitively.

    Args:
        value: The string to validate.

    Returns:
        ``True`` if ``value`` is a validly formatted MAC address,
        ``False`` otherwise (including for non-string input).
    """
    if not isinstance(value, str):
        return False
    return bool(_MAC_ADDRESS_PATTERN.match(value.strip()))


def normalize_mac_address(value: str) -> str | None:
    """Normalize a MAC address string to uppercase, colon-delimited form.

    Args:
        value: The MAC address string to normalize (colon- or
            hyphen-delimited).

    Returns:
        The normalized MAC address (e.g. ``"AA:BB:CC:DD:EE:FF"``), or
        ``None`` if ``value`` is not a validly formatted MAC address.
    """
    if not is_valid_mac_address(value):
        return None
    return value.strip().upper().replace("-", ":")


def is_valid_uuid(value: str) -> bool:
    """Check whether a string is a validly formatted UUID.

    Commonly used to validate Bluetooth GATT service and characteristic
    UUIDs, which are standard 128-bit UUIDs.

    Args:
        value: The string to validate.

    Returns:
        ``True`` if ``value`` can be parsed as a valid UUID, ``False``
        otherwise (including for non-string input).
    """
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value.strip())
        return True
    except (ValueError, AttributeError):
        return False


def format_rssi(rssi: int | float) -> str:
    """Format a Received Signal Strength Indicator (RSSI) value for display.

    Args:
        rssi: The RSSI value in dBm.

    Returns:
        A human-readable string such as ``"-67 dBm"``, or ``"N/A"`` if
        ``rssi`` is not a numeric value.
    """
    if not isinstance(rssi, (int, float)) or isinstance(rssi, bool):
        return "N/A"
    return f"{int(rssi)} dBm"


def bytes_to_human(size_in_bytes: int) -> str:
    """Convert a byte count into a human-readable binary-unit string.

    Args:
        size_in_bytes: The size in bytes. Negative values are treated
            as invalid.

    Returns:
        A human-readable string such as ``"1.50 MiB"``, or ``"0 B"`` if
        ``size_in_bytes`` is not a non-negative integer.
    """
    if not isinstance(size_in_bytes, int) or isinstance(size_in_bytes, bool) or size_in_bytes < 0:
        return "0 B"

    size = float(size_in_bytes)
    for unit in _BINARY_UNIT_LABELS:
        if size < 1024.0 or unit == _BINARY_UNIT_LABELS[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{int(size_in_bytes)} B"


# --------------------------------------------------------------------------- #
# System and environment helpers
# --------------------------------------------------------------------------- #

def command_exists(command: str) -> bool:
    """Check whether an executable command is available on the system PATH.

    This function only performs a PATH lookup; it does not execute the
    command in any way.

    Args:
        command: The name of the command to look up (e.g.
            ``"bluetoothctl"``).

    Returns:
        ``True`` if an executable matching ``command`` is found on the
        system PATH, ``False`` otherwise (including for empty or
        non-string input).
    """
    if not isinstance(command, str) or not command.strip():
        return False
    return shutil.which(command.strip()) is not None


def get_linux_hostname() -> str:
    """Return the current system's hostname.

    Returns:
        The system hostname, or ``"unknown-host"`` if it cannot be
        determined.
    """
    try:
        hostname = platform.node()
        return hostname if hostname else "unknown-host"
    except OSError:
        return "unknown-host"


def get_current_username() -> str:
    """Return the username of the currently logged-in operating system user.

    Returns:
        The current username, or ``"unknown-user"`` if it cannot be
        determined.
    """
    try:
        return getpass.getuser()
    except (OSError, KeyError):
        return os.environ.get("USER", "unknown-user")


def get_platform_information() -> dict[str, str]:
    """Gather general, non-sensitive information about the host platform.

    Returns:
        A dictionary containing the following string keys:
        ``"system"``, ``"node"``, ``"release"``, ``"version"``,
        ``"machine"``, and ``"python_version"``. Any field that cannot
        be determined is set to ``"unknown"``.
    """
    fields = ("system", "node", "release", "version", "machine")
    info: dict[str, str] = {}

    for field in fields:
        try:
            value = getattr(platform, field)()
            info[field] = value if value else "unknown"
        except OSError:
            info[field] = "unknown"

    try:
        info["python_version"] = platform.python_version()
    except OSError:
        info["python_version"] = "unknown"

    return info


__all__: Final[list[str]] = [
    "generate_case_id",
    "generate_random_identifier",
    "current_timestamp",
    "current_datetime_iso",
    "format_datetime",
    "ensure_directory",
    "create_case_directory",
    "sanitize_filename",
    "safe_write_text",
    "safe_read_text",
    "safe_json_dump",
    "safe_json_load",
    "calculate_file_sha256",
    "is_valid_mac_address",
    "normalize_mac_address",
    "is_valid_uuid",
    "format_rssi",
    "bytes_to_human",
    "command_exists",
    "get_linux_hostname",
    "get_current_username",
    "get_platform_information",
]
