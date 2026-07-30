"""
modules/hashing.py
===================

Forensic hashing and integrity verification module for
**BlueTrace Forensic Suite**.

This module contains the :class:`EvidenceHasher` class, whose sole
responsibility is to compute and verify SHA-256 hashes for evidence
artifacts already collected by the framework, and to produce structured
integrity records suitable for chain-of-custody verification.

This module never scans, connects to, or reads information from
Bluetooth devices, never reads local Linux Bluetooth artifacts, never
captures packets, never generates reports, and never writes or modifies
any file on disk. It only reads bytes that already exist on the
filesystem (or are passed in directly as text/JSON) in order to compute
hashes.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and BLE devices on Linux.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Final

from config import LOG_LEVEL, SHA256_HASHING_ENABLED
from modules.utils import calculate_file_sha256, current_datetime_iso

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Display label for the hashing algorithm used throughout this module,
#: reported in generated integrity records.
_HASH_ALGORITHM_LABEL: Final[str] = "SHA256"

#: Error code returned when hashing is disabled via
#: :data:`config.SHA256_HASHING_ENABLED`.
_HASHING_DISABLED: Final[str] = "hashing_disabled"

#: Error code returned when a target path does not exist.
_PATH_NOT_FOUND: Final[str] = "path_not_found"

#: Error code returned when a target path is neither a regular file nor
#: a directory.
_INVALID_PATH: Final[str] = "invalid_path"

#: Error code returned when directory traversal fails due to insufficient
#: permissions.
_PERMISSION_DENIED: Final[str] = "permission_denied"


class EvidenceHasher:
    """Compute and verify SHA-256 hashes for collected evidence artifacts.

    This class provides file, directory, text, and JSON hashing, along
    with structured integrity record generation for chain-of-custody
    purposes. It performs no Bluetooth communication, no report
    generation, and no filesystem writes; it only reads existing files
    (or in-memory values) to compute digests.
    """

    def __init__(self) -> None:
        """Initialize the hasher's logger and operational configuration."""
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
        self._hashing_enabled = SHA256_HASHING_ENABLED

        if not self._hashing_enabled:
            self._logger.warning(
                "SHA-256 hashing is disabled via configuration "
                "(SHA256_HASHING_ENABLED=False)."
            )

    # ----------------------------------------------------------------- #
    # Internal helpers
    # ----------------------------------------------------------------- #

    def _collect_file_hashes(
        self, directory: Path
    ) -> tuple[list[dict[str, str]], str | None]:
        """Hash every regular file found under a directory tree.

        Args:
            directory: The directory to walk. Traversal is recursive.

        Returns:
            A tuple of ``(file_hashes, error_code)``. ``file_hashes`` is a
            list of dictionaries with keys ``"file"`` (path relative to
            ``directory``) and ``"sha256"``. ``error_code`` is ``None`` on
            success, or one of :data:`_PATH_NOT_FOUND` or
            :data:`_PERMISSION_DENIED` on failure. Files that cannot be
            individually hashed are skipped and logged rather than
            aborting the whole traversal.
        """
        file_hashes: list[dict[str, str]] = []

        try:
            if not directory.is_dir():
                return file_hashes, _PATH_NOT_FOUND
            file_paths = sorted(
                path for path in directory.rglob("*") if path.is_file()
            )
        except PermissionError:
            self._logger.error(
                "Permission denied while traversing %s.", directory
            )
            return file_hashes, _PERMISSION_DENIED
        except OSError as exc:
            self._logger.warning("Could not traverse %s: %s", directory, exc)
            return file_hashes, f"read_failed: {exc}"

        for file_path in file_paths:
            file_hash = self.calculate_file_hash(file_path)
            if file_hash is None:
                self._logger.warning("Skipping unreadable file: %s", file_path)
                continue
            file_hashes.append(
                {
                    "file": str(file_path.relative_to(directory)),
                    "sha256": file_hash,
                }
            )

        return file_hashes, None

    # ----------------------------------------------------------------- #
    # Public hashing methods
    # ----------------------------------------------------------------- #

    def calculate_file_hash(self, file_path: Path) -> str | None:
        """Calculate the SHA-256 hash of a single file.

        Delegates the actual digest computation to
        :func:`modules.utils.calculate_file_sha256`.

        Args:
            file_path: Path to the file to hash.

        Returns:
            The lowercase hexadecimal SHA-256 digest, or ``None`` if
            hashing is disabled, the path does not exist, is not a
            regular file, or cannot be read (permission denied, I/O
            error, etc.).
        """
        if not self._hashing_enabled:
            return None

        try:
            if not file_path.is_file():
                self._logger.warning(
                    "Path does not exist or is not a regular file: %s",
                    file_path,
                )
                return None
        except OSError as exc:
            self._logger.warning("Could not stat %s: %s", file_path, exc)
            return None

        file_hash = calculate_file_sha256(file_path)
        if file_hash is None:
            self._logger.warning("Could not read file for hashing: %s", file_path)
        return file_hash

    def calculate_directory_hash(self, directory: Path) -> dict[str, Any]:
        """Calculate SHA-256 hashes for every file inside a directory.

        Args:
            directory: The directory whose files should be hashed.
                Traversal is recursive.

        Returns:
            A dictionary with keys ``"directory"`` (str), ``"files"``
            (a list of ``{"file": ..., "sha256": ...}`` dictionaries),
            and ``"error"`` (str or ``None``). Never raises; missing
            directories, permission errors, and unreadable files are all
            reported as structured errors or skipped entries rather than
            exceptions.
        """
        result: dict[str, Any] = {
            "directory": str(directory),
            "files": [],
            "error": None,
        }

        if not self._hashing_enabled:
            result["error"] = _HASHING_DISABLED
            return result

        file_hashes, error = self._collect_file_hashes(directory)
        result["files"] = file_hashes
        result["error"] = error
        return result

    def verify_hash(self, file_path: Path, expected_hash: str) -> bool:
        """Verify that a file's SHA-256 hash matches an expected value.

        Args:
            file_path: Path to the file to verify.
            expected_hash: The expected hexadecimal SHA-256 digest.

        Returns:
            ``True`` if the file's computed hash matches ``expected_hash``
            (case-insensitively), ``False`` otherwise, including when
            hashing is disabled, the file cannot be read, or
            ``expected_hash`` is empty or not a string.
        """
        if not self._hashing_enabled:
            return False

        if not isinstance(expected_hash, str) or not expected_hash.strip():
            self._logger.warning("No expected hash provided for verification.")
            return False

        computed_hash = self.calculate_file_hash(file_path)
        if computed_hash is None:
            return False

        return computed_hash.lower() == expected_hash.strip().lower()

    def generate_integrity_record(self, target: Path) -> dict[str, Any]:
        """Generate a structured integrity record for a file or directory.

        Args:
            target: The file or directory to build an integrity record
                for.

        Returns:
            A dictionary with keys ``"algorithm"`` (always
            :data:`_HASH_ALGORITHM_LABEL`), ``"timestamp"`` (ISO 8601,
            from :func:`modules.utils.current_datetime_iso`), ``"files"``
            (a list of ``{"file": ..., "sha256": ...}`` dictionaries),
            and ``"error"`` (str or ``None``), e.g.::

                {
                    "algorithm": "SHA256",
                    "timestamp": "2026-07-30T14:25:30.123456+00:00",
                    "files": [
                        {"file": "capture.pcap", "sha256": "..."}
                    ],
                    "error": None,
                }

            Never raises; every failure mode is captured in the
            ``"error"`` field.
        """
        record: dict[str, Any] = {
            "algorithm": _HASH_ALGORITHM_LABEL,
            "timestamp": current_datetime_iso(),
            "files": [],
            "error": None,
        }

        if not self._hashing_enabled:
            record["error"] = _HASHING_DISABLED
            return record

        try:
            target_exists = target.exists()
            target_is_file = target.is_file()
            target_is_dir = target.is_dir()
        except OSError as exc:
            self._logger.warning("Could not stat %s: %s", target, exc)
            record["error"] = f"stat_failed: {exc}"
            return record

        if not target_exists:
            self._logger.warning("Target path not found: %s", target)
            record["error"] = _PATH_NOT_FOUND
            return record

        if target_is_file:
            file_hash = self.calculate_file_hash(target)
            if file_hash is None:
                record["error"] = "unreadable_file"
            else:
                record["files"] = [{"file": target.name, "sha256": file_hash}]
            return record

        if target_is_dir:
            file_hashes, error = self._collect_file_hashes(target)
            record["files"] = file_hashes
            record["error"] = error
            return record

        record["error"] = _INVALID_PATH
        return record

    def hash_text(self, text: str) -> str | None:
        """Calculate the SHA-256 hash of a text string.

        Args:
            text: The text to hash.

        Returns:
            The lowercase hexadecimal SHA-256 digest of ``text`` encoded
            as UTF-8, or ``None`` if hashing is disabled or ``text`` is
            not a string.
        """
        if not self._hashing_enabled:
            return None

        if not isinstance(text, str):
            self._logger.warning("Cannot hash non-string text value.")
            return None

        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def hash_json(self, data: Any) -> str | None:
        """Calculate the SHA-256 hash of a JSON-serializable object.

        The object is serialized deterministically (sorted keys, compact
        separators) before hashing, so that logically identical data
        always produces the same digest regardless of key ordering.

        Args:
            data: The JSON-serializable object to hash.

        Returns:
            The lowercase hexadecimal SHA-256 digest of the serialized
            object, or ``None`` if hashing is disabled or ``data`` is not
            JSON-serializable.
        """
        if not self._hashing_enabled:
            return None

        try:
            serialized = json.dumps(
                data,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
                ensure_ascii=False,
            )
        except (TypeError, ValueError) as exc:
            self._logger.warning("Could not serialize data for hashing: %s", exc)
            return None

        return self.hash_text(serialized)


__all__: Final[list[str]] = ["EvidenceHasher"]
