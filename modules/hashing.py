"""
modules/hashing.py
===================

Forensic hashing and integrity verification module for
**BlueTrace Forensic Suite**.

This module contains the :class:`EvidenceHasher` class, whose sole
responsibility is to compute and verify SHA-256 hashes for evidence
artifacts already collected by the framework, and to produce structured
integrity records -- including evidence manifests -- suitable for
chain-of-custody verification.

This module never scans, connects to, or reads information from
Bluetooth devices, never reads local Linux Bluetooth artifacts, never
captures packets, never generates reports, and never writes or modifies
any file on disk. It only reads bytes that already exist on the
filesystem (or are passed in directly as text/JSON/structured records)
in order to compute digests.

WHAT A HASH DOES AND DOES NOT PROVE
------------------------------------
A SHA-256 digest is an *integrity* mechanism only. A matching hash means
the hashed bytes are identical to the bytes that produced the stored
digest -- nothing more. A hash recorded here is **not** evidence of:

* device ownership
* identity of any person
* physical location
* the existence or nature of a historical Bluetooth connection
* guilt or wrongdoing
* the authenticity, accuracy, or truthfulness of the underlying evidence

Establishing those things is a matter for the wider investigation and
corroborating evidence. This module answers a narrower question: *has
this data changed since it was first hashed?*

RAW VS DERIVED EVIDENCE
------------------------
Callers should mark each hashed item with a category:

* ``raw``      -- data captured directly from a source (e.g. a btsnoop
  capture, a journalctl/btmon dump, a BlueZ artifact file).
* ``derived``  -- data produced by BlueTrace's own analysis (e.g.
  connection history, timeline, device profiles).
* ``metadata`` -- descriptive information about evidence (not evidence
  content itself).
* ``report``   -- a generated report or summary document.

Recording an item as ``derived`` is not a claim that it is itself an
original forensic source; it documents that BlueTrace produced it from
other evidence.

DETERMINISTIC STRUCTURED-DATA HASHING
--------------------------------------
Structured data (dictionaries, JSON, connection-history records,
timeline records, analyzer results, evidence manifests) is hashed after
serializing it with sorted keys and compact, deterministic separators,
so that logically identical data always produces the same digest
regardless of key insertion order. List ordering is preserved as-is
because, for forensic timelines and similar sequences, order is
semantically meaningful and must not be silently reshuffled.

READ-ONLY BEHAVIOR
-------------------
Files are always opened read-only (``"rb"``) and read in fixed-size
chunks so that large evidence files (packet captures, logs) can be
hashed without loading them entirely into memory. This module never
writes to, truncates, or otherwise modifies any file it hashes.

LIMITATIONS
------------
* Filesystem modification/creation timestamps are contextual metadata
  only; they are not treated as, and must not be presented as, proof of
  when evidence was acquired.
* Verifying a manifest entry that has no associated file path (e.g. a
  purely in-memory structured record hashed via
  :meth:`EvidenceHasher.hash_structured_evidence`) requires the caller
  to re-supply the original data; this module cannot "re-hash" data it
  no longer has access to, and reports such entries as not verifiable
  rather than silently passing or failing them.
* This module never fabricates hashes, timestamps, evidence IDs, or
  verification outcomes. Any failure is reported as a structured error
  or an explicit non-``PASS`` status, never as a false success.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and BLE devices on Linux.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Iterable

from config import LOG_LEVEL, SHA256_HASHING_ENABLED
from modules.utils import calculate_file_sha256, current_datetime_iso

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Display label for the hashing algorithm used throughout this module,
#: reported in generated integrity records. SHA-256 is the sole
#: supported algorithm and remains the framework default; it is never
#: silently changed.
_HASH_ALGORITHM_LABEL: Final[str] = "SHA256"

#: Default chunk size, in bytes, used for streaming file reads (64 KiB).
#: Chosen to balance I/O efficiency and memory usage for evidence files
#: that may range from small logs to multi-gigabyte packet captures.
DEFAULT_CHUNK_SIZE: Final[int] = 65536

#: Expected character length of a lowercase hexadecimal SHA-256 digest.
_SHA256_HEX_LENGTH: Final[int] = 64

# --- Error codes (used by existing, preserved APIs) ----------------------- #

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

# --- Evidence categories ---------------------------------------------------#

#: Data captured directly from a source (e.g. a btsnoop capture, a
#: journalctl/btmon dump, a raw BlueZ artifact file).
CATEGORY_RAW: Final[str] = "raw"

#: Data produced by BlueTrace's own analysis (e.g. connection history,
#: timeline, device forensic profiles).
CATEGORY_DERIVED: Final[str] = "derived"

#: Descriptive information about evidence, not evidence content itself.
CATEGORY_METADATA: Final[str] = "metadata"

#: A generated report or summary document.
CATEGORY_REPORT: Final[str] = "report"

#: All recognized evidence categories.
EVIDENCE_CATEGORIES: Final[tuple[str, ...]] = (
    CATEGORY_RAW,
    CATEGORY_DERIVED,
    CATEGORY_METADATA,
    CATEGORY_REPORT,
)

# --- Structured verification statuses -------------------------------------#

#: The computed digest matches the expected digest.
STATUS_PASS: Final[str] = "PASS"

#: The computed digest does not match the expected digest.
STATUS_FAIL: Final[str] = "FAIL"

#: The target file/path could not be found at verification time.
STATUS_MISSING: Final[str] = "MISSING"

#: The target file exists but could not be read (permissions, I/O error).
STATUS_UNREADABLE: Final[str] = "UNREADABLE"

#: The "expected" hash supplied for comparison was empty, malformed, or
#: not a plausible SHA-256 hex digest.
STATUS_INVALID_EXPECTED_HASH: Final[str] = "INVALID_EXPECTED_HASH"

#: Hashing/verification could not be completed due to an unexpected but
#: non-fatal error (e.g. serialization failure). Never used to mean
#: success.
STATUS_ERROR: Final[str] = "ERROR"

#: Hashing is disabled via configuration; no integrity claim is made.
STATUS_DISABLED: Final[str] = "DISABLED"

#: The manifest entry has no re-hashable source (e.g. a structured
#: record hashed in-memory with no backing file) and therefore cannot
#: be independently re-verified from disk alone.
STATUS_NOT_VERIFIABLE: Final[str] = "NOT_VERIFIABLE"


class EvidenceHasher:
    """Compute and verify SHA-256 hashes for collected evidence artifacts.

    This class provides file, directory, text, JSON, and structured
    forensic-record hashing, along with evidence-manifest creation and
    verification for chain-of-custody purposes. It performs no
    Bluetooth communication, no report generation, and no filesystem
    writes; it only reads existing files (or in-memory values) to
    compute digests.

    A hash produced or verified by this class establishes only that the
    hashed bytes match (or do not match) an expected digest. It is not,
    by itself, proof of the origin, authenticity, or truthfulness of the
    underlying evidence -- see the module docstring for details.
    """

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        """Initialize the hasher's logger and operational configuration.

        Args:
            chunk_size: Number of bytes read per chunk when streaming
                file contents for hashing. Defaults to
                :data:`DEFAULT_CHUNK_SIZE` (64 KiB). Large evidence
                files are never read fully into memory.
        """
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
        self._hashing_enabled = SHA256_HASHING_ENABLED
        self._chunk_size = chunk_size if chunk_size and chunk_size > 0 else DEFAULT_CHUNK_SIZE

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

    @staticmethod
    def _deterministic_json(data: Any) -> str:
        """Serialize ``data`` deterministically for hashing.

        Uses sorted keys and compact separators so that dictionaries
        with different key insertion order -- but otherwise identical
        content -- always produce the same serialized string, and
        therefore the same digest. List/sequence ordering is preserved
        exactly as given, since forensic timelines and similar ordered
        records must not be silently reordered.

        Args:
            data: Any JSON-serializable value.

        Returns:
            A deterministic JSON string representation of ``data``.

        Raises:
            TypeError: If ``data`` contains values that cannot be
                serialized even with ``default=str`` coercion (this is
                effectively unreachable for well-formed input, but is
                allowed to propagate to the caller, which converts it
                into a structured error rather than letting it crash
                the application).
        """
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )

    @staticmethod
    def _make_evidence_id(*parts: str) -> str:
        """Generate a stable, deterministic evidence identifier.

        The identifier is derived from the evidence item's own identity
        (e.g. resolved path, category, source reference) rather than
        randomly generated, so that hashing the same evidence item again
        later -- for verification -- naturally arrives at the same
        identifier without needing to persist a separate ID mapping.

        Args:
            *parts: String components that uniquely identify the
                evidence item (e.g. category and path).

        Returns:
            A short, stable, hex-encoded identifier prefixed with
            ``"EVID-"``.
        """
        digest_input = "|".join(parts)
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
        return f"EVID-{digest[:16]}"

    @staticmethod
    def _make_manifest_id(evidence_ids: Iterable[str]) -> str:
        """Generate a stable, deterministic manifest identifier.

        Derived from the sorted set of evidence IDs the manifest
        contains, so that building a manifest from the same evidence
        items again produces the same manifest identifier.

        Args:
            evidence_ids: The evidence identifiers contained in the
                manifest.

        Returns:
            A short, stable, hex-encoded identifier prefixed with
            ``"MANIFEST-"``.
        """
        digest_input = "|".join(sorted(evidence_ids))
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
        return f"MANIFEST-{digest[:16]}"

    @staticmethod
    def _is_plausible_sha256(value: str) -> bool:
        """Check whether a string is plausibly a lowercase-able SHA-256 hex digest.

        This is a structural check only (length and hex-alphabet); it
        does not verify the digest against any content.

        Args:
            value: The candidate digest string.

        Returns:
            ``True`` if ``value`` is a 64-character hexadecimal string,
            ``False`` otherwise.
        """
        if not isinstance(value, str):
            return False
        candidate = value.strip()
        if len(candidate) != _SHA256_HEX_LENGTH:
            return False
        try:
            int(candidate, 16)
        except ValueError:
            return False
        return True

    def _file_metadata(self, file_path: Path) -> dict[str, Any]:
        """Gather non-authoritative filesystem metadata for a file.

        Args:
            file_path: The file to stat.

        Returns:
            A dictionary with ``"size_bytes"`` and ``"modified_time"``
            (ISO 8601, derived from the filesystem's modification time),
            or empty values if the file cannot be stat'd. This metadata
            describes the file on disk; it is NOT evidence of when the
            underlying data was acquired by BlueTrace.
        """
        try:
            stat_result = file_path.stat()
        except OSError as exc:
            self._logger.warning("Could not stat %s: %s", file_path, exc)
            return {"size_bytes": None, "modified_time": None}

        try:
            modified_time = datetime.fromtimestamp(
                stat_result.st_mtime, tz=timezone.utc
            ).isoformat()
        except (OSError, OverflowError, ValueError):
            modified_time = None

        return {"size_bytes": stat_result.st_size, "modified_time": modified_time}

    # ----------------------------------------------------------------- #
    # Public hashing methods (existing, preserved API)
    # ----------------------------------------------------------------- #

    def calculate_file_hash(
        self, file_path: Path, chunk_size: int | None = None
    ) -> str | None:
        """Calculate the SHA-256 hash of a single file.

        Delegates the actual digest computation to
        :func:`modules.utils.calculate_file_sha256`, which streams the
        file in fixed-size chunks rather than loading it fully into
        memory.

        Args:
            file_path: Path to the file to hash.
            chunk_size: Optional override for the read chunk size, in
                bytes. Defaults to this hasher's configured chunk size
                (:data:`DEFAULT_CHUNK_SIZE` unless overridden at
                construction).

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

        file_hash = calculate_file_sha256(
            file_path, chunk_size=chunk_size or self._chunk_size
        )
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

        Note:
            This method preserves the original simple boolean contract
            for existing callers. For a structured result that
            distinguishes *why* verification did not pass (missing,
            unreadable, invalid expected hash, mismatch, etc.), use
            :meth:`verify_evidence_file`.
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
            serialized = self._deterministic_json(data)
        except (TypeError, ValueError) as exc:
            self._logger.warning("Could not serialize data for hashing: %s", exc)
            return None

        return self.hash_text(serialized)

    # ----------------------------------------------------------------- #
    # Public hashing methods (new evidence-integrity API)
    # ----------------------------------------------------------------- #

    def hash_evidence_file(
        self,
        file_path: Path,
        *,
        evidence_id: str | None = None,
        category: str = CATEGORY_RAW,
        source_type: str | None = None,
        source_reference: str | None = None,
    ) -> dict[str, Any]:
        """Build a structured evidence-manifest entry for a single file.

        This computes the file's SHA-256 digest (read-only, chunked) and
        wraps it together with identity, provenance, and non-authoritative
        filesystem metadata into a manifest-ready record.

        Args:
            file_path: Path to the evidence file.
            evidence_id: A stable identifier for this evidence item. If
                not supplied, a deterministic identifier is derived from
                the resolved path and category so that hashing the same
                file again yields the same ID.
            category: One of :data:`EVIDENCE_CATEGORIES` (``"raw"``,
                ``"derived"``, ``"metadata"``, ``"report"``). Defaults to
                ``"raw"``.
            source_type: Optional label describing the evidence source
                (e.g. ``"btsnoop_capture"``, ``"journalctl"``).
            source_reference: Optional label identifying the specific
                source instance (e.g. a command, device, or file the
                evidence originated from).

        Returns:
            A dictionary matching the evidence-manifest entry schema::

                {
                    "evidence_id": "EVID-...",
                    "path": "...",
                    "size_bytes": 1234,
                    "modified_time": "..." | None,
                    "sha256": "..." | None,
                    "hash_algorithm": "SHA256",
                    "hashed_at": "2026-08-14T00:35:10+00:00",
                    "category": "raw",
                    "source_type": "..." | None,
                    "source_reference": "..." | None,
                    "status": "PASS" | "MISSING" | "UNREADABLE" | "DISABLED",
                    "error": None | "...",
                }

            ``status`` here reflects whether the hash was successfully
            computed at acquisition time, not a comparison against an
            expected value. Never raises.
        """
        resolved_category = category if category in EVIDENCE_CATEGORIES else CATEGORY_RAW
        stable_id = evidence_id or self._make_evidence_id(
            resolved_category, str(file_path)
        )

        entry: dict[str, Any] = {
            "evidence_id": stable_id,
            "path": str(file_path),
            "size_bytes": None,
            "modified_time": None,
            "sha256": None,
            "hash_algorithm": _HASH_ALGORITHM_LABEL,
            "hashed_at": current_datetime_iso(),
            "category": resolved_category,
            "source_type": source_type,
            "source_reference": source_reference,
            "status": STATUS_ERROR,
            "error": None,
        }

        if not self._hashing_enabled:
            entry["status"] = STATUS_DISABLED
            entry["error"] = _HASHING_DISABLED
            return entry

        try:
            exists = file_path.is_file()
        except OSError as exc:
            entry["status"] = STATUS_UNREADABLE
            entry["error"] = f"stat_failed: {exc}"
            return entry

        if not exists:
            entry["status"] = STATUS_MISSING
            entry["error"] = _PATH_NOT_FOUND
            return entry

        metadata = self._file_metadata(file_path)
        entry["size_bytes"] = metadata["size_bytes"]
        entry["modified_time"] = metadata["modified_time"]

        file_hash = self.calculate_file_hash(file_path)
        if file_hash is None:
            entry["status"] = STATUS_UNREADABLE
            entry["error"] = "unreadable_file"
            return entry

        entry["sha256"] = file_hash
        entry["status"] = STATUS_PASS
        return entry

    def hash_structured_evidence(
        self,
        data: Any,
        *,
        evidence_id: str | None = None,
        label: str | None = None,
        category: str = CATEGORY_DERIVED,
        source_type: str | None = None,
        source_reference: str | None = None,
    ) -> dict[str, Any]:
        """Build a structured evidence-manifest entry for in-memory data.

        Intended for hashing already-produced structured records such as
        connection-history results, timeline entries, analyzer output,
        or evidence-bundle metadata. The data is serialized
        deterministically (sorted keys, stable separators) so equivalent
        dictionaries with different key insertion order hash identically.

        This method does not modify, reorder, or reinterpret ``data`` in
        any way beyond serialization for hashing.

        Args:
            data: The JSON-serializable structured record to hash (e.g.
                output of ``ConnectionHistoryAnalyzer`` or
                ``ForensicTimeline``).
            evidence_id: A stable identifier for this evidence item. If
                not supplied, a deterministic identifier is derived from
                ``label`` (if given) and the category.
            label: A short, human-meaningful label for this record (e.g.
                ``"connection_history"``, ``"timeline"``), used for
                identification and, when ``evidence_id`` is not given,
                for deterministic ID generation.
            category: One of :data:`EVIDENCE_CATEGORIES`. Defaults to
                ``"derived"``, since structured records are normally
                produced by BlueTrace's own analysis rather than
                captured directly from a device.
            source_type: Optional label describing the evidence source.
            source_reference: Optional label identifying the specific
                source instance.

        Returns:
            A dictionary matching the evidence-manifest entry schema
            (see :meth:`hash_evidence_file`), with ``"path"`` set to
            ``None`` and ``"label"`` set to the supplied label. Because
            there is no backing file, later independent re-verification
            of this entry requires the caller to supply the same data
            again (see :meth:`verify_evidence_manifest`). Never raises.
        """
        resolved_category = category if category in EVIDENCE_CATEGORIES else CATEGORY_DERIVED
        stable_id = evidence_id or self._make_evidence_id(
            resolved_category, label or "structured_evidence"
        )

        entry: dict[str, Any] = {
            "evidence_id": stable_id,
            "label": label,
            "path": None,
            "size_bytes": None,
            "modified_time": None,
            "sha256": None,
            "hash_algorithm": _HASH_ALGORITHM_LABEL,
            "hashed_at": current_datetime_iso(),
            "category": resolved_category,
            "source_type": source_type,
            "source_reference": source_reference,
            "status": STATUS_ERROR,
            "error": None,
        }

        if not self._hashing_enabled:
            entry["status"] = STATUS_DISABLED
            entry["error"] = _HASHING_DISABLED
            return entry

        digest = self.hash_json(data)
        if digest is None:
            entry["status"] = STATUS_ERROR
            entry["error"] = "serialization_failed"
            return entry

        entry["sha256"] = digest
        entry["status"] = STATUS_PASS
        return entry

    def hash_evidence_bundle(
        self,
        bundle: dict[str, Any],
        *,
        evidence_id: str | None = None,
        source_reference: str | None = None,
    ) -> dict[str, Any]:
        """Hash a complete structured evidence bundle deterministically.

        A bundle typically groups together several already-produced
        pieces of case data (e.g. a target device profile, connection
        history, timeline, Linux artifacts, and raw-evidence
        references). This computes both an overall bundle digest and a
        per-top-level-key digest, without reordering any list-valued
        content (forensic timelines and similar ordered sequences are
        hashed exactly as given).

        Args:
            bundle: A JSON-serializable mapping of component name to
                component data (e.g. ``{"connection_history": [...],
                "timeline": [...], "device_profile": {...}}``).
            evidence_id: A stable identifier for the bundle as a whole.
                If not supplied, one is derived deterministically from
                the sorted bundle keys.
            source_reference: Optional label identifying where the
                bundle came from (e.g. a case ID).

        Returns:
            A dictionary::

                {
                    "evidence_id": "EVID-...",
                    "hash_algorithm": "SHA256",
                    "hashed_at": "...",
                    "bundle_sha256": "..." | None,
                    "components": [
                        {"key": "connection_history", "sha256": "..."},
                        ...
                    ],
                    "source_reference": "..." | None,
                    "status": "PASS" | "ERROR" | "DISABLED",
                    "error": None | "...",
                }

            Never raises; malformed or non-serializable bundle content
            is reported via ``"status"`` and ``"error"`` rather than
            raising an exception.
        """
        stable_id = evidence_id or self._make_evidence_id(
            "bundle", ",".join(sorted(bundle.keys())) if isinstance(bundle, dict) else "bundle"
        )

        result: dict[str, Any] = {
            "evidence_id": stable_id,
            "hash_algorithm": _HASH_ALGORITHM_LABEL,
            "hashed_at": current_datetime_iso(),
            "bundle_sha256": None,
            "components": [],
            "source_reference": source_reference,
            "status": STATUS_ERROR,
            "error": None,
        }

        if not self._hashing_enabled:
            result["status"] = STATUS_DISABLED
            result["error"] = _HASHING_DISABLED
            return result

        if not isinstance(bundle, dict):
            result["error"] = "bundle_must_be_a_mapping"
            return result

        bundle_digest = self.hash_json(bundle)
        if bundle_digest is None:
            result["error"] = "serialization_failed"
            return result

        result["bundle_sha256"] = bundle_digest

        components: list[dict[str, Any]] = []
        for key in sorted(bundle.keys()):
            component_digest = self.hash_json(bundle[key])
            components.append({"key": key, "sha256": component_digest})
            if component_digest is None:
                self._logger.warning(
                    "Could not hash bundle component %r for evidence_id %s.",
                    key, stable_id,
                )

        result["components"] = components
        result["status"] = STATUS_PASS
        return result

    def create_evidence_manifest(
        self,
        items: Iterable[dict[str, Any]],
        *,
        manifest_id: str | None = None,
    ) -> dict[str, Any]:
        """Assemble a structured evidence manifest from manifest entries.

        Entries are typically produced by :meth:`hash_evidence_file`,
        :meth:`hash_structured_evidence`, or equivalent structures
        supplied by the caller.

        The manifest's own digest (``"manifest_sha256"``) is computed
        over a deterministic serialization of the entry list only; the
        manifest hash is never included in the data used to compute
        itself, avoiding circular hashing.

        Args:
            items: An iterable of evidence-manifest entry dictionaries.
            manifest_id: A stable identifier for the manifest. If not
                supplied, one is derived deterministically from the
                sorted evidence IDs of ``items``.

        Returns:
            A dictionary::

                {
                    "manifest_id": "MANIFEST-...",
                    "algorithm": "SHA256",
                    "created_at": "...",
                    "evidence_count": 3,
                    "items": [ ... ],
                    "manifest_sha256": "..." | None,
                    "status": "PASS" | "ERROR" | "DISABLED",
                    "error": None | "...",
                }

            Never raises.
        """
        item_list = list(items)

        manifest: dict[str, Any] = {
            "manifest_id": None,
            "algorithm": _HASH_ALGORITHM_LABEL,
            "created_at": current_datetime_iso(),
            "evidence_count": len(item_list),
            "items": item_list,
            "manifest_sha256": None,
            "status": STATUS_ERROR,
            "error": None,
        }

        if not self._hashing_enabled:
            manifest["status"] = STATUS_DISABLED
            manifest["error"] = _HASHING_DISABLED
            manifest["manifest_id"] = manifest_id or "MANIFEST-DISABLED"
            return manifest

        evidence_ids = [
            str(item.get("evidence_id", "")) for item in item_list if isinstance(item, dict)
        ]
        manifest["manifest_id"] = manifest_id or self._make_manifest_id(evidence_ids)

        manifest_digest = self.hash_json(item_list)
        if manifest_digest is None:
            manifest["error"] = "serialization_failed"
            return manifest

        manifest["manifest_sha256"] = manifest_digest
        manifest["status"] = STATUS_PASS
        return manifest

    def verify_evidence_file(
        self,
        file_path: Path,
        expected_hash: str,
        *,
        evidence_id: str | None = None,
    ) -> dict[str, Any]:
        """Verify a single evidence file against an expected SHA-256 digest.

        This is the structured counterpart to :meth:`verify_hash`: it
        reports *why* verification did or did not pass, rather than a
        bare boolean.

        Args:
            file_path: Path to the file to verify.
            expected_hash: The expected hexadecimal SHA-256 digest,
                typically taken from a previously created evidence
                manifest entry.
            evidence_id: Optional identifier to include in the result
                for traceability back to a manifest entry.

        Returns:
            A dictionary::

                {
                    "evidence_id": "..." | None,
                    "verified": True | False,
                    "status": "PASS" | "FAIL" | "MISSING" | "UNREADABLE"
                               | "INVALID_EXPECTED_HASH" | "DISABLED",
                    "expected_sha256": "..." | None,
                    "actual_sha256": "..." | None,
                    "path": "...",
                    "verified_at": "...",
                }

            ``verified`` is ``True`` only when ``status`` is ``"PASS"``.
            Never raises, and never reports ``verified: True`` unless a
            digest was actually computed and matched.
        """
        result: dict[str, Any] = {
            "evidence_id": evidence_id,
            "verified": False,
            "status": STATUS_ERROR,
            "expected_sha256": expected_hash if isinstance(expected_hash, str) else None,
            "actual_sha256": None,
            "path": str(file_path),
            "verified_at": current_datetime_iso(),
        }

        if not self._hashing_enabled:
            result["status"] = STATUS_DISABLED
            return result

        if not self._is_plausible_sha256(str(expected_hash) if expected_hash is not None else ""):
            result["status"] = STATUS_INVALID_EXPECTED_HASH
            return result

        try:
            exists = file_path.is_file()
        except OSError:
            result["status"] = STATUS_UNREADABLE
            return result

        if not exists:
            result["status"] = STATUS_MISSING
            return result

        actual_hash = self.calculate_file_hash(file_path)
        if actual_hash is None:
            result["status"] = STATUS_UNREADABLE
            return result

        result["actual_sha256"] = actual_hash
        expected_normalized = expected_hash.strip().lower()
        if actual_hash.lower() == expected_normalized:
            result["verified"] = True
            result["status"] = STATUS_PASS
        else:
            result["status"] = STATUS_FAIL

        return result

    def verify_evidence_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Re-hash manifest items from disk and compare against stored digests.

        For each manifest entry that has a ``"path"`` (i.e. was produced
        by :meth:`hash_evidence_file` or has an equivalent shape), the
        file is re-hashed and compared against the entry's stored
        ``"sha256"``. Entries with no ``"path"`` (e.g. produced by
        :meth:`hash_structured_evidence`) cannot be independently
        re-verified from disk alone and are reported as
        :data:`STATUS_NOT_VERIFIABLE` rather than silently passed or
        failed -- verifying those requires the caller to re-supply the
        original data and compare digests directly.

        Args:
            manifest: A manifest dictionary as produced by
                :meth:`create_evidence_manifest`, or any dictionary with
                an ``"items"`` list of manifest-entry-shaped
                dictionaries.

        Returns:
            A dictionary::

                {
                    "manifest_id": "...",
                    "verified_at": "...",
                    "evidence_count": 3,
                    "verified_count": 2,
                    "failed_count": 0,
                    "not_verifiable_count": 1,
                    "results": [ {..per-item verify_evidence_file-style..}, ... ],
                    "integrity_status": "PASS" | "FAIL" | "INCOMPLETE" | "DISABLED",
                }

            ``integrity_status`` is ``"PASS"`` only if every verifiable
            item passed and at least one item was actually verifiable;
            ``"FAIL"`` if any verifiable item did not pass;
            ``"INCOMPLETE"`` if there were no verifiable items at all
            (e.g. an all-structured-data manifest); ``"DISABLED"`` if
            hashing is turned off. Never raises.
        """
        outcome: dict[str, Any] = {
            "manifest_id": manifest.get("manifest_id") if isinstance(manifest, dict) else None,
            "verified_at": current_datetime_iso(),
            "evidence_count": 0,
            "verified_count": 0,
            "failed_count": 0,
            "not_verifiable_count": 0,
            "results": [],
            "integrity_status": STATUS_ERROR,
        }

        if not self._hashing_enabled:
            outcome["integrity_status"] = STATUS_DISABLED
            return outcome

        items = manifest.get("items") if isinstance(manifest, dict) else None
        if not isinstance(items, list):
            outcome["integrity_status"] = STATUS_ERROR
            return outcome

        outcome["evidence_count"] = len(items)
        results: list[dict[str, Any]] = []
        verifiable_count = 0
        verified_count = 0
        failed_count = 0
        not_verifiable_count = 0

        for item in items:
            if not isinstance(item, dict):
                not_verifiable_count += 1
                results.append(
                    {
                        "evidence_id": None,
                        "verified": False,
                        "status": STATUS_NOT_VERIFIABLE,
                        "expected_sha256": None,
                        "actual_sha256": None,
                        "path": None,
                        "verified_at": current_datetime_iso(),
                    }
                )
                continue

            path_value = item.get("path")
            evidence_id = item.get("evidence_id")
            expected_hash = item.get("sha256")

            if not path_value:
                not_verifiable_count += 1
                results.append(
                    {
                        "evidence_id": evidence_id,
                        "verified": False,
                        "status": STATUS_NOT_VERIFIABLE,
                        "expected_sha256": expected_hash,
                        "actual_sha256": None,
                        "path": None,
                        "verified_at": current_datetime_iso(),
                    }
                )
                continue

            verifiable_count += 1
            item_result = self.verify_evidence_file(
                Path(path_value), str(expected_hash or ""), evidence_id=evidence_id
            )
            results.append(item_result)
            if item_result["status"] == STATUS_PASS:
                verified_count += 1
            else:
                failed_count += 1

        outcome["results"] = results
        outcome["verified_count"] = verified_count
        outcome["failed_count"] = failed_count
        outcome["not_verifiable_count"] = not_verifiable_count

        if verifiable_count == 0:
            outcome["integrity_status"] = "INCOMPLETE"
        elif failed_count == 0:
            outcome["integrity_status"] = STATUS_PASS
        else:
            outcome["integrity_status"] = STATUS_FAIL

        return outcome

    def verify_integrity_record(
        self, record: dict[str, Any], base_directory: Path
    ) -> dict[str, Any]:
        """Re-verify a legacy-style integrity record against files on disk.

        Compatible with records produced by
        :meth:`generate_integrity_record`, whose ``"files"`` entries
        store paths relative to a base directory rather than absolute
        paths.

        Args:
            record: An integrity record with a ``"files"`` list of
                ``{"file": relative_path, "sha256": expected_digest}``
                dictionaries.
            base_directory: The directory the relative ``"file"`` values
                should be resolved against (normally the same directory
                originally passed to :meth:`generate_integrity_record`).

        Returns:
            A dictionary::

                {
                    "verified_at": "...",
                    "file_count": 2,
                    "verified_count": 2,
                    "failed_count": 0,
                    "results": [ {..per-file verify_evidence_file-style..}, ... ],
                    "integrity_status": "PASS" | "FAIL" | "INCOMPLETE" | "DISABLED",
                }

            Never raises.
        """
        outcome: dict[str, Any] = {
            "verified_at": current_datetime_iso(),
            "file_count": 0,
            "verified_count": 0,
            "failed_count": 0,
            "results": [],
            "integrity_status": STATUS_ERROR,
        }

        if not self._hashing_enabled:
            outcome["integrity_status"] = STATUS_DISABLED
            return outcome

        files = record.get("files") if isinstance(record, dict) else None
        if not isinstance(files, list):
            outcome["integrity_status"] = STATUS_ERROR
            return outcome

        outcome["file_count"] = len(files)
        results: list[dict[str, Any]] = []
        verified_count = 0
        failed_count = 0

        for file_entry in files:
            if not isinstance(file_entry, dict):
                continue
            relative_path = file_entry.get("file")
            expected_hash = file_entry.get("sha256")
            if not relative_path:
                continue

            full_path = base_directory / relative_path
            item_result = self.verify_evidence_file(
                full_path, str(expected_hash or "")
            )
            results.append(item_result)
            if item_result["status"] == STATUS_PASS:
                verified_count += 1
            else:
                failed_count += 1

        outcome["results"] = results
        outcome["verified_count"] = verified_count
        outcome["failed_count"] = failed_count

        if not results:
            outcome["integrity_status"] = "INCOMPLETE"
        elif failed_count == 0:
            outcome["integrity_status"] = STATUS_PASS
        else:
            outcome["integrity_status"] = STATUS_FAIL

        return outcome


__all__: Final[list[str]] = [
    "EvidenceHasher",
    "DEFAULT_CHUNK_SIZE",
    "CATEGORY_RAW",
    "CATEGORY_DERIVED",
    "CATEGORY_METADATA",
    "CATEGORY_REPORT",
    "EVIDENCE_CATEGORIES",
    "STATUS_PASS",
    "STATUS_FAIL",
    "STATUS_MISSING",
    "STATUS_UNREADABLE",
    "STATUS_INVALID_EXPECTED_HASH",
    "STATUS_ERROR",
    "STATUS_DISABLED",
    "STATUS_NOT_VERIFIABLE",
]
