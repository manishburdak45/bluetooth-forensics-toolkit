"""
modules/linux_artifacts.py
===========================

Local Linux Bluetooth artifact collection module for
**BlueTrace Forensic Suite**.

This module contains the :class:`LinuxArtifactsCollector` class, whose
sole responsibility is to collect Bluetooth-related forensic artifacts
that already exist on the local Linux host: host/system information, the
local Bluetooth controller's configuration, the paired/trusted/blocked/
known device records persisted by the Linux Bluetooth stack (BlueZ)
under ``/var/lib/bluetooth``, and locally available Bluetooth-related
log evidence (via ``journalctl``) that may contain historical
connection/disconnection events.

This module never communicates with remote Bluetooth devices. It only
reads local system state: environment metadata, local controller status
via ``bluetoothctl``/``hciconfig``, on-disk BlueZ configuration files, and
the local systemd journal. No device is contacted, connected to, paired
with, or modified, and no local logs, configuration, or evidence are
ever altered or deleted.

Connection-history evidence
----------------------------
This module is an **evidence acquisition layer only**. It collects and
preserves raw local evidence -- it does not itself decide whether a
device was historically connected, nor does it fabricate or infer
connection events from static BlueZ state (a device being "paired" or
"trusted" is not evidence of a connection). Historical connection
reconstruction and interpretation is the responsibility of
:class:`modules.connection_history.ConnectionHistoryAnalyzer`, which
consumes evidence bundles produced by
:meth:`LinuxArtifactsCollector.build_connection_history_evidence`.

Forensic limitations
---------------------
* ``journalctl`` output is only as complete as the local system's journal
  retention policy (``SystemMaxUse``/``SystemMaxFileSize``/journal
  rotation, or a wholly volatile in-memory journal); older Bluetooth
  events may simply no longer exist on disk.
* The Bluetooth systemd unit name varies across distributions; this
  module tries a small set of common candidate unit names and falls
  back to a filtered, time-bounded journal search rather than dumping
  the entire system journal.
* Absence of journal evidence does not prove a device was never
  connected -- only that no supporting log evidence was found on this
  host within the collected window.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and BLE devices on Linux.
"""

from __future__ import annotations

import logging
import platform
import subprocess
from pathlib import Path
from typing import Any, Final

from config import BLUETOOTH_COMMANDS, LOG_LEVEL
from modules.utils import (
    command_exists,
    current_datetime_iso,
    get_current_username,
    get_linux_hostname,
    get_platform_information,
)

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Value returned for fields whose value could not be determined.
_UNKNOWN_VALUE: Final[str] = "Unknown"

#: Directory in which BlueZ persists per-controller and per-device state
#: (link keys, trust/blocked flags, cached names, etc.) on most Linux
#: distributions.
_BLUETOOTH_STATE_DIR: Final[Path] = Path("/var/lib/bluetooth")

#: Name of the per-device configuration file stored by BlueZ under each
#: ``<controller_mac>/<device_mac>/`` directory.
_DEVICE_INFO_FILENAME: Final[str] = "info"

#: Error codes returned alongside ``None`` output by
#: :meth:`LinuxArtifactsCollector._run_command`.
_TOOL_MISSING: Final[str] = "tool_missing"
_PERMISSION_DENIED: Final[str] = "permission_denied"
_TIMEOUT: Final[str] = "timeout"

#: Error/status code used when a command succeeded but produced no
#: usable output (e.g. no matching journal entries in the collected
#: window).
_NO_DATA: Final[str] = "no_data"

#: Candidate systemd unit names for the Bluetooth daemon, tried in
#: order. Unit naming for BlueZ's ``bluetoothd`` varies across Linux
#: distributions, so several common names are attempted before falling
#: back to a filtered, time-bounded journal search.
_JOURNALCTL_UNIT_CANDIDATES: Final[tuple[str, ...]] = ("bluetooth", "bluetoothd")

#: Default lookback window passed to ``journalctl --since`` when the
#: caller does not specify one. Chosen to be a reasonable, targeted
#: collection window rather than dumping the entire available journal.
_DEFAULT_JOURNAL_LOOKBACK: Final[str] = "7 days ago"

#: Case-insensitive extended-regex pattern used with ``journalctl -g``
#: (``--grep``) as a fallback when none of :data:`_JOURNALCTL_UNIT_CANDIDATES`
#: yield a matching systemd unit, so collection still stays targeted to
#: Bluetooth-related messages rather than the whole journal.
_BLUETOOTH_GREP_PATTERN: Final[str] = "[Bb]luetooth"

#: Output format passed to ``journalctl -o``. ``short-iso`` produces
#: ISO-8601-style timestamp prefixes (e.g. ``"2026-08-13T22:41:18+0000"``)
#: that :class:`modules.connection_history.ConnectionHistoryAnalyzer` can
#: parse directly without additional interpretation.
_JOURNALCTL_OUTPUT_FORMAT: Final[str] = "short-iso"

#: Source-type label used for all journalctl-derived evidence records.
#: Kept as a local string constant (rather than importing it from
#: :mod:`modules.connection_history`) so this module has no import-time
#: dependency on the analyzer module; the two are composed only through
#: the plain-dict evidence structure returned by
#: :meth:`LinuxArtifactsCollector.build_connection_history_evidence`.
_SOURCE_TYPE_JOURNALCTL: Final[str] = "journalctl"


class LinuxArtifactsCollector:
    """Collect Bluetooth forensic artifacts stored on the local Linux system.

    This class reads local host/environment information, queries the
    local Bluetooth controller's status via ``bluetoothctl`` and
    ``hciconfig``, parses the BlueZ device records persisted under
    ``/var/lib/bluetooth``, and collects locally available Bluetooth-
    related log evidence via ``journalctl``. It performs no
    communication with remote Bluetooth devices, makes no changes to the
    local Bluetooth configuration, and never pairs, connects, or
    modifies/deletes any local evidence.

    This class does not interpret whether a device was historically
    connected -- it only acquires and preserves raw evidence. Use
    :meth:`build_connection_history_evidence` to package that evidence
    into the shape expected by
    :class:`modules.connection_history.ConnectionHistoryAnalyzer`, which
    performs the actual historical reconstruction.
    """

    def __init__(self) -> None:
        """Initialize the collector's logger and operational configuration."""
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # ----------------------------------------------------------------- #
    # Internal helpers
    # ----------------------------------------------------------------- #

    def _run_command(
        self, command_args: list[str], timeout: int = 10
    ) -> tuple[str | None, str | None]:
        """Run a local command-line tool and return its output.

        Centralizes subprocess invocation and error handling shared by
        the collection methods that rely on external Bluetooth tooling.

        Args:
            command_args: The command and its arguments, e.g.
                ``["bluetoothctl", "show"]``.
            timeout: Maximum time, in seconds, to wait for the command.

        Returns:
            A tuple of ``(output, error_code)``. On success, ``output``
            is the command's standard output and ``error_code`` is
            ``None``. On failure, ``output`` is ``None`` and
            ``error_code`` is one of :data:`_TOOL_MISSING`,
            :data:`_PERMISSION_DENIED`, or :data:`_TIMEOUT`.
        """
        if not command_args or not command_exists(command_args[0]):
            self._logger.warning("Required tool not found: %s", command_args[0])
            return None, _TOOL_MISSING

        try:
            completed = subprocess.run(
                command_args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            self._logger.warning("Required tool not found: %s", command_args[0])
            return None, _TOOL_MISSING
        except PermissionError:
            self._logger.error(
                "Permission denied while running: %s", " ".join(command_args)
            )
            return None, _PERMISSION_DENIED
        except subprocess.TimeoutExpired:
            self._logger.error(
                "Timed out while running: %s", " ".join(command_args)
            )
            return None, _TIMEOUT

        return completed.stdout or "", None

    def _get_linux_distribution(self) -> str:
        """Determine the local Linux distribution's display name.

        Attempts :func:`platform.freedesktop_os_release` first, falling
        back to manually reading ``/etc/os-release`` if that API is
        unavailable or fails.

        Returns:
            The distribution's ``PRETTY_NAME`` (e.g.
            ``"Ubuntu 24.04.1 LTS"``), or :data:`_UNKNOWN_VALUE` if it
            cannot be determined.
        """
        try:
            os_release = platform.freedesktop_os_release()
            pretty_name = os_release.get("PRETTY_NAME")
            if pretty_name:
                return pretty_name
        except (OSError, AttributeError):
            pass

        try:
            os_release_path = Path("/etc/os-release")
            content = os_release_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass

        return _UNKNOWN_VALUE

    @staticmethod
    def _parse_device_lines(output: str) -> list[dict[str, str]]:
        """Parse ``bluetoothctl devices``-style output into structured records.

        Args:
            output: Raw standard output containing lines of the form
                ``"Device <MAC> <Name>"``.

        Returns:
            A list of dictionaries with keys ``"mac"`` and ``"name"``.
        """
        devices: list[dict[str, str]] = []
        for line in output.splitlines():
            stripped_line = line.strip()
            if not stripped_line.startswith("Device "):
                continue
            parts = stripped_line.split(" ", 2)
            if len(parts) < 2:
                continue
            mac = parts[1]
            name = parts[2].strip() if len(parts) == 3 else _UNKNOWN_VALUE
            devices.append({"mac": mac, "name": name or _UNKNOWN_VALUE})
        return devices

    def _read_device_info_file(
        self, info_path: Path, controller_mac: str, device_mac: str
    ) -> dict[str, Any] | None:
        """Parse a single BlueZ per-device ``info`` file.

        Args:
            info_path: Path to the device's ``info`` file.
            controller_mac: The MAC address of the owning controller
                (the parent directory name).
            device_mac: The MAC address of the device (the directory name).

        Returns:
            A dictionary describing the device, or ``None`` if the file
            could not be read.
        """
        try:
            content = info_path.read_text(encoding="utf-8")
        except OSError as exc:
            self._logger.warning("Could not read %s: %s", info_path, exc)
            return None

        current_section = ""
        fields: dict[str, str] = {}
        sections: set[str] = set()

        for line in content.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("[") and stripped_line.endswith("]"):
                current_section = stripped_line.strip("[]")
                sections.add(current_section)
                continue
            if current_section == "General" and "=" in stripped_line:
                key, _, value = stripped_line.partition("=")
                fields[key.strip()] = value.strip()

        name = fields.get("Name") or fields.get("Alias") or _UNKNOWN_VALUE
        trusted = fields.get("Trusted", "").lower() == "true"
        blocked = fields.get("Blocked", "").lower() == "true"

        if "Paired" in fields:
            paired = fields.get("Paired", "").lower() == "true"
        else:
            paired = "LinkKey" in sections or "LongTermKey" in sections

        return {
            "mac": device_mac,
            "controller_mac": controller_mac,
            "name": name,
            "class": fields.get("Class", _UNKNOWN_VALUE),
            "trusted": trusted,
            "blocked": blocked,
            "paired": paired,
        }

    def _read_known_devices_from_disk(self) -> list[dict[str, Any]]:
        """Read all cached device records from the BlueZ state directory.

        Walks ``/var/lib/bluetooth/<controller_mac>/<device_mac>/info``
        for every controller and device directory present, parsing each
        into a structured record.

        Returns:
            A list of device dictionaries as produced by
            :meth:`_read_device_info_file`. Returns an empty list if the
            state directory is missing or cannot be read.
        """
        devices: list[dict[str, Any]] = []

        try:
            if not _BLUETOOTH_STATE_DIR.is_dir():
                return devices
            controller_dirs = list(_BLUETOOTH_STATE_DIR.iterdir())
        except PermissionError:
            self._logger.error(
                "Permission denied while accessing %s.", _BLUETOOTH_STATE_DIR
            )
            return devices
        except OSError as exc:
            self._logger.warning(
                "Could not list %s: %s", _BLUETOOTH_STATE_DIR, exc
            )
            return devices

        for controller_dir in controller_dirs:
            if not controller_dir.is_dir():
                continue
            controller_mac = controller_dir.name

            try:
                device_dirs = list(controller_dir.iterdir())
            except PermissionError:
                self._logger.warning(
                    "Permission denied while accessing %s.", controller_dir
                )
                continue
            except OSError as exc:
                self._logger.warning(
                    "Could not list %s: %s", controller_dir, exc
                )
                continue

            for device_dir in device_dirs:
                if not device_dir.is_dir():
                    continue
                info_path = device_dir / _DEVICE_INFO_FILENAME
                if not info_path.is_file():
                    continue

                record = self._read_device_info_file(
                    info_path, controller_mac, device_dir.name
                )
                if record is not None:
                    devices.append(record)

        return devices

    # ----------------------------------------------------------------- #
    # Collection methods
    # ----------------------------------------------------------------- #

    def get_host_information(self) -> dict[str, str]:
        """Collect general information about the local host system.

        Returns:
            A dictionary with keys ``"hostname"``, ``"username"``,
            ``"distribution"``, ``"kernel_version"``, and
            ``"python_version"``. Any field that cannot be determined is
            set to :data:`_UNKNOWN_VALUE`.
        """
        platform_info = get_platform_information()

        return {
            "hostname": get_linux_hostname(),
            "username": get_current_username(),
            "distribution": self._get_linux_distribution(),
            "kernel_version": platform_info.get("release", _UNKNOWN_VALUE),
            "python_version": platform_info.get("python_version", _UNKNOWN_VALUE),
        }

    def get_bluetooth_controller(self) -> dict[str, Any]:
        """Collect the local Bluetooth controller's basic status.

        Invokes ``bluetoothctl show`` to gather the controller's MAC
        address, name, and Powered/Discoverable/Pairable state.

        Returns:
            A dictionary with keys ``"mac"``, ``"name"``, ``"powered"``,
            ``"discoverable"``, ``"pairable"``, and ``"error"``. Boolean
            fields are ``None`` if their state could not be determined,
            and ``"error"`` is ``None`` on success.
        """
        command_name = BLUETOOTH_COMMANDS.get("bluetoothctl", "bluetoothctl")
        result: dict[str, Any] = {
            "mac": None,
            "name": None,
            "powered": None,
            "discoverable": None,
            "pairable": None,
            "error": None,
        }

        output, error = self._run_command([command_name, "show"])
        if error:
            result["error"] = error
            return result

        if "No default controller available" in output or not output.strip():
            result["error"] = "no_adapter"
            self._logger.warning("No Bluetooth adapter detected.")
            return result

        for line in output.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("Controller "):
                parts = stripped_line.split(" ")
                if len(parts) >= 2:
                    result["mac"] = parts[1]
            elif stripped_line.startswith("Name:"):
                result["name"] = stripped_line.split(":", 1)[1].strip()
            elif stripped_line.startswith("Powered:"):
                result["powered"] = stripped_line.split(":", 1)[1].strip().lower() == "yes"
            elif stripped_line.startswith("Discoverable:"):
                result["discoverable"] = (
                    stripped_line.split(":", 1)[1].strip().lower() == "yes"
                )
            elif stripped_line.startswith("Pairable:"):
                result["pairable"] = stripped_line.split(":", 1)[1].strip().lower() == "yes"

        return result

    def get_adapter_information(self) -> dict[str, Any]:
        """Collect low-level adapter details using ``hciconfig``.

        Returns:
            A dictionary with keys ``"raw"`` (the tool's raw output, or
            ``None``) and ``"error"`` (an error code, or ``None`` on
            success). The raw output is preserved rather than
            over-parsed, since ``hciconfig`` output varies across BlueZ
            versions and adapter vendors.
        """
        command_name = BLUETOOTH_COMMANDS.get("hciconfig", "hciconfig")
        output, error = self._run_command([command_name, "-a"], timeout=10)

        if error:
            return {"raw": None, "error": error}

        if not output.strip():
            self._logger.warning("No Bluetooth adapter detected.")
            return {"raw": None, "error": "no_adapter"}

        return {"raw": output.strip(), "error": None}

    def get_bluetooth_directory(self) -> dict[str, Any]:
        """Check the status and accessibility of the BlueZ state directory.

        Returns:
            A dictionary with keys ``"path"`` (str), ``"exists"`` (bool),
            ``"accessible"`` (bool), and ``"error"`` (str or ``None``).
        """
        result: dict[str, Any] = {
            "path": str(_BLUETOOTH_STATE_DIR),
            "exists": False,
            "accessible": False,
            "error": None,
        }

        try:
            result["exists"] = _BLUETOOTH_STATE_DIR.is_dir()
        except OSError as exc:
            result["error"] = f"stat_failed: {exc}"
            return result

        if not result["exists"]:
            result["error"] = "directory_missing"
            return result

        try:
            next(_BLUETOOTH_STATE_DIR.iterdir(), None)
            result["accessible"] = True
        except PermissionError:
            result["error"] = _PERMISSION_DENIED
            self._logger.warning(
                "Permission denied while accessing %s.", _BLUETOOTH_STATE_DIR
            )
        except OSError as exc:
            result["error"] = f"read_failed: {exc}"

        return result

    def get_paired_devices(self) -> list[dict[str, Any]]:
        """Return devices marked as paired in the local BlueZ state.

        Returns:
            A list of device dictionaries (see
            :meth:`_read_device_info_file`) for which ``"paired"`` is
            ``True``. Returns an empty list if no paired devices are
            found or the state directory is inaccessible.
        """
        return [
            device
            for device in self._read_known_devices_from_disk()
            if device.get("paired")
        ]

    def get_trusted_devices(self) -> list[dict[str, Any]]:
        """Return devices marked as trusted in the local BlueZ state.

        Returns:
            A list of device dictionaries (see
            :meth:`_read_device_info_file`) for which ``"trusted"`` is
            ``True``. Returns an empty list if no trusted devices are
            found or the state directory is inaccessible.
        """
        return [
            device
            for device in self._read_known_devices_from_disk()
            if device.get("trusted")
        ]

    def get_blocked_devices(self) -> list[dict[str, Any]]:
        """Return devices marked as blocked in the local BlueZ state.

        Returns:
            A list of device dictionaries (see
            :meth:`_read_device_info_file`) for which ``"blocked"`` is
            ``True``. Returns an empty list if no blocked devices are
            found or the state directory is inaccessible.
        """
        return [
            device
            for device in self._read_known_devices_from_disk()
            if device.get("blocked")
        ]

    def get_known_devices(self) -> list[dict[str, Any]]:
        """Return all Bluetooth devices cached in the local BlueZ state.

        Returns:
            A list of every device record found under the BlueZ state
            directory, regardless of paired/trusted status. Returns an
            empty list if the state directory is missing or inaccessible.
        """
        return self._read_known_devices_from_disk()

    # ----------------------------------------------------------------- #
    # Bluetooth connection log evidence (journalctl)
    # ----------------------------------------------------------------- #

    @staticmethod
    def _build_log_evidence_record(
        source_type: str,
        source_reference: str,
        content: str | None,
        success: bool,
        error: str | None,
    ) -> dict[str, Any]:
        """Assemble a single, self-describing log evidence record.

        Preserves the raw collected text (when available) alongside
        provenance metadata, so that another forensic module can inspect
        or reproduce exactly what was collected without re-running the
        original acquisition command.

        Args:
            source_type: A short label identifying the kind of source
                (e.g. ``"journalctl"``).
            source_reference: The exact command (or other locator) that
                produced (or was attempted to produce) this evidence,
                preserved for provenance.
            content: The raw collected text, or ``None`` if collection
                did not succeed or produced no data.
            success: Whether this specific collection attempt succeeded.
            error: A short error code describing why collection failed,
                or ``None`` on success.

        Returns:
            A dictionary with keys ``"source_type"``, ``"source_reference"``,
            ``"collected_at"`` (UTC ISO-8601), ``"content"``, ``"success"``,
            ``"error"``, and ``"line_count"``.
        """
        return {
            "source_type": source_type,
            "source_reference": source_reference,
            "collected_at": current_datetime_iso(),
            "content": content,
            "success": success,
            "error": error,
            "line_count": len(content.splitlines()) if content else 0,
        }

    def _collect_journalctl_output(
        self, command_args: list[str], timeout: int
    ) -> tuple[str | None, str | None]:
        """Run a single ``journalctl`` invocation via the shared command runner.

        Thin, purpose-specific wrapper around :meth:`_run_command` kept
        separate so journal-log collection call sites stay small and
        individually testable.

        Args:
            command_args: The full ``journalctl`` command and arguments
                to execute (argument list, never a shell string).
            timeout: Maximum time, in seconds, to wait for the command.

        Returns:
            A tuple of ``(output, error_code)``, as returned by
            :meth:`_run_command`.
        """
        return self._run_command(command_args, timeout=timeout)

    def get_bluetooth_log_evidence(
        self,
        since: str = _DEFAULT_JOURNAL_LOOKBACK,
        unit_candidates: tuple[str, ...] = _JOURNALCTL_UNIT_CANDIDATES,
    ) -> list[dict[str, Any]]:
        """Collect locally available Bluetooth-related journal log evidence.

        Attempts a targeted, read-only ``journalctl`` query for each
        candidate Bluetooth systemd unit name in ``unit_candidates``
        (since unit naming for ``bluetoothd`` varies across
        distributions). If none of those unit-scoped queries yield any
        data, falls back to a single time-bounded, pattern-filtered
        journal search (``journalctl -g``) instead of retrieving the
        entire system journal, keeping collection targeted per the
        framework's evidence-handling policy.

        This method never classifies or interprets the collected text --
        it only acquires and preserves it. Classification into
        connected/disconnected/paired/etc. events is performed later by
        :class:`modules.connection_history.ConnectionHistoryAnalyzer`.

        Args:
            since: A ``journalctl --since``-compatible time expression
                bounding how far back to search (e.g. ``"7 days ago"``,
                ``"2026-08-01"``). Defaults to
                :data:`_DEFAULT_JOURNAL_LOOKBACK`.
            unit_candidates: Systemd unit names to try, in order.
                Defaults to :data:`_JOURNALCTL_UNIT_CANDIDATES`.

        Returns:
            A list of log evidence records (see
            :meth:`_build_log_evidence_record`), one per collection
            attempt actually made. Includes both successful and failed
            attempts so that the absence of evidence is itself
            documented rather than silently omitted. Returns a single
            failed record if ``journalctl`` is not available on this
            system. Never raises.
        """
        command_name = BLUETOOTH_COMMANDS.get("journalctl", "journalctl")
        evidence_sources: list[dict[str, Any]] = []

        if not command_exists(command_name):
            self._logger.warning("Required tool not found: %s", command_name)
            evidence_sources.append(
                self._build_log_evidence_record(
                    source_type=_SOURCE_TYPE_JOURNALCTL,
                    source_reference=command_name,
                    content=None,
                    success=False,
                    error=_TOOL_MISSING,
                )
            )
            return evidence_sources

        found_unit_evidence = False
        for unit_name in unit_candidates:
            command_args = [
                command_name,
                "-u", unit_name,
                "--no-pager",
                "-o", _JOURNALCTL_OUTPUT_FORMAT,
                "--since", since,
            ]
            source_reference = " ".join(command_args)
            output, error = self._collect_journalctl_output(command_args, timeout=15)

            if error:
                self._logger.warning(
                    "journalctl collection failed for unit %s: %s", unit_name, error
                )
                evidence_sources.append(
                    self._build_log_evidence_record(
                        source_type=_SOURCE_TYPE_JOURNALCTL,
                        source_reference=source_reference,
                        content=None,
                        success=False,
                        error=error,
                    )
                )
                continue

            if not output.strip():
                evidence_sources.append(
                    self._build_log_evidence_record(
                        source_type=_SOURCE_TYPE_JOURNALCTL,
                        source_reference=source_reference,
                        content=None,
                        success=False,
                        error=_NO_DATA,
                    )
                )
                continue

            evidence_sources.append(
                self._build_log_evidence_record(
                    source_type=_SOURCE_TYPE_JOURNALCTL,
                    source_reference=source_reference,
                    content=output,
                    success=True,
                    error=None,
                )
            )
            found_unit_evidence = True

        if not found_unit_evidence:
            command_args = [
                command_name,
                "--no-pager",
                "-o", _JOURNALCTL_OUTPUT_FORMAT,
                "--since", since,
                "-g", _BLUETOOTH_GREP_PATTERN,
            ]
            source_reference = " ".join(command_args)
            output, error = self._collect_journalctl_output(command_args, timeout=20)

            if error:
                self._logger.warning(
                    "journalctl fallback grep collection failed: %s", error
                )
                evidence_sources.append(
                    self._build_log_evidence_record(
                        source_type=_SOURCE_TYPE_JOURNALCTL,
                        source_reference=source_reference,
                        content=None,
                        success=False,
                        error=error,
                    )
                )
            elif not output.strip():
                evidence_sources.append(
                    self._build_log_evidence_record(
                        source_type=_SOURCE_TYPE_JOURNALCTL,
                        source_reference=source_reference,
                        content=None,
                        success=False,
                        error=_NO_DATA,
                    )
                )
            else:
                evidence_sources.append(
                    self._build_log_evidence_record(
                        source_type=_SOURCE_TYPE_JOURNALCTL,
                        source_reference=source_reference,
                        content=output,
                        success=True,
                        error=None,
                    )
                )

        return evidence_sources

    def build_connection_history_evidence(
        self,
        known_devices: list[dict[str, Any]] | None = None,
        connection_log_evidence: list[dict[str, Any]] | None = None,
        assume_year: int | None = None,
    ) -> dict[str, Any]:
        """Assemble collected evidence into the shape expected by the analyzer.

        Packages this collector's output into the evidence structure
        consumed by
        :meth:`modules.connection_history.ConnectionHistoryAnalyzer.get_connection_history`
        (and ``get_full_connection_timeline``), so the two modules can be
        composed without either one needing to know the other's internal
        collection details. Only successful log evidence records with
        non-empty content are included as parseable log sources; failed
        or empty attempts are omitted here (they remain visible in the
        raw ``connection_log_evidence`` returned by
        :meth:`get_bluetooth_log_evidence` for audit purposes).

        Args:
            known_devices: Pre-collected BlueZ device records, as
                returned by :meth:`get_known_devices`. If ``None``,
                :meth:`get_known_devices` is called to collect them.
            connection_log_evidence: Pre-collected log evidence records,
                as returned by :meth:`get_bluetooth_log_evidence`. If
                ``None``, :meth:`get_bluetooth_log_evidence` is called
                with its default lookback window.
            assume_year: Optional year to combine with year-less
                syslog-style timestamps that may appear in some log
                sources. Left as ``None``, the analyzer will not
                fabricate a year for such lines and will instead
                preserve the raw timestamp text. Not needed for
                ``journalctl -o short-iso`` output, which already
                includes a year.

        Returns:
            A dictionary with keys ``"log_sources"``,
            ``"bluez_known_devices"``, and ``"structured_events"``,
            ready to pass directly as the ``evidence`` argument to
            :class:`modules.connection_history.ConnectionHistoryAnalyzer`.
        """
        resolved_known_devices = (
            known_devices if known_devices is not None else self.get_known_devices()
        )
        resolved_log_evidence = (
            connection_log_evidence
            if connection_log_evidence is not None
            else self.get_bluetooth_log_evidence()
        )

        log_sources: list[dict[str, Any]] = []
        for source in resolved_log_evidence:
            if not isinstance(source, dict):
                continue
            if not source.get("success"):
                continue
            content = source.get("content")
            if not content:
                continue
            log_sources.append(
                {
                    "content": content,
                    "source_type": source.get("source_type", _SOURCE_TYPE_JOURNALCTL),
                    "source_reference": source.get("source_reference", _UNKNOWN_VALUE),
                    "assume_year": assume_year,
                }
            )

        return {
            "log_sources": log_sources,
            "bluez_known_devices": resolved_known_devices,
            "structured_events": [],
        }

    # ----------------------------------------------------------------- #
    # Orchestration
    # ----------------------------------------------------------------- #

    def collect_all(self) -> dict[str, Any]:
        """Collect all local Bluetooth forensic artifacts into one structure.

        Never raises; every individual collection method already handles
        its own failure modes and returns safe defaults, and this method
        adds a final defensive safety net around the aggregation itself.

        Returns:
            A dictionary with keys ``"host_information"``,
            ``"bluetooth_controller"``, ``"adapter_information"``,
            ``"bluetooth_directory"``, ``"known_devices"``,
            ``"paired_devices"``, ``"trusted_devices"``,
            ``"blocked_devices"``, ``"connection_log_evidence"`` (raw
            journal evidence records, see
            :meth:`get_bluetooth_log_evidence`), and
            ``"connection_history_evidence"`` (the same evidence,
            pre-packaged via :meth:`build_connection_history_evidence`
            for direct use with
            :class:`modules.connection_history.ConnectionHistoryAnalyzer`).
        """
        try:
            known_devices = self.get_known_devices()
            connection_log_evidence = self.get_bluetooth_log_evidence()
            return {
                "host_information": self.get_host_information(),
                "bluetooth_controller": self.get_bluetooth_controller(),
                "adapter_information": self.get_adapter_information(),
                "bluetooth_directory": self.get_bluetooth_directory(),
                "known_devices": known_devices,
                "paired_devices": [
                    device for device in known_devices if device.get("paired")
                ],
                "trusted_devices": [
                    device for device in known_devices if device.get("trusted")
                ],
                "blocked_devices": [
                    device for device in known_devices if device.get("blocked")
                ],
                "connection_log_evidence": connection_log_evidence,
                "connection_history_evidence": self.build_connection_history_evidence(
                    known_devices=known_devices,
                    connection_log_evidence=connection_log_evidence,
                ),
            }
        except OSError as exc:
            self._logger.error("Unexpected error while collecting artifacts: %s", exc)
            return {
                "host_information": {},
                "bluetooth_controller": {},
                "adapter_information": {},
                "bluetooth_directory": {},
                "known_devices": [],
                "paired_devices": [],
                "trusted_devices": [],
                "blocked_devices": [],
                "connection_log_evidence": [],
                "connection_history_evidence": {
                    "log_sources": [],
                    "bluez_known_devices": [],
                    "structured_events": [],
                },
                "error": str(exc),
            }


__all__: Final[list[str]] = ["LinuxArtifactsCollector"]
