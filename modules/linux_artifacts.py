"""
modules/linux_artifacts.py
===========================

Local Linux Bluetooth artifact collection module for
**BlueTrace Forensic Suite**.

This module contains the :class:`LinuxArtifactsCollector` class, whose
sole responsibility is to acquire and PRESERVE Bluetooth-related
forensic evidence that already exists on the local Linux host: host/
system information, the local Bluetooth controller's configuration, the
paired/trusted/blocked/known device records persisted by the Linux
Bluetooth stack (BlueZ) under ``/var/lib/bluetooth`` (including each
device's raw ``info`` file text, not just parsed fields), and locally
available Bluetooth-related log evidence (via ``journalctl``, queried
both by systemd unit and by syslog identifier) that may contain
historical connection, disconnection, pairing, trust, authentication,
and connection-failure evidence.

This module never communicates with remote Bluetooth devices. It only
reads local system state: environment metadata, local controller status
via ``bluetoothctl``/``hciconfig``, on-disk BlueZ configuration files, and
the local systemd journal. No device is contacted, connected to, paired
with, or modified, and no local logs, configuration, or evidence are
ever altered or deleted.

Connection-history evidence
----------------------------
This module is an **evidence acquisition and preservation layer only**.
It collects and preserves raw local evidence -- it does not itself
decide whether a device was historically connected, nor does it
fabricate or infer connection events from static BlueZ state (a device
being "paired" or "trusted" is not evidence of a connection, and a
journal line such as ``"failed connect to <MAC>"`` is evidence of a
connection *attempt*, not a successful historical connection). Raw log
text is always preserved alongside any structured metadata; this module
never discards raw evidence after extracting fields from it, so that
:class:`modules.connection_history.ConnectionHistoryAnalyzer` -- which
consumes evidence bundles produced by
:meth:`LinuxArtifactsCollector.build_connection_history_evidence` -- can
independently interpret it.

Forensic limitations
---------------------
* ``journalctl`` output is only as complete as the local system's journal
  retention policy (``SystemMaxUse``/``SystemMaxFileSize``/journal
  rotation, or a wholly volatile in-memory journal); older Bluetooth
  events may simply no longer exist on disk.
* The Bluetooth systemd unit name varies across distributions, and
  ``bluetoothd``'s own log lines are not always attributable to a
  distinct systemd unit; this module queries by both unit name and
  syslog identifier, and falls back to a filtered, time-bounded journal
  search rather than dumping the entire system journal.
* Absence of journal or BlueZ evidence does not prove a device was
  never connected -- only that no supporting evidence was found on this
  host within the collected window, or that the relevant evidence could
  not be accessed (e.g. due to filesystem permissions, which is always
  reported explicitly rather than silently treated as "no evidence").
* BlueZ's per-device ``info`` file records current pairing/trust/
  blocked/link-key state; it does NOT record connection history, live
  RSSI, or a "Connected" flag, so none of those are fabricated from it.

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

#: Candidate syslog identifiers queried directly via ``journalctl -t``
#: (``SYSLOG_IDENTIFIER``), independent of which systemd unit launched
#: the process. Real-world Linux systems commonly tag ``bluetoothd``'s
#: own log lines (e.g. ``"bluetoothd: src/profile.c:ext_connect() ..."``)
#: with this identifier even when captured under a differently-named
#: unit, so this targeted, read-only query is attempted in addition to
#: the unit-based queries above rather than only as a last-resort
#: fallback.
_JOURNALCTL_IDENTIFIER_CANDIDATES: Final[tuple[str, ...]] = ("bluetoothd",)

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

    @staticmethod
    def _empty_device_record(
        controller_mac: str, device_mac: str, info_path: Path, error: str | None
    ) -> dict[str, Any]:
        """Build a placeholder device record for evidence that could not be read.

        Used both when a device directory has no ``info`` file at all
        and when an ``info`` file exists but could not be read/parsed.
        The device's presence in the BlueZ state directory (its MAC
        address, controller, and path) is itself evidence and is
        preserved even when the file content is unavailable, per the
        forensic requirement that inaccessible evidence must be reported
        explicitly rather than silently treated as "no devices".

        Args:
            controller_mac: The MAC address of the owning controller.
            device_mac: The MAC address of the device.
            info_path: The path where the device's ``info`` file would
                be located, whether or not it actually exists.
            error: A short error code explaining why no data is
                available (e.g. ``"info_file_missing"``,
                :data:`_PERMISSION_DENIED`), or ``None``.

        Returns:
            A device dictionary with the standard schema (see
            :meth:`_read_device_info_file`), all data fields at their
            "unavailable" defaults, and ``"info_available"`` set to
            ``False``.
        """
        return {
            "mac": device_mac,
            "controller_mac": controller_mac,
            "info_path": str(info_path),
            "info_available": False,
            "error": error,
            "name": _UNKNOWN_VALUE,
            "alias": None,
            "class": _UNKNOWN_VALUE,
            "address_type": None,
            "trusted": False,
            "blocked": False,
            "paired": False,
            "uuids": [],
            "raw_info": None,
        }

    def _read_device_info_file(
        self, info_path: Path, controller_mac: str, device_mac: str
    ) -> dict[str, Any]:
        """Parse a single BlueZ per-device ``info`` file, preserving its raw text.

        BlueZ's ``info`` file records *current* pairing/trust/blocked/
        link-key state, an optionally cached name/alias, device class,
        address type, and advertised service UUIDs. It does NOT record
        connection history or a live "Connected" flag, so neither is
        read from it or fabricated here.

        Args:
            info_path: Path to the device's ``info`` file.
            controller_mac: The MAC address of the owning controller
                (the parent directory name).
            device_mac: The MAC address of the device (the directory name).

        Returns:
            A dictionary with keys ``"mac"``, ``"controller_mac"``,
            ``"info_path"``, ``"info_available"`` (bool),
            ``"error"`` (str or ``None``), ``"name"``, ``"alias"``,
            ``"class"``, ``"address_type"``, ``"trusted"``, ``"blocked"``,
            ``"paired"``, ``"uuids"`` (list[str]), and ``"raw_info"``
            (the file's exact raw text, or ``None`` if it could not be
            read). Never raises; permission and I/O errors, and files
            that could be read but contain no recognizable BlueZ
            sections, are all reported via ``"error"`` rather than
            silently producing an empty-looking but "successful" record.
        """
        record = self._empty_device_record(controller_mac, device_mac, info_path, None)

        try:
            content = info_path.read_text(encoding="utf-8")
        except PermissionError:
            record["error"] = _PERMISSION_DENIED
            self._logger.warning(
                "Permission denied while reading %s.", info_path
            )
            return record
        except OSError as exc:
            record["error"] = f"read_failed: {exc}"
            self._logger.warning("Could not read %s: %s", info_path, exc)
            return record

        record["raw_info"] = content
        record["info_available"] = True

        current_section = ""
        fields: dict[str, str] = {}
        sections: set[str] = set()
        uuids: list[str] = []

        for line in content.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("[") and stripped_line.endswith("]"):
                current_section = stripped_line.strip("[]")
                sections.add(current_section)
                continue
            if current_section == "General" and "=" in stripped_line:
                key, _, value = stripped_line.partition("=")
                key = key.strip()
                value = value.strip()
                if key == "UUID":
                    # BlueZ info files may list multiple UUID= lines
                    # within [General]; a plain dict would silently
                    # drop all but the last one.
                    uuids.append(value)
                else:
                    fields[key] = value

        if not fields and not uuids and not sections:
            record["error"] = "malformed_info_file"
            self._logger.warning(
                "Info file %s contained no recognizable BlueZ sections.",
                info_path,
            )
            return record

        name = fields.get("Name") or fields.get("Alias") or _UNKNOWN_VALUE
        trusted = fields.get("Trusted", "").lower() == "true"
        blocked = fields.get("Blocked", "").lower() == "true"

        if "Paired" in fields:
            paired = fields.get("Paired", "").lower() == "true"
        else:
            paired = "LinkKey" in sections or "LongTermKey" in sections

        record.update(
            {
                "name": name,
                "alias": fields.get("Alias"),
                "class": fields.get("Class", _UNKNOWN_VALUE),
                "address_type": fields.get("AddressType"),
                "trusted": trusted,
                "blocked": blocked,
                "paired": paired,
                "uuids": uuids,
            }
        )
        return record

    def _walk_bluez_state(
        self,
    ) -> tuple[list[dict[str, Any]], str | None, list[dict[str, str]]]:
        """Walk the BlueZ state directory and read every device's info file.

        A single, shared traversal used by both :meth:`get_known_devices`
        (backward-compatible list output) and :meth:`get_bluez_device_evidence`
        (full acquisition-status output), so directory-walking logic is
        never duplicated.

        Per-controller or per-device access problems (e.g. a single
        unreadable device directory) are recorded individually in
        ``collection_errors`` rather than aborting the whole walk, so
        that one inaccessible item never hides evidence about the
        others. Only a failure to list the top-level state directory
        itself is treated as a fatal ``top_level_error``.

        Returns:
            A tuple of ``(devices, top_level_error, collection_errors)``.
            ``top_level_error`` is one of ``"directory_missing"``,
            :data:`_PERMISSION_DENIED`, or a ``"read_failed: ..."``
            message when the state directory could not be listed at
            all; otherwise ``None``. ``collection_errors`` is a list of
            ``{"path": ..., "error": ...}`` dictionaries for any
            individual controller/device directory or info file that
            could not be fully read.
        """
        devices: list[dict[str, Any]] = []
        collection_errors: list[dict[str, str]] = []

        try:
            if not _BLUETOOTH_STATE_DIR.is_dir():
                return devices, "directory_missing", collection_errors
            controller_dirs = list(_BLUETOOTH_STATE_DIR.iterdir())
        except PermissionError:
            self._logger.error(
                "Permission denied while accessing %s.", _BLUETOOTH_STATE_DIR
            )
            return devices, _PERMISSION_DENIED, collection_errors
        except OSError as exc:
            self._logger.warning(
                "Could not list %s: %s", _BLUETOOTH_STATE_DIR, exc
            )
            return devices, f"read_failed: {exc}", collection_errors

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
                collection_errors.append(
                    {"path": str(controller_dir), "error": _PERMISSION_DENIED}
                )
                continue
            except OSError as exc:
                self._logger.warning(
                    "Could not list %s: %s", controller_dir, exc
                )
                collection_errors.append(
                    {"path": str(controller_dir), "error": f"read_failed: {exc}"}
                )
                continue

            for device_dir in device_dirs:
                if not device_dir.is_dir():
                    continue
                device_mac = device_dir.name
                info_path = device_dir / _DEVICE_INFO_FILENAME

                if not info_path.is_file():
                    devices.append(
                        self._empty_device_record(
                            controller_mac, device_mac, info_path, "info_file_missing"
                        )
                    )
                    continue

                record = self._read_device_info_file(
                    info_path, controller_mac, device_mac
                )
                devices.append(record)
                if record.get("error"):
                    collection_errors.append(
                        {"path": str(info_path), "error": record["error"]}
                    )

        return devices, None, collection_errors

    def _read_known_devices_from_disk(self) -> list[dict[str, Any]]:
        """Read all cached device records from the BlueZ state directory.

        Preserved for backward compatibility: returns exactly the device
        list, discarding the richer top-level/collection error status
        that :meth:`get_bluez_device_evidence` exposes. Prefer
        :meth:`get_bluez_device_evidence` when the caller needs to know
        *why* evidence might be incomplete (e.g. permission denied)
        rather than just receiving an empty list.

        Returns:
            A list of device dictionaries as produced by
            :meth:`_read_device_info_file` / :meth:`_empty_device_record`.
            Returns an empty list if the state directory is missing or
            cannot be read at all.
        """
        devices, _top_level_error, _collection_errors = self._walk_bluez_state()
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
            Preserved for backward compatibility; prefer
            :meth:`get_bluez_device_evidence` when the caller needs to
            distinguish "no devices present" from "evidence could not be
            acquired" (e.g. permission denied).
        """
        return self._read_known_devices_from_disk()

    def get_bluez_device_evidence(self) -> dict[str, Any]:
        """Collect BlueZ persisted device state with full acquisition status.

        Unlike :meth:`get_known_devices` (which, for backward
        compatibility, returns a bare list and cannot distinguish "the
        directory genuinely contained no devices" from "evidence could
        not be acquired"), this method reports explicit acquisition
        status so that inaccessible evidence is never silently presented
        as an empty result.

        Returns:
            A dictionary with keys:

            * ``"path"``: the BlueZ state directory path.
            * ``"accessible"`` (bool): whether the top-level state
              directory itself could be listed at all.
            * ``"devices"`` (list[dict]): every device record found,
              including placeholder records (with
              ``"info_available": False`` and an ``"error"`` code) for
              devices whose ``info`` file was missing or unreadable.
            * ``"collection_errors"`` (list[dict]): ``{"path": ...,
              "error": ...}`` entries for every individual controller
              directory, device directory, or info file that could not
              be fully read (e.g. :data:`_PERMISSION_DENIED`), even when
              other devices were read successfully.
            * ``"error"`` (str or ``None``): set only when the top-level
              state directory itself could not be listed (e.g.
              ``"directory_missing"`` or :data:`_PERMISSION_DENIED`);
              ``None`` when at least directory listing succeeded, even
              if individual devices had their own errors.

            Never raises.
        """
        devices, top_level_error, collection_errors = self._walk_bluez_state()
        return {
            "path": str(_BLUETOOTH_STATE_DIR),
            "accessible": top_level_error is None,
            "devices": devices,
            "collection_errors": collection_errors,
            "error": top_level_error,
        }

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

        Note:
            ``"collected_at"`` records when THIS ACQUISITION ran; it is
            metadata about the collection process, never a substitute
            for the actual event timestamps embedded within ``content``
            itself. Extracting and normalizing those source timestamps
            is the responsibility of
            :class:`modules.connection_history.ConnectionHistoryAnalyzer`.
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

    def _run_journalctl_query(
        self,
        command_name: str,
        command_args: list[str],
        timeout: int,
        evidence_sources: list[dict[str, Any]],
    ) -> bool:
        """Run one journalctl query and append its evidence record.

        Shared by the unit-based, identifier-based, and fallback
        grep-based queries in :meth:`get_bluetooth_log_evidence` so each
        query's success/failure handling and evidence-record shape stay
        identical and are not duplicated three times.

        Args:
            command_name: The resolved ``journalctl`` command name
                (included here only for logging context).
            command_args: The full command and arguments to execute.
            timeout: Maximum time, in seconds, to wait for the command.
            evidence_sources: The list to append this query's evidence
                record to, in place.

        Returns:
            ``True`` if this query produced usable evidence (i.e. was
            appended with ``"success": True``), ``False`` otherwise.
        """
        source_reference = " ".join(command_args)
        output, error = self._collect_journalctl_output(command_args, timeout=timeout)

        if error:
            self._logger.warning(
                "journalctl query failed (%s): %s", source_reference, error
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
            return False

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
            return False

        evidence_sources.append(
            self._build_log_evidence_record(
                source_type=_SOURCE_TYPE_JOURNALCTL,
                source_reference=source_reference,
                content=output,
                success=True,
                error=None,
            )
        )
        return True

    def get_bluetooth_log_evidence(
        self,
        since: str = _DEFAULT_JOURNAL_LOOKBACK,
        unit_candidates: tuple[str, ...] = _JOURNALCTL_UNIT_CANDIDATES,
        identifier_candidates: tuple[str, ...] = _JOURNALCTL_IDENTIFIER_CANDIDATES,
    ) -> list[dict[str, Any]]:
        """Collect locally available Bluetooth-related journal log evidence.

        Attempts a targeted, read-only ``journalctl`` query for each
        candidate Bluetooth systemd unit name in ``unit_candidates``
        (since unit naming for ``bluetoothd`` varies across
        distributions), AND a separate query for each syslog identifier
        in ``identifier_candidates`` via ``journalctl -t`` (since
        ``bluetoothd``'s own log lines are commonly tagged with that
        identifier regardless of which unit launched it). Every query is
        preserved as its own separate evidence record -- sources are
        never merged, overwritten, or deduplicated here, so a later
        analyzer can independently correlate them. Only if NONE of those
        targeted queries yield any data does this method fall back to a
        single time-bounded, pattern-filtered journal search
        (``journalctl -g``), instead of retrieving the entire system
        journal, keeping collection targeted per the framework's
        evidence-handling policy.

        This method never classifies or interprets the collected text --
        it only acquires and preserves it verbatim. Classification into
        connected/disconnected/paired/authentication-failure/etc. events
        is performed later by
        :class:`modules.connection_history.ConnectionHistoryAnalyzer`.

        Args:
            since: A ``journalctl --since``-compatible time expression
                bounding how far back to search (e.g. ``"7 days ago"``,
                ``"2026-08-01"``). Defaults to
                :data:`_DEFAULT_JOURNAL_LOOKBACK`; this default lookback
                window is unchanged from the project's existing targeted
                collection behavior.
            unit_candidates: Systemd unit names to try, in order.
                Defaults to :data:`_JOURNALCTL_UNIT_CANDIDATES`.
            identifier_candidates: Syslog identifiers to try via
                ``journalctl -t``, in order. Defaults to
                :data:`_JOURNALCTL_IDENTIFIER_CANDIDATES`.

        Returns:
            A list of log evidence records (see
            :meth:`_build_log_evidence_record`), one per collection
            attempt actually made -- both successful and failed, so that
            the absence of evidence from a given source is itself
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

        found_targeted_evidence = False

        for unit_name in unit_candidates:
            command_args = [
                command_name,
                "-u", unit_name,
                "--no-pager",
                "-o", _JOURNALCTL_OUTPUT_FORMAT,
                "--since", since,
            ]
            if self._run_journalctl_query(
                command_name, command_args, 15, evidence_sources
            ):
                found_targeted_evidence = True

        for identifier in identifier_candidates:
            command_args = [
                command_name,
                "-t", identifier,
                "--no-pager",
                "-o", _JOURNALCTL_OUTPUT_FORMAT,
                "--since", since,
            ]
            if self._run_journalctl_query(
                command_name, command_args, 15, evidence_sources
            ):
                found_targeted_evidence = True

        if not found_targeted_evidence:
            command_args = [
                command_name,
                "--no-pager",
                "-o", _JOURNALCTL_OUTPUT_FORMAT,
                "--since", since,
                "-g", _BLUETOOTH_GREP_PATTERN,
            ]
            self._run_journalctl_query(command_name, command_args, 20, evidence_sources)

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
            ``"blocked_devices"`` (all four preserved exactly as before
            for backward compatibility), ``"bluez_device_evidence"``
            (the same device data plus explicit acquisition status --
            see :meth:`get_bluez_device_evidence` -- so permission
            issues or unreadable devices are never silently presented as
            "no devices"), ``"connection_log_evidence"`` (raw journal
            evidence records, see :meth:`get_bluetooth_log_evidence`),
            and ``"connection_history_evidence"`` (the same log/BlueZ
            evidence, pre-packaged via
            :meth:`build_connection_history_evidence` for direct use
            with :class:`modules.connection_history.ConnectionHistoryAnalyzer`).
        """
        try:
            bluez_device_evidence = self.get_bluez_device_evidence()
            known_devices = bluez_device_evidence["devices"]
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
                "bluez_device_evidence": bluez_device_evidence,
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
                "bluez_device_evidence": {
                    "path": str(_BLUETOOTH_STATE_DIR),
                    "accessible": False,
                    "devices": [],
                    "collection_errors": [],
                    "error": str(exc),
                },
                "connection_log_evidence": [],
                "connection_history_evidence": {
                    "log_sources": [],
                    "bluez_known_devices": [],
                    "structured_events": [],
                },
                "error": str(exc),
            }


__all__: Final[list[str]] = ["LinuxArtifactsCollector"]
