"""
modules/analyzer.py
====================

Bluetooth device analysis module for **BlueTrace Forensic Suite**.

This module contains the :class:`BluetoothAnalyzer` class, whose sole
responsibility is to analyze a single Bluetooth device previously
discovered by :mod:`modules.scanner` and collect the publicly available
forensic metadata that device advertises: its name, vendor (derived from
its MAC address OUI), Class of Device, SDP services, advertised UUIDs,
manufacturer data, and signal information.

This module never connects to, pairs with, or modifies a target device,
and never reads private user data (messages, contacts, photos, passwords,
health data, or any other protected information). It only inspects
information the device makes publicly available over the air or that the
local Bluetooth stack already has cached, using read-only Linux tooling.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and BLE devices on Linux.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any, Final

from config import BLUETOOTH_COMMANDS, LOG_LEVEL
from modules.utils import command_exists, is_valid_mac_address, normalize_mac_address

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Value returned for fields whose value could not be determined.
_UNKNOWN_VALUE: Final[str] = "Unknown"

#: Human-readable labels for the Bluetooth "major device class" bits
#: (bits 12:8) of a Class of Device value, per the Bluetooth Assigned
#: Numbers specification.
_MAJOR_DEVICE_CLASS_LABELS: Final[dict[int, str]] = {
    0x00: "Miscellaneous",
    0x01: "Computer",
    0x02: "Phone",
    0x03: "LAN/Network Access Point",
    0x04: "Audio/Video",
    0x05: "Peripheral",
    0x06: "Imaging",
    0x07: "Wearable",
    0x08: "Toy",
    0x09: "Health",
    0x1F: "Uncategorized",
}

#: Best-effort, locally-maintained mapping of well-known IEEE MAC address
#: OUI prefixes (first three octets) to vendor names. This is a small,
#: illustrative offline lookup table only; it is not a substitute for the
#: full IEEE OUI registry and unmatched prefixes are reported as
#: :data:`_UNKNOWN_VALUE`.
_OUI_VENDOR_MAP: Final[dict[str, str]] = {
    "00:1A:7D": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "AC:DE:48": "Apple, Inc.",
    "38:8B:59": "Samsung Electronics",
    "5C:F8:A1": "Samsung Electronics",
    "88:9F:6F": "Samsung Electronics",
    "3C:5A:B4": "Google, Inc.",
    "F4:F5:D8": "Google, Inc.",
    "7C:D9:5C": "Microsoft Corporation",
    "00:15:5D": "Microsoft Corporation",
    "00:1B:63": "Intel Corporate",
    "8C:85:90": "Intel Corporate",
    "AC:87:A3": "Sony Corporation",
    "00:24:8C": "Sony Corporation",
    "88:0F:10": "Fitbit, Inc.",
    "E0:5F:B9": "Fitbit, Inc.",
}

#: Error codes that :meth:`BluetoothAnalyzer._run_bluetoothctl_info` may
#: return alongside a ``None`` output, used consistently across the
#: collection methods to produce meaningful, structured error responses.
_TOOL_MISSING: Final[str] = "tool_missing"
_PERMISSION_DENIED: Final[str] = "permission_denied"
_TIMEOUT: Final[str] = "timeout"
_DEVICE_UNAVAILABLE: Final[str] = "device_unavailable"
_UNSUPPORTED_INFORMATION: Final[str] = "unsupported_information"


class BluetoothAnalyzer:
    """Analyze a single Bluetooth device and collect public forensic metadata.

    This class wraps the external ``bluetoothctl`` and ``sdptool``
    command-line tools to gather publicly advertised information about a
    device already identified by its MAC address (typically via
    :class:`modules.scanner.BluetoothScanner`). No connection, pairing,
    GATT access, or device modification is ever performed.
    """

    def __init__(self) -> None:
        """Initialize the analyzer's logger and operational configuration."""
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # ----------------------------------------------------------------- #
    # Internal helpers
    # ----------------------------------------------------------------- #

    def _run_bluetoothctl_info(
        self, mac_address: str
    ) -> tuple[str | None, str | None]:
        """Run ``bluetoothctl info <mac_address>`` and return its output.

        Centralizes the subprocess invocation and error handling shared by
        the individual collection methods so that failure modes are
        interpreted consistently.

        Args:
            mac_address: The MAC address of the device to query.

        Returns:
            A tuple of ``(output, error_code)``. On success, ``output`` is
            the command's standard output and ``error_code`` is ``None``.
            On failure, ``output`` is ``None`` and ``error_code`` is one
            of :data:`_TOOL_MISSING`, :data:`_PERMISSION_DENIED`,
            :data:`_TIMEOUT`, or :data:`_DEVICE_UNAVAILABLE`.
        """
        command_name = BLUETOOTH_COMMANDS.get("bluetoothctl", "bluetoothctl")
        if not command_exists(command_name):
            self._logger.warning("Required tool not found: %s", command_name)
            return None, _TOOL_MISSING

        try:
            completed = subprocess.run(
                [command_name, "info", mac_address],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except FileNotFoundError:
            self._logger.warning("Required tool not found: %s", command_name)
            return None, _TOOL_MISSING
        except PermissionError:
            self._logger.error(
                "Permission denied while querying device %s.", mac_address
            )
            return None, _PERMISSION_DENIED
        except subprocess.TimeoutExpired:
            self._logger.error("Timed out while querying device %s.", mac_address)
            return None, _TIMEOUT

        output = completed.stdout or ""
        if not output.strip() or "not available" in output:
            self._logger.warning("Device %s is not available.", mac_address)
            return None, _DEVICE_UNAVAILABLE

        return output, None

    # ----------------------------------------------------------------- #
    # Individual collection methods
    # ----------------------------------------------------------------- #

    def get_device_name(self, mac_address: str) -> str:
        """Obtain the Bluetooth device name (or alias) of a device.

        Args:
            mac_address: The MAC address of the device to query.

        Returns:
            The device's advertised name, or its alias if no name is set,
            or :data:`_UNKNOWN_VALUE` if neither is available or the
            device could not be queried.
        """
        output, error = self._run_bluetoothctl_info(mac_address)
        if error:
            return _UNKNOWN_VALUE

        name: str | None = None
        alias: str | None = None
        for line in output.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("Name:"):
                name = stripped_line.split(":", 1)[1].strip()
            elif stripped_line.startswith("Alias:"):
                alias = stripped_line.split(":", 1)[1].strip()

        return name or alias or _UNKNOWN_VALUE

    def get_vendor(self, mac_address: str) -> str:
        """Determine the device vendor using its MAC address OUI.

        Looks up the first three octets (the Organizationally Unique
        Identifier) of the MAC address against a small, locally-maintained
        vendor table. No network lookup is performed.

        Args:
            mac_address: The MAC address of the device.

        Returns:
            The matched vendor name, or :data:`_UNKNOWN_VALUE` if the
            address is invalid or its OUI is not present in the local
            vendor table.
        """
        if not is_valid_mac_address(mac_address):
            return _UNKNOWN_VALUE

        normalized_mac = normalize_mac_address(mac_address)
        if normalized_mac is None:
            return _UNKNOWN_VALUE

        oui = ":".join(normalized_mac.split(":")[:3])
        return _OUI_VENDOR_MAP.get(oui, _UNKNOWN_VALUE)

    def get_device_class(self, mac_address: str) -> dict[str, Any]:
        """Collect the Bluetooth Class of Device (CoD) value, if available.

        Args:
            mac_address: The MAC address of the device to query.

        Returns:
            A dictionary with keys ``"raw_class"`` (the CoD hex string, or
            ``None``), ``"major_device_class"`` (a human-readable label, or
            :data:`_UNKNOWN_VALUE`), and ``"error"`` (an error code, or
            ``None`` on success).
        """
        result: dict[str, Any] = {
            "raw_class": None,
            "major_device_class": _UNKNOWN_VALUE,
            "error": None,
        }

        output, error = self._run_bluetoothctl_info(mac_address)
        if error:
            result["error"] = error
            return result

        raw_class: str | None = None
        for line in output.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("Class:"):
                raw_class = stripped_line.split(":", 1)[1].strip()
                break

        if raw_class is None:
            result["error"] = _UNSUPPORTED_INFORMATION
            return result

        try:
            class_value = int(raw_class, 16)
        except ValueError:
            result["error"] = _UNSUPPORTED_INFORMATION
            return result

        major_class_bits = (class_value >> 8) & 0x1F
        result["raw_class"] = raw_class
        result["major_device_class"] = _MAJOR_DEVICE_CLASS_LABELS.get(
            major_class_bits, _UNKNOWN_VALUE
        )
        return result

    def get_services(self, mac_address: str) -> list[str]:
        """Collect SDP (Service Discovery Protocol) services using ``sdptool``.

        Args:
            mac_address: The MAC address of the device to query.

        Returns:
            A list of advertised SDP service names. Returns an empty list
            if the tool is missing, permission is denied, the query times
            out, or the device advertises no discoverable services.
        """
        command_name = BLUETOOTH_COMMANDS.get("sdptool", "sdptool")
        if not command_exists(command_name):
            self._logger.warning("Required tool not found: %s", command_name)
            return []

        try:
            completed = subprocess.run(
                [command_name, "browse", mac_address],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except FileNotFoundError:
            self._logger.warning("Required tool not found: %s", command_name)
            return []
        except PermissionError:
            self._logger.error(
                "Permission denied while browsing services on %s.", mac_address
            )
            return []
        except subprocess.TimeoutExpired:
            self._logger.error(
                "Timed out while browsing services on %s.", mac_address
            )
            return []

        services: list[str] = []
        for line in (completed.stdout or "").splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("Service Name:"):
                service_name = stripped_line.split(":", 1)[1].strip()
                if service_name:
                    services.append(service_name)

        return services

    def get_uuid_list(self, mac_address: str) -> list[dict[str, str]]:
        """Collect advertised service/profile UUIDs, if available.

        Args:
            mac_address: The MAC address of the device to query.

        Returns:
            A list of dictionaries with keys ``"name"`` and ``"uuid"``,
            one per advertised UUID. Returns an empty list if the device
            could not be queried or advertises no UUIDs.
        """
        output, error = self._run_bluetoothctl_info(mac_address)
        if error:
            return []

        uuids: list[dict[str, str]] = []
        for line in output.splitlines():
            stripped_line = line.strip()
            if not stripped_line.startswith("UUID:"):
                continue

            remainder = stripped_line.split(":", 1)[1].strip()
            if remainder.endswith(")") and "(" in remainder:
                name_part, _, uuid_part = remainder.rpartition("(")
                uuid_value = uuid_part.rstrip(")").strip()
                name_value = name_part.strip()
            else:
                uuid_value = remainder
                name_value = ""

            if uuid_value:
                uuids.append({"name": name_value, "uuid": uuid_value})

        return uuids

    def get_manufacturer_data(self, mac_address: str) -> dict[str, str]:
        """Collect advertised manufacturer data, if available.

        Args:
            mac_address: The MAC address of the device to query.

        Returns:
            A dictionary with keys ``"key"`` (the manufacturer identifier,
            e.g. ``"0x004c"``) and ``"value"`` (the raw hex byte string).
            Returns an empty dictionary if the device could not be queried
            or advertises no manufacturer data.
        """
        output, error = self._run_bluetoothctl_info(mac_address)
        if error:
            return {}

        manufacturer_key: str | None = None
        value_bytes: list[str] = []
        collecting_value = False

        for line in output.splitlines():
            stripped_line = line.strip()

            if stripped_line.startswith("ManufacturerData Key:"):
                manufacturer_key = stripped_line.split(":", 1)[1].strip()
                collecting_value = False
                continue

            if stripped_line.startswith("ManufacturerData Value:"):
                collecting_value = True
                continue

            if collecting_value:
                tokens = stripped_line.split()
                hex_tokens = [
                    token for token in tokens if self._is_hex_byte(token)
                ]
                if hex_tokens:
                    value_bytes.extend(hex_tokens)
                else:
                    collecting_value = False

        if manufacturer_key is None:
            return {}

        return {"key": manufacturer_key, "value": " ".join(value_bytes)}

    @staticmethod
    def _is_hex_byte(token: str) -> bool:
        """Check whether a string token represents a single hex byte.

        Args:
            token: The token to check.

        Returns:
            ``True`` if ``token`` is exactly two hexadecimal characters,
            ``False`` otherwise.
        """
        if len(token) != 2:
            return False
        try:
            int(token, 16)
            return True
        except ValueError:
            return False

    def get_signal_information(self, mac_address: str) -> dict[str, Any]:
        """Collect Received Signal Strength Indicator (RSSI) information.

        Args:
            mac_address: The MAC address of the device to query.

        Returns:
            A dictionary with keys ``"rssi"`` (int or ``None``),
            ``"available"`` (bool), and ``"note"`` (str, populated when
            RSSI information could not be determined).
        """
        result: dict[str, Any] = {"rssi": None, "available": False, "note": ""}

        output, error = self._run_bluetoothctl_info(mac_address)
        if error:
            result["note"] = f"Signal information unavailable: {error}."
            return result

        for line in output.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("RSSI:"):
                raw_rssi = stripped_line.split(":", 1)[1].strip()
                try:
                    result["rssi"] = int(raw_rssi)
                    result["available"] = True
                except ValueError:
                    result["note"] = "RSSI value could not be parsed."
                return result

        result["note"] = (
            "RSSI information unavailable; device is not currently "
            "advertising or in range."
        )
        return result

    # ----------------------------------------------------------------- #
    # Orchestration
    # ----------------------------------------------------------------- #

    def build_summary(self, mac_address: str) -> dict[str, Any]:
        """Generate a structured forensic summary for a single device.

        Invokes each individual collection method and assembles the
        results into a single, flat summary dictionary.

        Args:
            mac_address: The MAC address of the device to summarize.

        Returns:
            A dictionary with keys ``"device_name"``, ``"mac"``,
            ``"vendor"``, ``"device_class"``, ``"services"``, ``"uuids"``,
            ``"manufacturer_data"``, and ``"rssi"``, e.g.::

                {
                    "device_name": "Galaxy Watch",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "vendor": "Samsung Electronics",
                    "device_class": "Wearable",
                    "services": [...],
                    "uuids": [...],
                    "manufacturer_data": {},
                    "rssi": -53,
                }
        """
        normalized_mac = normalize_mac_address(mac_address) or mac_address

        device_class_info = self.get_device_class(normalized_mac)
        signal_info = self.get_signal_information(normalized_mac)

        return {
            "device_name": self.get_device_name(normalized_mac),
            "mac": normalized_mac,
            "vendor": self.get_vendor(normalized_mac),
            "device_class": device_class_info.get("major_device_class", _UNKNOWN_VALUE),
            "services": self.get_services(normalized_mac),
            "uuids": self.get_uuid_list(normalized_mac),
            "manufacturer_data": self.get_manufacturer_data(normalized_mac),
            "rssi": signal_info.get("rssi"),
        }

    def analyze_device(self, mac_address: str) -> dict[str, Any]:
        """Analyze a discovered Bluetooth device and return its full profile.

        This is the main entry point of the analyzer. It validates the
        supplied MAC address, verifies that the required tooling is
        available, and then delegates to :meth:`build_summary` to collect
        and assemble the device's publicly available forensic metadata.
        Never raises; all failure modes are captured and returned as
        structured error dictionaries.

        Args:
            mac_address: The MAC address of the device to analyze.

        Returns:
            On success, the structured summary dictionary produced by
            :meth:`build_summary`. On failure, a dictionary with keys
            ``"mac"``, ``"error"`` (a short error code), and ``"message"``
            (a human-readable description).
        """
        if not is_valid_mac_address(mac_address):
            self._logger.warning("Invalid MAC address supplied: %s", mac_address)
            return {
                "mac": mac_address,
                "error": "invalid_mac_address",
                "message": "The provided MAC address is not validly formatted.",
            }

        normalized_mac = normalize_mac_address(mac_address) or mac_address

        command_name = BLUETOOTH_COMMANDS.get("bluetoothctl", "bluetoothctl")
        if not command_exists(command_name):
            self._logger.warning("Required tool not found: %s", command_name)
            return {
                "mac": normalized_mac,
                "error": _TOOL_MISSING,
                "message": f"Required tool not found: {command_name}",
            }

        try:
            return self.build_summary(normalized_mac)
        except (OSError, subprocess.SubprocessError) as exc:
            self._logger.error(
                "Unexpected error while analyzing device %s: %s",
                normalized_mac,
                exc,
            )
            return {
                "mac": normalized_mac,
                "error": "unexpected_error",
                "message": str(exc),
            }


__all__: Final[list[str]] = ["BluetoothAnalyzer"]
