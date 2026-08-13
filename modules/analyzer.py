"""
modules/analyzer.py
====================

Bluetooth device analysis module for **BlueTrace Forensic Suite**.

This module contains the :class:`BluetoothAnalyzer` class, whose
responsibility is to analyze a single Bluetooth device (previously
discovered by :mod:`modules.scanner`, or referenced by evidence
already collected by other BlueTrace modules) and assemble the
publicly available forensic metadata that device advertises or that
the local Bluetooth stack already has cached: its name/alias, vendor
(derived from its MAC address OUI), Class of Device, SDP services,
advertised UUIDs, BLE advertisement metadata (address type,
appearance, TX power, service data, manufacturer data), and signal
(RSSI) information -- including simple aggregate RSSI statistics when
multiple observations of the same device are supplied.

This module never connects to, pairs with, authenticates to, or
modifies a target device, and never reads private user data (messages,
contacts, photos, passwords, health data, or any other protected
information). It only inspects information the device makes publicly
available over the air, that the local Bluetooth stack already has
cached, or that other BlueTrace evidence-acquisition modules have
already collected and supplied as structured evidence. All Bluetooth
tooling this module invokes (``bluetoothctl info``, ``sdptool
browse``) is read-only and non-interactive.

Forensic scope and epistemic labeling
--------------------------------------
This module distinguishes between:

* **observed** -- read directly from the device's own advertised
  properties or the local Bluetooth stack's live view of it (e.g. a
  ``Name:``/``RSSI:``/``AddressType:`` field from ``bluetoothctl
  info``).
* **reported** -- supplied by the caller as evidence from another
  source (e.g. a cached name from a BlueZ on-disk artifact record, or
  BLE advertisement fields captured earlier by a scanning module) that
  this module did not itself observe.
* **derived** -- computed or inferred by this module from other
  evidence (e.g. a vendor name derived from a MAC OUI lookup, or a
  human-readable device-type label derived from Class-of-Device bits).
* **unknown** -- no evidence of any kind was available.

:meth:`BluetoothAnalyzer.build_forensic_profile` records this
classification per-field in the profile's ``"field_classification"``
key so that a derived or reported value is never presented as if it
had been directly observed.

This module intentionally does NOT:

* reconstruct historical connection events (see
  :class:`modules.connection_history.ConnectionHistoryAnalyzer`);
* build a chronological timeline (see :mod:`modules.timeline`);
* generate reports or calculate evidence hashes (see
  :mod:`modules.report` / :mod:`modules.hashing`);
* infer a device's physical location from RSSI, or infer ownership or
  human identity from a device name, alias, or local relationship
  state.

Forensic limitations
---------------------
* A device being "paired", "trusted", or "known" to the local
  Bluetooth stack is a *local relationship state*, not proof of a
  historical connection, and it does not establish ownership.
* RSSI reflects received signal strength only; it is not converted to
  a physical distance and must not be treated as one.
* Bluetooth Low Energy devices using Resolvable/Non-Resolvable Private
  Addresses can rotate their advertised MAC address over time. This
  module treats each MAC address it is given as a distinct identity
  and performs no cross-address correlation.
* The small, locally-maintained OUI-to-vendor table used by
  :meth:`get_vendor` is illustrative only, not a complete IEEE OUI
  registry; randomized or unrecognized OUIs are reported as unknown
  rather than guessed at.
* Manufacturer-specific and service-specific advertisement data are
  preserved in raw hexadecimal form; this module does not decode
  proprietary payloads into invented interpretations.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and BLE devices on Linux.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any, Final

from config import BLUETOOTH_COMMANDS, LOG_LEVEL
from modules.utils import (
    command_exists,
    current_datetime_iso,
    is_valid_mac_address,
    normalize_mac_address,
)

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

#: Field-classification labels used throughout
#: :meth:`BluetoothAnalyzer.build_forensic_profile`. See the module
#: docstring for their precise meaning.
_STATUS_OBSERVED: Final[str] = "observed"
_STATUS_REPORTED: Final[str] = "reported"
_STATUS_DERIVED: Final[str] = "derived"
_STATUS_UNKNOWN: Final[str] = "unknown"


class BluetoothAnalyzer:
    """Analyze a single Bluetooth device and build a forensic profile of it.

    This class wraps the external ``bluetoothctl`` and ``sdptool``
    command-line tools to gather publicly advertised information about a
    device already identified by its MAC address (typically via
    :class:`modules.scanner.BluetoothScanner`), and can additionally
    incorporate structured evidence supplied by other BlueTrace modules
    (e.g. local BlueZ relationship state from
    :class:`modules.linux_artifacts.LinuxArtifactsCollector`, or
    repeated RSSI observations from a scanning module). No connection,
    pairing, GATT access, authentication, or device modification is
    ever performed.

    Existing single-purpose collection methods (``get_device_name``,
    ``get_vendor``, ``get_device_class``, ``get_services``,
    ``get_uuid_list``, ``get_manufacturer_data``,
    ``get_signal_information``, ``build_summary``, ``analyze_device``)
    remain fully backward compatible. The richer
    :meth:`build_forensic_profile` is the recommended entry point for
    new callers that want a complete, epistemically-labeled device
    profile in a single call.
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

    def _get_output(
        self, mac_address: str, precomputed_output: str | None
    ) -> tuple[str | None, str | None]:
        """Return ``bluetoothctl info`` output, reusing a prior fetch if given.

        Allows orchestration methods (such as
        :meth:`build_forensic_profile`) to fetch device info once and
        share it across several field-extraction calls, while every
        individual collection method remains independently callable
        (and independently fetches the info itself) for backward
        compatibility.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Previously fetched ``bluetoothctl info``
                output to reuse, or ``None`` to fetch fresh output.

        Returns:
            A tuple of ``(output, error_code)`` with the same meaning as
            :meth:`_run_bluetoothctl_info`.
        """
        if precomputed_output is not None:
            return precomputed_output, None
        return self._run_bluetoothctl_info(mac_address)

    @staticmethod
    def _extract_field(output: str, prefix: str) -> str | None:
        """Extract the value of the first line starting with ``prefix``.

        Args:
            output: Raw ``bluetoothctl info`` output text.
            prefix: The field prefix to search for, e.g. ``"Name:"``.

        Returns:
            The trimmed field value, or ``None`` if the field is absent
            or empty.
        """
        for line in output.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith(prefix):
                value = stripped_line.split(":", 1)[1].strip()
                return value or None
        return None

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

    @classmethod
    def _extract_hex_value_blocks(
        cls, output: str, key_prefix: str, value_prefix: str
    ) -> dict[str, str]:
        """Parse repeated ``"<Key>: ..."``/``"<Value>: <hex bytes...>"`` blocks.

        Generalizes the shape shared by ``bluetoothctl info``'s
        ``ManufacturerData Key:``/``ManufacturerData Value:`` and
        ``ServiceData Key:``/``ServiceData Value:`` block pairs, which
        may repeat multiple times for a device advertising more than
        one entry.

        Args:
            output: Raw ``bluetoothctl info`` output text.
            key_prefix: The line prefix introducing a new block's key,
                e.g. ``"ManufacturerData Key:"``.
            value_prefix: The line prefix introducing a block's hex-byte
                value, e.g. ``"ManufacturerData Value:"``.

        Returns:
            A dictionary mapping each observed key to a space-separated
            hex-byte string. Blocks with a key but no parsable value are
            omitted. Never raises.
        """
        blocks: dict[str, str] = {}
        current_key: str | None = None
        value_bytes: list[str] = []
        collecting = False

        def _flush() -> None:
            if current_key is not None and value_bytes:
                blocks[current_key] = " ".join(value_bytes)

        for line in output.splitlines():
            stripped_line = line.strip()

            if stripped_line.startswith(key_prefix):
                _flush()
                current_key = stripped_line.split(":", 1)[1].strip()
                value_bytes = []
                collecting = False
                continue

            if stripped_line.startswith(value_prefix):
                collecting = True
                continue

            if collecting:
                tokens = stripped_line.split()
                hex_tokens = [token for token in tokens if cls._is_hex_byte(token)]
                if hex_tokens:
                    value_bytes.extend(hex_tokens)
                else:
                    collecting = False

        _flush()
        return blocks

    # ----------------------------------------------------------------- #
    # Individual collection methods
    # ----------------------------------------------------------------- #

    def get_device_name(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> str:
        """Obtain the Bluetooth device name (or alias) of a device.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

        Returns:
            The device's advertised name, or its alias if no name is set,
            or :data:`_UNKNOWN_VALUE` if neither is available or the
            device could not be queried.
        """
        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
            return _UNKNOWN_VALUE

        name = self._extract_field(output, "Name:")
        alias = self._extract_field(output, "Alias:")
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

    def get_device_class(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> dict[str, Any]:
        """Collect the Bluetooth Class of Device (CoD) value, if available.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

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

        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
            result["error"] = error
            return result

        raw_class = self._extract_field(output, "Class:")
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

    def get_uuid_list(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> list[dict[str, str]]:
        """Collect advertised service/profile UUIDs, if available.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

        Returns:
            A list of dictionaries with keys ``"name"`` and ``"uuid"``,
            one per advertised UUID. Returns an empty list if the device
            could not be queried or advertises no UUIDs.
        """
        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
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

    def get_manufacturer_data(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> dict[str, str]:
        """Collect a single advertised manufacturer-data entry, if available.

        Preserved for backward compatibility. This method reports only
        one manufacturer-data entry (the last one encountered in the
        ``bluetoothctl info`` output), matching the original analyzer's
        behavior. For devices that advertise multiple manufacturer-data
        entries, prefer :meth:`get_manufacturer_data_map`.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

        Returns:
            A dictionary with keys ``"key"`` (the manufacturer identifier,
            e.g. ``"0x004c"``) and ``"value"`` (the raw hex byte string).
            Returns an empty dictionary if the device could not be queried
            or advertises no manufacturer data.
        """
        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
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

    def get_manufacturer_data_map(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> dict[str, str]:
        """Collect all advertised manufacturer-data entries, keyed by identifier.

        Unlike :meth:`get_manufacturer_data` (which preserves the
        original single-entry behavior for backward compatibility),
        this method captures every ``ManufacturerData Key:``/
        ``ManufacturerData Value:`` block present, which some BLE
        devices advertise more than one of.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

        Returns:
            A dictionary mapping each manufacturer identifier (e.g.
            ``"0x004c"``) to its raw hex-byte value string. Returns an
            empty dictionary if the device could not be queried or
            advertises no manufacturer data.
        """
        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
            return {}
        return self._extract_hex_value_blocks(
            output, "ManufacturerData Key:", "ManufacturerData Value:"
        )

    def get_service_data(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> dict[str, str]:
        """Collect advertised BLE service-data entries, keyed by service UUID.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

        Returns:
            A dictionary mapping each service UUID to its raw hex-byte
            value string. Returns an empty dictionary if the device
            could not be queried or advertises no service data.
        """
        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
            return {}
        return self._extract_hex_value_blocks(
            output, "ServiceData Key:", "ServiceData Value:"
        )

    def get_address_type(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> str:
        """Collect the device's Bluetooth address type, if available.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

        Returns:
            ``"Public"`` or ``"Random"`` (as reported by the local
            Bluetooth stack), or :data:`_UNKNOWN_VALUE` if the address
            type could not be determined. Never claims a specific type
            when none was reported.
        """
        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
            return _UNKNOWN_VALUE

        raw_value = self._extract_field(output, "AddressType:")
        if not raw_value:
            return _UNKNOWN_VALUE
        return raw_value.strip().capitalize()

    def get_appearance(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> str | None:
        """Collect the device's advertised BLE appearance value, if available.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

        Returns:
            The raw appearance field as reported by the local Bluetooth
            stack (e.g. category name and/or numeric value), or ``None``
            if unavailable. Preserved as-is; not decoded into an
            invented category.
        """
        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
            return None
        return self._extract_field(output, "Appearance:")

    def get_tx_power(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> int | None:
        """Collect the device's advertised TX power level, if available.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

        Returns:
            The TX power in dBm as an integer, or ``None`` if
            unavailable or unparsable.
        """
        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
            return None

        raw_value = self._extract_field(output, "TxPower:")
        if raw_value is None:
            return None
        try:
            return int(raw_value)
        except ValueError:
            return None

    def get_signal_information(
        self, mac_address: str, precomputed_output: str | None = None
    ) -> dict[str, Any]:
        """Collect Received Signal Strength Indicator (RSSI) information.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.

        Returns:
            A dictionary with keys ``"rssi"`` (int or ``None``),
            ``"available"`` (bool), and ``"note"`` (str, populated when
            RSSI information could not be determined).
        """
        result: dict[str, Any] = {"rssi": None, "available": False, "note": ""}

        output, error = self._get_output(mac_address, precomputed_output)
        if error or output is None:
            result["note"] = f"Signal information unavailable: {error}."
            return result

        raw_rssi = self._extract_field(output, "RSSI:")
        if raw_rssi is None:
            result["note"] = (
                "RSSI information unavailable; device is not currently "
                "advertising or in range."
            )
            return result

        try:
            result["rssi"] = int(raw_rssi)
            result["available"] = True
        except ValueError:
            result["note"] = "RSSI value could not be parsed."

        return result

    # ----------------------------------------------------------------- #
    # BLE metadata
    # ----------------------------------------------------------------- #

    def extract_ble_metadata(
        self,
        mac_address: str,
        precomputed_output: str | None = None,
        ble_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Assemble BLE advertisement metadata for a device.

        Combines whatever BLE-relevant fields can be directly observed
        via ``bluetoothctl info`` (address type, appearance, TX power,
        service UUIDs, service data, manufacturer data) with any
        additional BLE evidence explicitly supplied by the caller (for
        example, advertisement fields captured earlier by a passive
        scanning module). Caller-supplied evidence is only used to fill
        fields this module could not itself observe, and is tracked
        separately so a reported value is never mistaken for an
        observed one.

        Args:
            mac_address: The MAC address of the device to query.
            precomputed_output: Optional previously fetched
                ``bluetoothctl info`` output to reuse instead of issuing
                a fresh query.
            ble_evidence: Optional dictionary of previously captured BLE
                advertisement fields. Recognized keys: ``"address_type"``,
                ``"appearance"``, ``"tx_power"``, ``"service_uuids"``,
                ``"service_data"``, ``"manufacturer_data"``.

        Returns:
            A dictionary with keys ``"address_type"``, ``"appearance"``,
            ``"tx_power"``, ``"service_uuids"`` (list[str]),
            ``"service_data"`` (dict), ``"manufacturer_data"`` (dict),
            ``"reported_fields"`` (list of field names filled from
            ``ble_evidence`` rather than directly observed), and
            ``"error"`` (an error code, or ``None``).
        """
        output, error = self._get_output(mac_address, precomputed_output)

        metadata: dict[str, Any] = {
            "address_type": _UNKNOWN_VALUE,
            "appearance": None,
            "tx_power": None,
            "service_uuids": [],
            "service_data": {},
            "manufacturer_data": {},
            "error": error,
        }

        if output is not None:
            metadata["address_type"] = self.get_address_type(
                mac_address, precomputed_output=output
            )
            metadata["appearance"] = self.get_appearance(
                mac_address, precomputed_output=output
            )
            metadata["tx_power"] = self.get_tx_power(
                mac_address, precomputed_output=output
            )
            metadata["service_uuids"] = [
                entry["uuid"]
                for entry in self.get_uuid_list(mac_address, precomputed_output=output)
            ]
            metadata["service_data"] = self.get_service_data(
                mac_address, precomputed_output=output
            )
            metadata["manufacturer_data"] = self.get_manufacturer_data_map(
                mac_address, precomputed_output=output
            )

        reported_fields: list[str] = []
        if isinstance(ble_evidence, dict):
            fillable_fields = (
                "address_type", "appearance", "tx_power",
                "service_uuids", "service_data", "manufacturer_data",
            )
            for field_name in fillable_fields:
                current_value = metadata.get(field_name)
                is_empty = current_value in (None, _UNKNOWN_VALUE, [], {})
                if field_name in ble_evidence and is_empty:
                    supplied_value = ble_evidence[field_name]
                    if supplied_value not in (None, _UNKNOWN_VALUE, [], {}):
                        metadata[field_name] = supplied_value
                        reported_fields.append(field_name)

        metadata["reported_fields"] = reported_fields
        return metadata

    # ----------------------------------------------------------------- #
    # Observation statistics
    # ----------------------------------------------------------------- #

    def extract_observation_statistics(
        self, observations: list[dict[str, Any]] | None
    ) -> dict[str, Any]:
        """Compute simple RSSI observation statistics from repeated readings.

        Aggregate fields (``rssi_min``/``rssi_max``/``rssi_average``)
        are only populated when the supplied evidence actually contains
        more than one valid RSSI observation; a single observation is
        never turned into a fabricated range or average.

        Args:
            observations: A list of observation dictionaries, each
                expected to contain a numeric ``"rssi"`` value and,
                optionally, a ``"timestamp"`` (ISO-8601 string). Order
                is assumed to be chronological (oldest first); the last
                valid entry is treated as the most recent. May be
                ``None`` or empty.

        Returns:
            A dictionary with keys ``"observation_count"``,
            ``"rssi_current"`` (the most recent valid RSSI, or
            ``None``), ``"first_observed"``, ``"last_observed"``, and,
            only when more than one valid observation was supplied,
            ``"rssi_min"``, ``"rssi_max"``, ``"rssi_average"``, and
            ``"observations"`` (the preserved, validated observation
            list).
        """
        if not observations:
            return {
                "observation_count": 0,
                "rssi_current": None,
                "first_observed": None,
                "last_observed": None,
            }

        valid_observations: list[dict[str, Any]] = []
        for entry in observations:
            if not isinstance(entry, dict):
                continue
            rssi_value = entry.get("rssi")
            if isinstance(rssi_value, bool) or not isinstance(rssi_value, (int, float)):
                continue
            valid_observations.append(
                {"rssi": int(rssi_value), "timestamp": entry.get("timestamp")}
            )

        if not valid_observations:
            return {
                "observation_count": 0,
                "rssi_current": None,
                "first_observed": None,
                "last_observed": None,
            }

        rssi_values = [entry["rssi"] for entry in valid_observations]
        timestamps = [entry["timestamp"] for entry in valid_observations if entry["timestamp"]]

        stats: dict[str, Any] = {
            "observation_count": len(valid_observations),
            "rssi_current": rssi_values[-1],
            "first_observed": timestamps[0] if timestamps else None,
            "last_observed": timestamps[-1] if timestamps else None,
        }

        if len(valid_observations) > 1:
            stats["rssi_min"] = min(rssi_values)
            stats["rssi_max"] = max(rssi_values)
            stats["rssi_average"] = round(sum(rssi_values) / len(rssi_values), 1)
            stats["observations"] = valid_observations

        return stats

    # ----------------------------------------------------------------- #
    # Local relationship (BlueZ artifact) correlation
    # ----------------------------------------------------------------- #

    def build_local_relationship(
        self, local_relationship_evidence: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Summarize local BlueZ relationship state supplied as evidence.

        Accepts a device record such as one produced by
        :class:`modules.linux_artifacts.LinuxArtifactsCollector`
        (``get_known_devices`` / ``get_paired_devices`` / etc.), which
        typically carries boolean ``"paired"``/``"trusted"``/``"blocked"``
        fields. This method never infers a relationship state beyond
        what the supplied artifact states, and never treats "paired" as
        "currently connected", "trusted" as "owner", or "known" as
        proof of a historical connection.

        Args:
            local_relationship_evidence: A device-record dictionary from
                local BlueZ artifact evidence, or ``None``/empty if no
                such evidence was supplied for this device.

        Returns:
            A dictionary with keys ``"known"``, ``"paired"``,
            ``"trusted"``, ``"blocked"`` (each ``True``/``False`` when
            evidence was supplied, or ``None`` when no local artifact
            evidence exists for this device -- never guessed as
            ``False`` in the absence of evidence), and ``"note"``
            describing the evidentiary limits of this field.
        """
        if not isinstance(local_relationship_evidence, dict) or not local_relationship_evidence:
            return {
                "known": None,
                "paired": None,
                "trusted": None,
                "blocked": None,
                "note": (
                    "No local BlueZ artifact evidence was supplied for "
                    "this device; local relationship state is unknown, "
                    "not necessarily absent."
                ),
            }

        return {
            "known": True,
            "paired": bool(local_relationship_evidence.get("paired", False)),
            "trusted": bool(local_relationship_evidence.get("trusted", False)),
            "blocked": bool(local_relationship_evidence.get("blocked", False)),
            "note": (
                "Reflects locally cached BlueZ relationship state only. "
                "Paired/trusted/known status does not itself prove a "
                "historical connection, current connection, or device "
                "ownership."
            ),
        }

    # ----------------------------------------------------------------- #
    # Device-type derivation
    # ----------------------------------------------------------------- #

    @staticmethod
    def _derive_device_type(
        device_class_info: dict[str, Any], evidence: dict[str, Any]
    ) -> tuple[str, str]:
        """Determine a device-type label and its epistemic status.

        Prefers an explicitly caller-reported device type over one
        this module derives itself, and clearly marks a
        Class-of-Device-derived label as derived rather than observed.

        Args:
            device_class_info: The result of :meth:`get_device_class`.
            evidence: The caller-supplied evidence dictionary passed to
                :meth:`build_forensic_profile`.

        Returns:
            A tuple of ``(device_type_value, status)`` where ``status``
            is one of :data:`_STATUS_REPORTED`, :data:`_STATUS_DERIVED`,
            or :data:`_STATUS_UNKNOWN`.
        """
        reported_type = evidence.get("device_type")
        if isinstance(reported_type, str) and reported_type.strip():
            return reported_type.strip(), _STATUS_REPORTED

        major_class = device_class_info.get("major_device_class")
        if major_class and major_class != _UNKNOWN_VALUE:
            return major_class, _STATUS_DERIVED

        return _UNKNOWN_VALUE, _STATUS_UNKNOWN

    # ----------------------------------------------------------------- #
    # Orchestration
    # ----------------------------------------------------------------- #

    def build_summary(self, mac_address: str) -> dict[str, Any]:
        """Generate a structured forensic summary for a single device.

        Invokes each individual collection method and assembles the
        results into a single, flat summary dictionary. Preserved
        exactly for backward compatibility; prefer
        :meth:`build_forensic_profile` for a fuller, epistemically
        labeled profile that also incorporates evidence from other
        BlueTrace modules.

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

        Preserved exactly for backward compatibility. This is the
        original entry point of the analyzer; it validates the supplied
        MAC address, verifies that the required tooling is available,
        and then delegates to :meth:`build_summary`. Never raises; all
        failure modes are captured and returned as structured error
        dictionaries. New callers wanting local-artifact correlation,
        BLE metadata, RSSI statistics, or epistemic field labeling
        should use :meth:`build_forensic_profile` instead.

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

    def build_forensic_profile(
        self, mac_address: str, evidence: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Build a complete, epistemically-labeled forensic device profile.

        This is the analyzer's primary entry point for new BlueTrace
        code. It queries ``bluetoothctl info`` once (reused across all
        field extractors), separately queries ``sdptool`` for Classic
        SDP services, and can incorporate structured evidence from
        other BlueTrace modules -- local BlueZ relationship state
        (``evidence["local_relationship"]``), repeated RSSI observations
        (``evidence["observations"]``), previously captured BLE
        advertisement fields (``evidence["ble_evidence"]``), an explicit
        provenance/source label (``evidence["source"]``), an explicit
        observation timestamp (``evidence["observed_at"]``), and/or an
        explicitly reported device type (``evidence["device_type"]``).

        Every finding is labeled in the returned ``"field_classification"``
        dictionary as one of ``"observed"``, ``"reported"``, ``"derived"``,
        or ``"unknown"`` (see the module docstring), so that a derived or
        reported value is never presented as directly observed. Never
        raises; all failure modes are captured and reflected in the
        returned structure.

        Args:
            mac_address: The MAC address of the device to profile.
            evidence: Optional dictionary of supplementary evidence from
                other BlueTrace modules or the caller. All keys are
                optional:

                * ``"local_relationship"``: a device-record dictionary
                  from :class:`modules.linux_artifacts.LinuxArtifactsCollector`.
                * ``"observations"``: a list of ``{"rssi": int,
                  "timestamp": str}`` dictionaries.
                * ``"ble_evidence"``: previously captured BLE
                  advertisement fields (see
                  :meth:`extract_ble_metadata`).
                * ``"source"``: ``{"type": ..., "reference": ...}``
                  describing where this analysis originated.
                * ``"observed_at"``: an ISO-8601 timestamp for when the
                  underlying evidence was actually observed.
                * ``"device_type"``: an explicitly reported device type
                  label.

        Returns:
            On success, a dictionary containing (among others) the keys
            ``"mac_address"``, ``"address_type"``, ``"name"``,
            ``"alias"``, ``"vendor"``, ``"device_class"``,
            ``"device_type"``, ``"rssi"``, ``"tx_power"``,
            ``"appearance"``, ``"service_uuids"``, ``"service_data"``,
            ``"manufacturer_data"``, ``"sdp_services"``,
            ``"local_relationship"``, ``"observation_statistics"``,
            ``"observed_at"``, ``"source"``, ``"field_classification"``,
            and ``"errors"``. On failure (invalid MAC address only), a
            dictionary with keys ``"mac_address"``, ``"error"``, and
            ``"message"``.
        """
        if not is_valid_mac_address(mac_address):
            self._logger.warning("Invalid MAC address supplied: %s", mac_address)
            return {
                "mac_address": mac_address,
                "error": "invalid_mac_address",
                "message": "The provided MAC address is not validly formatted.",
            }

        normalized_mac = normalize_mac_address(mac_address) or mac_address
        evidence = evidence if isinstance(evidence, dict) else {}

        command_name = BLUETOOTH_COMMANDS.get("bluetoothctl", "bluetoothctl")
        collected_errors: list[str] = []

        # _run_bluetoothctl_info already performs its own tool-availability
        # check; calling it directly (rather than duplicating that check
        # here) keeps this method consistent with every other collection
        # method and safe to exercise against a mocked/overridden
        # _run_bluetoothctl_info in tests.
        output, output_error = self._run_bluetoothctl_info(normalized_mac)

        if output_error:
            collected_errors.append(output_error)

        if output is not None:
            raw_name = self._extract_field(output, "Name:")
            raw_alias = self._extract_field(output, "Alias:")
            device_class_info = self.get_device_class(
                normalized_mac, precomputed_output=output
            )
            uuid_list = self.get_uuid_list(normalized_mac, precomputed_output=output)
            manufacturer_map = self.get_manufacturer_data_map(
                normalized_mac, precomputed_output=output
            )
            service_data = self.get_service_data(
                normalized_mac, precomputed_output=output
            )
            address_type = self.get_address_type(
                normalized_mac, precomputed_output=output
            )
            appearance = self.get_appearance(
                normalized_mac, precomputed_output=output
            )
            tx_power = self.get_tx_power(normalized_mac, precomputed_output=output)
            rssi_info = self.get_signal_information(
                normalized_mac, precomputed_output=output
            )
        else:
            raw_name = None
            raw_alias = None
            device_class_info = {
                "raw_class": None,
                "major_device_class": _UNKNOWN_VALUE,
                "error": output_error,
            }
            uuid_list = []
            manufacturer_map = {}
            service_data = {}
            address_type = _UNKNOWN_VALUE
            appearance = None
            tx_power = None
            rssi_info = {
                "rssi": None,
                "available": False,
                "note": f"Unavailable: {output_error}.",
            }

        vendor = self.get_vendor(normalized_mac)

        try:
            sdp_services = self.get_services(normalized_mac)
        except (OSError, subprocess.SubprocessError) as exc:
            self._logger.error(
                "Unexpected error while browsing SDP services on %s: %s",
                normalized_mac, exc,
            )
            sdp_services = []
            collected_errors.append("sdp_browse_error")

        # Resolve device name: observed name, then observed alias, then a
        # locally cached artifact name reported by other evidence -- never
        # invented, and always labeled with its true provenance.
        local_relationship_evidence = evidence.get("local_relationship")
        if raw_name:
            resolved_name, name_status = raw_name, _STATUS_OBSERVED
        elif raw_alias:
            resolved_name, name_status = raw_alias, _STATUS_OBSERVED
        else:
            artifact_name = None
            if isinstance(local_relationship_evidence, dict):
                candidate = local_relationship_evidence.get("name")
                if isinstance(candidate, str) and candidate and candidate != _UNKNOWN_VALUE:
                    artifact_name = candidate
            if artifact_name:
                resolved_name, name_status = artifact_name, _STATUS_REPORTED
            else:
                resolved_name, name_status = _UNKNOWN_VALUE, _STATUS_UNKNOWN

        # BLE metadata: merge live-observed fields with any explicitly
        # reported BLE evidence supplied by the caller.
        ble_metadata = self.extract_ble_metadata(
            normalized_mac,
            precomputed_output=output,
            ble_evidence=evidence.get("ble_evidence"),
        )
        # Prefer values already collected above (avoids redundant work);
        # extract_ble_metadata is authoritative for reported-field tracking.
        address_type = ble_metadata["address_type"] if ble_metadata["address_type"] != _UNKNOWN_VALUE else address_type
        appearance = ble_metadata["appearance"] or appearance
        tx_power = ble_metadata["tx_power"] if ble_metadata["tx_power"] is not None else tx_power
        service_uuids = ble_metadata["service_uuids"] or [entry["uuid"] for entry in uuid_list]
        service_data = ble_metadata["service_data"] or service_data
        manufacturer_map = ble_metadata["manufacturer_data"] or manufacturer_map
        ble_reported_fields = set(ble_metadata["reported_fields"])

        # Local relationship correlation (evidence-only; never inferred).
        local_relationship = self.build_local_relationship(local_relationship_evidence)

        # RSSI / signal observation statistics.
        observation_input = evidence.get("observations")
        if not observation_input and rssi_info.get("available"):
            observation_input = [
                {"rssi": rssi_info["rssi"], "timestamp": evidence.get("observed_at")}
            ]
        observation_stats = self.extract_observation_statistics(observation_input)

        # Device type: reported > derived from Class of Device > unknown.
        device_type_value, device_type_status = self._derive_device_type(
            device_class_info, evidence
        )

        # Provenance.
        source_info = evidence.get("source")
        if not isinstance(source_info, dict) or not source_info:
            if output is not None:
                source_info = {"type": "bluetoothctl_live_query", "reference": command_name}
            else:
                source_info = {"type": "unavailable", "reference": None}

        observed_at = evidence.get("observed_at")
        if not observed_at and output is not None:
            observed_at = current_datetime_iso()

        field_classification: dict[str, str] = {
            "mac_address": _STATUS_OBSERVED,
            "address_type": (
                _STATUS_REPORTED if "address_type" in ble_reported_fields
                else _STATUS_OBSERVED if address_type != _UNKNOWN_VALUE
                else _STATUS_UNKNOWN
            ),
            "name": name_status,
            "alias": _STATUS_OBSERVED if raw_alias else _STATUS_UNKNOWN,
            "vendor": _STATUS_DERIVED if vendor != _UNKNOWN_VALUE else _STATUS_UNKNOWN,
            "device_class": (
                _STATUS_DERIVED if device_class_info.get("raw_class") else _STATUS_UNKNOWN
            ),
            "device_type": device_type_status,
            "rssi": (
                _STATUS_OBSERVED
                if observation_stats.get("rssi_current") is not None
                else _STATUS_UNKNOWN
            ),
            "tx_power": (
                _STATUS_REPORTED if "tx_power" in ble_reported_fields
                else _STATUS_OBSERVED if tx_power is not None
                else _STATUS_UNKNOWN
            ),
            "appearance": (
                _STATUS_REPORTED if "appearance" in ble_reported_fields
                else _STATUS_OBSERVED if appearance
                else _STATUS_UNKNOWN
            ),
            "service_uuids": (
                _STATUS_REPORTED if "service_uuids" in ble_reported_fields
                else _STATUS_OBSERVED if service_uuids
                else _STATUS_UNKNOWN
            ),
            "service_data": (
                _STATUS_REPORTED if "service_data" in ble_reported_fields
                else _STATUS_OBSERVED if service_data
                else _STATUS_UNKNOWN
            ),
            "manufacturer_data": (
                _STATUS_REPORTED if "manufacturer_data" in ble_reported_fields
                else _STATUS_OBSERVED if manufacturer_map
                else _STATUS_UNKNOWN
            ),
            "sdp_services": _STATUS_OBSERVED if sdp_services else _STATUS_UNKNOWN,
            "local_relationship": (
                _STATUS_REPORTED if local_relationship.get("known") else _STATUS_UNKNOWN
            ),
        }

        return {
            "mac_address": normalized_mac,
            "address_type": address_type,
            "name": resolved_name,
            "alias": raw_alias,
            "vendor": vendor,
            "device_class": device_class_info.get("major_device_class", _UNKNOWN_VALUE),
            "device_type": device_type_value,
            "rssi": observation_stats.get("rssi_current"),
            "tx_power": tx_power,
            "appearance": appearance,
            "service_uuids": service_uuids,
            "service_data": service_data,
            "manufacturer_data": manufacturer_map,
            "sdp_services": sdp_services,
            "local_relationship": local_relationship,
            "observation_statistics": observation_stats,
            "observed_at": observed_at,
            "source": source_info,
            "field_classification": field_classification,
            "errors": collected_errors,
        }


__all__: Final[list[str]] = ["BluetoothAnalyzer"]
