"""
modules/scanner.py
===================

Bluetooth device discovery module for **BlueTrace Forensic Suite**.

This module contains the :class:`BluetoothScanner` class, whose sole
responsibility is to discover nearby Bluetooth Classic and Bluetooth Low
Energy (BLE) devices on a Linux host and return the results as clean,
structured Python objects.

It intentionally contains **no report generation**, **no GATT/characteristic
reading**, **no packet capture**, **no pairing or connection logic**, and
**no forensic analysis**. Those responsibilities belong to dedicated
modules elsewhere in the framework. This module only discovers devices and
hands back plain data for downstream analyzer modules to consume.

BlueTrace Forensic Suite is a defensive, forensic-oriented tool intended
for lawful digital forensics and incident-response use cases involving
Bluetooth Classic and BLE devices on Linux.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import subprocess
from typing import Any, Final

from bleak import BleakScanner
from bleak.exc import BleakError

from config import (
    BLUETOOTH_COMMANDS,
    DEFAULT_BLE_SCAN_TIMEOUT_SECONDS,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    LOG_LEVEL,
    MAX_RETRIES,
)
from modules.utils import command_exists, normalize_mac_address

# --------------------------------------------------------------------------- #
# Module-level constants
# --------------------------------------------------------------------------- #

#: Names of the external tools required for Bluetooth Classic discovery and
#: adapter inspection, checked via :func:`modules.utils.command_exists`.
_REQUIRED_TOOLS: Final[tuple[str, ...]] = (
    "bluetoothctl",
    "btmgmt",
    "hciconfig",
)

#: Device dictionary value used when a discovered device advertises no
#: usable name.
_UNKNOWN_DEVICE_NAME: Final[str] = "Unknown"

#: Sentinel RSSI value used to sort devices with no known signal strength
#: to the end of a signal-sorted list.
_UNKNOWN_RSSI_SORT_VALUE: Final[int] = -999


class BluetoothScanner:
    """Discover nearby Bluetooth Classic and BLE devices on Linux.

    This class wraps the external ``bluetoothctl``/``hciconfig`` command-line
    tools (for Bluetooth Classic discovery and adapter inspection) and the
    :mod:`bleak` library (for BLE discovery), and normalizes their output
    into a common, structured device format suitable for consumption by the
    forensic analyzer module. No device pairing, connection, GATT reading,
    or evidence collection is performed here.
    """

    def __init__(
        self,
        ble_timeout: int = DEFAULT_BLE_SCAN_TIMEOUT_SECONDS,
        classic_timeout: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
        max_retries: int = MAX_RETRIES,
    ) -> None:
        """Initialize the scanner's logger and operational configuration.

        Args:
            ble_timeout: Default timeout, in seconds, for BLE scans.
                Defaults to :data:`config.DEFAULT_BLE_SCAN_TIMEOUT_SECONDS`.
            classic_timeout: Default timeout, in seconds, for Bluetooth
                Classic scans. Defaults to
                :data:`config.DEFAULT_SCAN_TIMEOUT_SECONDS`.
            max_retries: Maximum number of retry attempts for a failed
                acquisition operation. Defaults to :data:`config.MAX_RETRIES`.
        """
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

        self._ble_timeout = ble_timeout
        self._classic_timeout = classic_timeout
        self._max_retries = max_retries

    # ----------------------------------------------------------------- #
    # Environment checks
    # ----------------------------------------------------------------- #

    def check_linux(self) -> bool:
        """Verify that the current operating system is Linux.

        Returns:
            ``True`` if the host operating system is Linux, ``False``
            otherwise.
        """
        is_linux = platform.system() == "Linux"
        if not is_linux:
            self._logger.warning(
                "Unsupported operating system detected: %s", platform.system()
            )
        return is_linux

    def check_bluetooth_tools(self) -> list[str]:
        """Verify that the required Linux Bluetooth command-line tools exist.

        Checks for the presence of ``bluetoothctl``, ``btmgmt``, and
        ``hciconfig`` on the system ``PATH`` using
        :func:`modules.utils.command_exists`.

        Returns:
            A list of tool names from :data:`BLUETOOTH_COMMANDS` that are
            required but not found on the system ``PATH``. An empty list
            indicates all required tools are available.
        """
        missing_tools: list[str] = []
        for tool_key in _REQUIRED_TOOLS:
            command_name = BLUETOOTH_COMMANDS.get(tool_key, tool_key)
            if not command_exists(command_name):
                missing_tools.append(command_name)

        if missing_tools:
            self._logger.warning(
                "Missing required Bluetooth tools: %s", ", ".join(missing_tools)
            )
        return missing_tools

    def check_adapter(self) -> dict[str, Any]:
        """Detect the local Bluetooth adapter and its current status.

        Invokes ``bluetoothctl show`` to collect the adapter name, powered
        state, and general status. Never crashes: all failure modes (no
        adapter, Bluetooth service off, tool missing, permission denied)
        are captured and returned as a structured, meaningful error.

        Returns:
            A dictionary with the following keys:
            ``"adapter_present"`` (bool), ``"name"`` (str or ``None``),
            ``"powered"`` (bool or ``None``), ``"status"`` (str), and
            ``"error"`` (str or ``None``).
        """
        result: dict[str, Any] = {
            "adapter_present": False,
            "name": None,
            "powered": None,
            "status": "unknown",
            "error": None,
        }

        command_name = BLUETOOTH_COMMANDS.get("bluetoothctl", "bluetoothctl")
        if not command_exists(command_name):
            result["status"] = "tool_missing"
            result["error"] = f"Required tool not found: {command_name}"
            self._logger.warning(result["error"])
            return result

        try:
            completed = subprocess.run(
                [command_name, "show"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except FileNotFoundError:
            result["status"] = "tool_missing"
            result["error"] = f"Required tool not found: {command_name}"
            self._logger.warning(result["error"])
            return result
        except PermissionError:
            result["status"] = "permission_denied"
            result["error"] = "Permission denied while accessing Bluetooth adapter."
            self._logger.error(result["error"])
            return result
        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            result["error"] = "Timed out while querying the Bluetooth adapter."
            self._logger.error(result["error"])
            return result

        output = completed.stdout or ""
        if "No default controller available" in output or not output.strip():
            result["status"] = "no_adapter"
            result["error"] = "No Bluetooth adapter detected."
            self._logger.warning(result["error"])
            return result

        for line in output.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("Name:") and result["name"] is None:
                result["name"] = stripped_line.split(":", 1)[1].strip()
            elif stripped_line.startswith("Powered:"):
                result["powered"] = stripped_line.split(":", 1)[1].strip().lower() == "yes"

        result["adapter_present"] = True
        result["status"] = "ok" if result["powered"] else "powered_off"
        if not result["powered"]:
            self._logger.warning("Bluetooth adapter detected but not powered on.")
        return result

    # ----------------------------------------------------------------- #
    # Discovery
    # ----------------------------------------------------------------- #

    async def scan_ble(self, timeout: int | None = None) -> list[dict[str, Any]]:
        """Discover nearby BLE devices using :mod:`bleak`.

        Implementation note: this method deliberately avoids the
        ``BleakScanner.discover(..., return_adv=True)`` convenience
        classmethod. On some BlueZ/D-Bus configurations that call has been
        observed to hang indefinitely (e.g. if the adapter is already in a
        discovering state, or a D-Bus signal is dropped), because its
        internal ``start()``/``stop()`` calls are not bounded by any
        timeout of their own. Instead, a :class:`BleakScanner` instance is
        driven manually as an async context manager for exactly
        ``scan_timeout`` seconds, and that whole operation is wrapped in
        :func:`asyncio.wait_for` with a hard ceiling so a stuck ``start()``
        or ``stop()`` call can never block the rest of the program.
        Discovered devices (with advertisement data) are then read from the
        scanner's ``discovered_devices_and_advertisement_data`` property,
        which is the modern, non-deprecated equivalent of ``return_adv``.

        Args:
            timeout: Scan duration in seconds. Defaults to the scanner's
                configured BLE timeout.

        Returns:
            A list of dictionaries, each with keys ``"name"``, ``"mac"``,
            ``"rssi"``, and ``"type"`` (always ``"BLE"``). Returns an empty
            list if the scan fails for any reason (Bluetooth off, no
            adapter, permission denied, etc.); the failure is logged but
            never raised.
        """
        scan_timeout = timeout if timeout is not None else self._ble_timeout
        # Hard ceiling on top of the requested scan duration itself, so
        # that a start()/stop() call stuck on D-Bus cannot hang forever.
        hard_timeout = scan_timeout + 10

        devices: list[dict[str, Any]] = []
        scanner = BleakScanner()

        async def _run_scan() -> None:
            async with scanner:
                await asyncio.sleep(scan_timeout)

        try:
            await asyncio.wait_for(_run_scan(), timeout=hard_timeout)
        except asyncio.TimeoutError:
            self._logger.error(
                "BLE scan did not finish within %d second(s); returning "
                "whatever devices were discovered so far.",
                hard_timeout,
            )
            # Best-effort cleanup: try to stop the scanner so the adapter
            # isn't left in a stuck discovering state. Bounded by its own
            # short timeout so this can never itself hang the program.
            try:
                await asyncio.wait_for(scanner.stop(), timeout=5)
            except Exception:  # noqa: BLE001 - cleanup must never raise
                pass
        except BleakError as exc:
            self._logger.error("BLE scan failed: %s", exc)
            return []
        except PermissionError:
            self._logger.error("Permission denied while performing BLE scan.")
            return []
        except OSError as exc:
            self._logger.error("BLE scan failed due to a system error: %s", exc)
            return []
        except Exception as exc:  # noqa: BLE001 - never let BLE scanning crash the app
            self._logger.error("Unexpected error during BLE scan: %s", exc)
            return []

        discovered = scanner.discovered_devices_and_advertisement_data

        for address, discovery in discovered.items():
            device, advertisement = discovery
            name = device.name or _UNKNOWN_DEVICE_NAME
            mac = normalize_mac_address(address) or address
            rssi = getattr(advertisement, "rssi", None)
            devices.append(
                {
                    "name": name,
                    "mac": mac,
                    "rssi": rssi,
                    "type": "BLE",
                }
            )

        self._logger.info("BLE scan discovered %d device(s).", len(devices))
        return devices

    def scan_classic(self, timeout: int | None = None) -> list[dict[str, Any]]:
        """Discover nearby Bluetooth Classic devices using ``bluetoothctl``.

        Runs a timed ``bluetoothctl`` discovery session and then lists the
        devices known to the adapter as a result. Never crashes: all
        failure modes are logged and result in an empty list.

        Args:
            timeout: Scan duration in seconds. Defaults to the scanner's
                configured Classic timeout.

        Returns:
            A list of dictionaries, each with keys ``"name"``, ``"mac"``,
            and ``"type"`` (always ``"Classic"``).
        """
        scan_timeout = timeout if timeout is not None else self._classic_timeout
        command_name = BLUETOOTH_COMMANDS.get("bluetoothctl", "bluetoothctl")

        if not command_exists(command_name):
            self._logger.warning("Required tool not found: %s", command_name)
            return []

        try:
            subprocess.run(
                [command_name, "--timeout", str(scan_timeout), "scan", "on"],
                capture_output=True,
                text=True,
                timeout=scan_timeout + 10,
                check=False,
            )
            completed = subprocess.run(
                [command_name, "devices"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except FileNotFoundError:
            self._logger.warning("Required tool not found: %s", command_name)
            return []
        except PermissionError:
            self._logger.error("Permission denied while performing Classic scan.")
            return []
        except subprocess.TimeoutExpired:
            self._logger.error("Classic scan timed out.")
            return []

        devices: list[dict[str, Any]] = []
        for line in (completed.stdout or "").splitlines():
            stripped_line = line.strip()
            if not stripped_line.startswith("Device "):
                continue
            parts = stripped_line.split(" ", 2)
            if len(parts) < 2:
                continue
            raw_mac = parts[1]
            name = parts[2].strip() if len(parts) == 3 else _UNKNOWN_DEVICE_NAME
            mac = normalize_mac_address(raw_mac) or raw_mac
            devices.append(
                {
                    "name": name or _UNKNOWN_DEVICE_NAME,
                    "mac": mac,
                    "type": "Classic",
                }
            )

        self._logger.info("Classic scan discovered %d device(s).", len(devices))
        return devices

    # ----------------------------------------------------------------- #
    # Result processing
    # ----------------------------------------------------------------- #

    def filter_duplicates(
        self, devices: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Remove duplicate devices from a device list based on MAC address.

        The first occurrence of each MAC address is kept; subsequent
        entries with the same (normalized) MAC address are discarded.

        Args:
            devices: A list of device dictionaries, each expected to
                contain a ``"mac"`` key.

        Returns:
            A new list of device dictionaries with duplicate MAC addresses
            removed, preserving the original order.
        """
        seen_macs: set[str] = set()
        unique_devices: list[dict[str, Any]] = []

        for device in devices:
            mac = str(device.get("mac", "")).upper()
            if not mac or mac in seen_macs:
                continue
            seen_macs.add(mac)
            unique_devices.append(device)

        return unique_devices

    def sort_by_signal(
        self, devices: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Sort a list of devices by RSSI in descending order (strongest first).

        Devices without a known RSSI value (e.g. Bluetooth Classic devices)
        are sorted to the end of the list.

        Args:
            devices: A list of device dictionaries, optionally containing
                an ``"rssi"`` key.

        Returns:
            A new, sorted list of device dictionaries.
        """
        def sort_key(device: dict[str, Any]) -> int | float:
            rssi = device.get("rssi")
            if isinstance(rssi, (int, float)) and not isinstance(rssi, bool):
                return rssi
            return _UNKNOWN_RSSI_SORT_VALUE

        return sorted(devices, key=sort_key, reverse=True)

    # ----------------------------------------------------------------- #
    # Orchestration
    # ----------------------------------------------------------------- #

    async def scan(self) -> list[dict[str, Any]]:
        """Run both BLE and Classic scans and return a merged device list.

        Executes :meth:`scan_ble` and :meth:`scan_classic` (the latter via
        a worker thread, since it is a blocking call), merges their
        results, removes duplicate MAC addresses, and sorts the combined
        list by signal strength.

        Returns:
            A clean, structured list of discovered device dictionaries,
            e.g.::

                [
                    {
                        "name": "Galaxy Watch",
                        "mac": "AA:BB:CC:DD:EE:FF",
                        "type": "BLE",
                        "rssi": -51,
                    }
                ]

            Returns an empty list if both scans fail; individual scan
            failures are logged but never raised.
        """
        if not self.check_linux():
            self._logger.error("Bluetooth scanning is only supported on Linux.")
            return []

        missing_tools = self.check_bluetooth_tools()
        if missing_tools:
            self._logger.warning(
                "Continuing with limited functionality; missing tools: %s",
                ", ".join(missing_tools),
            )

        ble_devices, classic_devices = await asyncio.gather(
            self.scan_ble(),
            asyncio.to_thread(self.scan_classic),
        )

        merged_devices = [*ble_devices, *classic_devices]
        deduplicated_devices = self.filter_duplicates(merged_devices)
        return self.sort_by_signal(deduplicated_devices)

    def get_statistics(self, devices: list[dict[str, Any]]) -> dict[str, int]:
        """Summarize a device list into aggregate discovery statistics.

        Args:
            devices: A list of device dictionaries, each expected to
                contain a ``"type"`` key of ``"BLE"``, ``"Classic"``, or
                an unrecognized value.

        Returns:
            A dictionary with the keys ``"total_devices"``,
            ``"ble_devices"``, ``"classic_devices"``, and
            ``"unknown_devices"``.
        """
        total_devices = len(devices)
        ble_devices = sum(1 for device in devices if device.get("type") == "BLE")
        classic_devices = sum(
            1 for device in devices if device.get("type") == "Classic"
        )
        unknown_devices = total_devices - ble_devices - classic_devices

        return {
            "total_devices": total_devices,
            "ble_devices": ble_devices,
            "classic_devices": classic_devices,
            "unknown_devices": unknown_devices,
        }


__all__: Final[list[str]] = ["BluetoothScanner"]
