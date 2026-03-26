"""
Android HCE Bridge — ADB-based APDU relay for GREENWIRE.

Works on both ROOTED and NON-ROOTED devices.

Non-rooted path (standard ADB):
  1. USB debugging enabled on device
  2. Deploy GreenwireHCEService.apk via  adb install
  3. adb forward tcp:7816 localabstract:greenwire-hce
  4. Tap device to NFC reader — APDUs flow through relay to HCEManager

Rooted path (additional capabilities):
  1. All of the above, plus:
  2. Toggle NFC on/off programmatically (no UI needed)
  3. Set default wallet role without user prompt
  4. Suppress payment confirmation dialogs
  5. Read/write to /system/prefs for persistent NFC config

APK source: java/hce/GreenwireHCEService.java
Build:      cd java/hce && ./gradlew assembleDebug
Output:     java/hce/app/build/outputs/apk/debug/app-debug.apk
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
APK_DEBUG = REPO_ROOT / "java" / "hce" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
APK_PREBUILT = REPO_ROOT / "static" / "android" / "greenwire-hce.apk"
HCE_PACKAGE = "com.greenwire.hce"
HCE_SERVICE = f"{HCE_PACKAGE}/.GreenwireHCEService"
RELAY_LOCAL_PORT = 7816
RELAY_ABSTRACT = "greenwire-hce"

# ---------------------------------------------------------------------------
# ADB device info
# ---------------------------------------------------------------------------

@dataclass
class AndroidDevice:
    serial: str
    model: str = ""
    android_version: str = ""
    api_level: int = 0
    rooted: bool = False
    nfc_available: bool = False
    hce_available: bool = False
    hce_apk_installed: bool = False
    relay_forwarded: bool = False


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------

class AndroidHCEBridge:
    """
    Manages the full lifecycle of the HCE relay:
      - Device detection
      - APK installation
      - ADB port forwarding
      - Root-specific helpers
    """

    def __init__(
        self,
        device_id: Optional[str] = None,
        relay_port: int = RELAY_LOCAL_PORT,
        verbose: bool = False,
    ) -> None:
        self.device_id = device_id
        self.relay_port = relay_port
        self.verbose = verbose
        self._device: Optional[AndroidDevice] = None

    # ------------------------------------------------------------------
    # Device discovery
    # ------------------------------------------------------------------

    def find_devices(self) -> List[str]:
        """Return list of connected ADB device serials."""
        out = self._adb_raw(["adb", "devices"])
        serials = []
        for line in out.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) == 2 and parts[1] == "device":
                serials.append(parts[0])
        return serials

    def probe_device(self, serial: Optional[str] = None) -> AndroidDevice:
        """Probe a device and return its capabilities."""
        if serial:
            self.device_id = serial
        if not self.device_id:
            devs = self.find_devices()
            if not devs:
                raise RuntimeError("No ADB devices found — check USB cable and USB debugging")
            self.device_id = devs[0]
            if len(devs) > 1:
                logger.warning("Multiple devices found, using %s", self.device_id)

        dev = AndroidDevice(serial=self.device_id)
        dev.model          = self._getprop("ro.product.model")
        dev.android_version= self._getprop("ro.build.version.release")
        try:
            dev.api_level  = int(self._getprop("ro.build.version.sdk"))
        except ValueError:
            dev.api_level  = 0

        dev.rooted         = self._check_root()
        dev.nfc_available  = self._check_nfc()
        dev.hce_available  = dev.api_level >= 19   # HCE requires API 19 (Android 4.4)
        dev.hce_apk_installed = self._is_apk_installed(HCE_PACKAGE)
        self._device = dev

        logger.info(
            "Device: %s | Android %s (API %d) | root=%s NFC=%s HCE=%s APK=%s",
            dev.model, dev.android_version, dev.api_level,
            dev.rooted, dev.nfc_available, dev.hce_available, dev.hce_apk_installed,
        )
        return dev

    # ------------------------------------------------------------------
    # APK management
    # ------------------------------------------------------------------

    def install_apk(self, apk_path: Optional[Path] = None, force: bool = False) -> bool:
        """Install GreenwireHCEService APK on the device."""
        if not apk_path:
            apk_path = APK_DEBUG if APK_DEBUG.exists() else APK_PREBUILT
        if not apk_path or not apk_path.exists():
            logger.error("HCE APK not found at %s — build it first: cd java/hce && ./gradlew assembleDebug", apk_path)
            return False

        if not force and self._device and self._device.hce_apk_installed:
            logger.info("HCE APK already installed — use force=True to reinstall")
            return True

        logger.info("Installing HCE APK from %s ...", apk_path)
        result = self._adb(["install", "-r", str(apk_path)])
        success = "Success" in result
        if success:
            logger.info("APK installed: %s", HCE_PACKAGE)
            if self._device:
                self._device.hce_apk_installed = True
        else:
            logger.error("APK install failed: %s", result)
        return success

    def uninstall_apk(self) -> bool:
        result = self._adb(["uninstall", HCE_PACKAGE])
        return "Success" in result

    # ------------------------------------------------------------------
    # Port forwarding
    # ------------------------------------------------------------------

    def setup_forward(self) -> bool:
        """
        Forward localhost:relay_port → device abstract socket :greenwire-hce.
        Works on both rooted and non-rooted devices.
        """
        result = self._adb(["forward", f"tcp:{self.relay_port}", f"localabstract:{RELAY_ABSTRACT}"])
        ok = result.strip() == str(self.relay_port) or result.strip() == ""
        if ok:
            logger.info("adb forward: tcp:%d → localabstract:%s", self.relay_port, RELAY_ABSTRACT)
            if self._device:
                self._device.relay_forwarded = True
        else:
            logger.error("adb forward failed: %s", result)
        return ok

    def remove_forward(self) -> None:
        self._adb(["forward", "--remove", f"tcp:{self.relay_port}"])

    # ------------------------------------------------------------------
    # NFC control
    # ------------------------------------------------------------------

    def enable_nfc(self) -> bool:
        """Enable NFC on device. Rooted: direct svc command. Non-rooted: UI intent."""
        if self._device and self._device.rooted:
            return self._enable_nfc_root()
        return self._enable_nfc_intent()

    def disable_nfc(self) -> bool:
        """Disable NFC (rooted only — non-rooted cannot disable programmatically)."""
        if self._device and self._device.rooted:
            result = self._adb_shell_su("svc nfc disable")
            return "Error" not in result
        logger.warning("Cannot disable NFC on non-rooted device — use device settings")
        return False

    def get_nfc_status(self) -> str:
        """Returns 'enabled', 'disabled', or 'unavailable'."""
        result = self._adb_shell("dumpsys nfc | grep -i 'mState\\|nfc state'")
        result_lower = result.lower()
        if "enabled" in result_lower:
            return "enabled"
        if "disabled" in result_lower:
            return "disabled"
        return "unavailable"

    # ------------------------------------------------------------------
    # Wallet role (default payment app)
    # ------------------------------------------------------------------

    def set_default_wallet(self) -> bool:
        """
        Set GreenwireHCEService as the default NFC payment handler.

        Rooted:     adb shell cmd nfc set-default-wallet-role ... (silent)
        Non-rooted: Opens system settings dialog — user must confirm.
        """
        if self._device and self._device.rooted:
            result = self._adb_shell_su(
                f"cmd nfc set-default-wallet-role {HCE_PACKAGE}"
            )
            ok = not result.strip() or "Error" not in result
            if ok:
                logger.info("Default wallet set to %s (root)", HCE_PACKAGE)
            return ok
        else:
            # Open the change-default-app dialog (non-rooted)
            self._adb_shell(
                f"am start -a android.settings.NFC_PAYMENT_SETTINGS"
            )
            logger.info(
                "Opened NFC payment settings — manually select GREENWIRE as default"
            )
            return True   # Dialog opened; user must confirm

    # ------------------------------------------------------------------
    # Service lifecycle
    # ------------------------------------------------------------------

    def start_hce_service(self) -> bool:
        """Start the HCE relay service on device."""
        result = self._adb_shell(
            f"am startservice -n {HCE_SERVICE} --es action start"
        )
        ok = "Error" not in result
        if ok:
            logger.info("HCE service started")
        else:
            logger.error("Failed to start HCE service: %s", result)
        return ok

    def stop_hce_service(self) -> bool:
        """Stop the HCE relay service."""
        result = self._adb_shell(f"am stopservice -n {HCE_SERVICE}")
        return "Error" not in result

    # ------------------------------------------------------------------
    # Full setup (one-shot)
    # ------------------------------------------------------------------

    def setup(self, apk_path: Optional[Path] = None) -> bool:
        """
        Full setup: probe → install APK → forward port → enable NFC → start service.
        Returns True if ready to receive APDUs.
        """
        if not self._device:
            try:
                self.probe_device()
            except RuntimeError as e:
                logger.error(str(e))
                return False

        if not self._device.hce_available:
            logger.error("Device API level %d does not support HCE (need 19+)", self._device.api_level)
            return False

        if not self._device.nfc_available:
            logger.error("Device does not have NFC hardware")
            return False

        steps = [
            ("Install APK",   lambda: self.install_apk(apk_path)),
            ("Port forward",  self.setup_forward),
            ("Enable NFC",    self.enable_nfc),
            ("Start service", self.start_hce_service),
        ]
        for name, fn in steps:
            logger.info("Setup: %s ...", name)
            if not fn():
                logger.error("Setup failed at: %s", name)
                return False

        if self._device.rooted:
            self.set_default_wallet()

        logger.info("HCE bridge ready on port %d — tap device to NFC reader", self.relay_port)
        return True

    def teardown(self) -> None:
        """Graceful teardown."""
        self.stop_hce_service()
        self.remove_forward()
        logger.info("HCE bridge torn down")

    # ------------------------------------------------------------------
    # Root helpers
    # ------------------------------------------------------------------

    def _enable_nfc_root(self) -> bool:
        result = self._adb_shell_su("svc nfc enable")
        time.sleep(1)
        return "Error" not in result

    def _enable_nfc_intent(self) -> bool:
        """Non-rooted: open NFC settings page and inform user."""
        self._adb_shell("am start -a android.settings.NFC_SETTINGS")
        logger.info("NFC settings opened — enable NFC manually if not already on")
        # Give it a moment and check
        time.sleep(2)
        return self.get_nfc_status() == "enabled"

    # ------------------------------------------------------------------
    # Device info helpers
    # ------------------------------------------------------------------

    def _check_root(self) -> bool:
        """Check if device is rooted (su available)."""
        out = self._adb_shell("which su 2>/dev/null || su -c id 2>&1")
        return bool(out.strip()) and "not found" not in out.lower()

    def _check_nfc(self) -> bool:
        out = self._adb_shell("pm list features | grep -i nfc")
        return "android.hardware.nfc" in out.lower()

    def _is_apk_installed(self, package: str) -> bool:
        out = self._adb_shell(f"pm list packages {package}")
        return package in out

    def _getprop(self, key: str) -> str:
        return self._adb_shell(f"getprop {key}").strip()

    # ------------------------------------------------------------------
    # ADB command wrappers
    # ------------------------------------------------------------------

    def _adb_args(self) -> List[str]:
        if self.device_id:
            return ["adb", "-s", self.device_id]
        return ["adb"]

    def _adb(self, args: List[str], timeout: int = 30) -> str:
        cmd = self._adb_args() + args
        if self.verbose:
            logger.debug("ADB: %s", " ".join(cmd))
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except FileNotFoundError:
            return "ERROR: adb not found in PATH"

    def _adb_shell(self, shell_cmd: str, timeout: int = 15) -> str:
        return self._adb(["shell", shell_cmd], timeout=timeout)

    def _adb_shell_su(self, shell_cmd: str) -> str:
        """Run shell command with su (rooted devices only)."""
        return self._adb_shell(f"su -c '{shell_cmd}'")

    def _adb_raw(self, cmd: List[str], timeout: int = 10) -> str:
        if self.verbose:
            logger.debug("RAW: %s", " ".join(cmd))
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout
        except subprocess.TimeoutExpired:
            return ""
        except FileNotFoundError:
            return ""


# ---------------------------------------------------------------------------
# Convenience: full pipeline startup
# ---------------------------------------------------------------------------

def start_hce_pipeline(
    device_id: Optional[str] = None,
    scheme: str = "visa",
    fpan: Optional[str] = None,
    expiry: str = "2512",
    mock_tsp: bool = True,
    verbose: bool = True,
) -> Tuple[AndroidHCEBridge, "HCEManager", object]:
    """
    One-call setup: probe device → provision token → set up relay → return
    (bridge, hce_manager, token_record) ready for NFC transactions.

    Works on rooted AND non-rooted devices.

    Returns:
        bridge       — AndroidHCEBridge (controls device)
        hce_manager  — HCEManager (processes APDUs)
        token_record — TokenRecord (DPAN + LUKs)
    """
    from modules.tsp_integration import make_tsp_client, DeviceInfo, VISA_TEST_PANS, MC_TEST_PANS
    from modules.hce_manager import HCEManager

    bridge = AndroidHCEBridge(device_id=device_id, verbose=verbose)
    dev = bridge.probe_device()

    tsp = make_tsp_client(scheme=scheme, mock_mode=mock_tsp)
    test_pan = (VISA_TEST_PANS["visa_credit"] if scheme == "visa" else MC_TEST_PANS["mc_credit"])
    pan = fpan or test_pan
    device_info = DeviceInfo(device_id=dev.serial, device_name=dev.model)
    token = tsp.provision_token(fpan=pan, expiry=expiry, cvv2="737", device=device_info)

    hce = HCEManager(
        device_id=dev.serial,
        relay_port=bridge.relay_port,
        tsp_client=tsp,
        scheme=scheme,
        verbose=verbose,
    )
    hce.load_token(token)

    if not bridge.setup():
        logger.warning("Bridge setup incomplete — relay may not be ready")

    return bridge, hce, token


__all__ = ["AndroidHCEBridge", "AndroidDevice", "start_hce_pipeline"]
