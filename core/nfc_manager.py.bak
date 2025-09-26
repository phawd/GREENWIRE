#!/usr/bin/env python3
"""
GREENWIRE Unified NFC Device Manager
Combines NFCDaemon and AndroidNFCVerifier functionality into a single, coherent system
"""

import subprocess
import threading
import time
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from core.logging_system import get_logger, handle_errors, log_operation, track_operation
from core.config import get_config

@dataclass
class NFCDevice:
    """Unified representation of an NFC device."""
    device_id: str
    device_type: str  # 'android', 'hardware', 'pcsc'
    name: str
    status: str  # 'available', 'unavailable', 'unknown'
    capabilities: Dict[str, Any]
    connection_info: Dict[str, Any]

class UnifiedNFCManager:
    """
    Unified NFC device management combining Android and hardware NFC operations.
    Replaces both NFCDaemon and AndroidNFCVerifier with a single, coherent system.
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        self.devices = {}
        self.listeners = {}
        self.running = False
        self.scan_thread = None
        
        # Android-specific setup
        self.adb_available = self._check_adb_availability()
        self.android_devices = []
        
        # Hardware NFC setup
        self.hardware_available = self._check_hardware_availability()
        self.hardware_devices = []
        
        self.logger.info("UnifiedNFCManager initialized", "NFC_INIT")
    
    @handle_errors("ADB availability check", return_on_error=False)
    def _check_adb_availability(self) -> bool:
        """Check if ADB is available in system PATH."""
        try:
            result = subprocess.run(['adb', 'version'], capture_output=True, text=True, timeout=5)
            available = result.returncode == 0
            self.logger.debug(f"ADB availability: {available}", "ADB_CHECK")
            return available
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.debug("ADB not available", "ADB_CHECK")
            return False
    
    @handle_errors("Hardware NFC availability check", return_on_error=False)
    def _check_hardware_availability(self) -> bool:
        """Check if hardware NFC readers are available."""
        try:
            # Try to import smartcard modules
            from smartcard.System import readers
            available_readers = readers()
            available = len(available_readers) > 0
            self.logger.debug(f"Hardware NFC readers: {len(available_readers) if available else 0}", "HW_NFC_CHECK")
            return available
        except ImportError:
            self.logger.debug("pyscard not available for hardware NFC", "HW_NFC_CHECK")
            return False
        except Exception as e:
            self.logger.debug(f"Hardware NFC check failed: {e}", "HW_NFC_CHECK")
            return False
    
    @handle_errors("Android device scan", return_on_error=[])
    def scan_android_devices(self) -> List[NFCDevice]:
        """Scan for connected Android devices via ADB."""
        if not self.adb_available:
            self.logger.debug("ADB not available - skipping Android device scan", "ANDROID_SCAN")
            return []
        
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.logger.warning("ADB devices command failed", "ANDROID_SCAN")
                return []
            
            devices = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                if '\tdevice' in line:
                    device_id = line.split('\t')[0]
                    nfc_device = self._create_android_nfc_device(device_id)
                    if nfc_device:
                        devices.append(nfc_device)
            
            self.android_devices = devices
            self.logger.info(f"Found {len(devices)} Android devices", "ANDROID_SCAN")
            return devices
            
        except subprocess.TimeoutExpired:
            self.logger.error("Android device scan timed out", "ANDROID_SCAN")
            return []
        except Exception as e:
            self.logger.error(f"Android device scan failed: {e}", "ANDROID_SCAN")
            return []
    
    @handle_errors("Android NFC device creation", return_on_error=None)
    def _create_android_nfc_device(self, device_id: str) -> Optional[NFCDevice]:
        """Create NFCDevice object for Android device with NFC capability check."""
        try:
            # Get device info
            model_result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', 'ro.product.model'],
                                        capture_output=True, text=True, timeout=5)
            brand_result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', 'ro.product.brand'],
                                        capture_output=True, text=True, timeout=5)
            
            model = model_result.stdout.strip() if model_result.returncode == 0 else "Unknown"
            brand = brand_result.stdout.strip() if brand_result.returncode == 0 else "Unknown"
            name = f"{brand} {model}"
            
            # Check NFC capabilities
            capabilities = self._check_android_nfc_capability(device_id)
            status = capabilities.get('status', 'unknown')
            
            return NFCDevice(
                device_id=device_id,
                device_type='android',
                name=name,
                status=status,
                capabilities=capabilities,
                connection_info={'adb_id': device_id, 'brand': brand, 'model': model}
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to create Android NFC device for {device_id}: {e}", "ANDROID_DEVICE")
            return None
    
    @handle_errors("Android NFC capability check", return_on_error={'status': 'unknown'})
    def _check_android_nfc_capability(self, device_id: str) -> Dict[str, Any]:
        """Check NFC capabilities of Android device."""
        capabilities = {
            'has_nfc_feature': False,
            'nfc_enabled': False,
            'status': 'unknown'
        }
        
        try:
            # Check NFC feature
            nfc_feature_result = subprocess.run([
                'adb', '-s', device_id, 'shell', 'pm', 'list', 'features'
            ], capture_output=True, text=True, timeout=10)
            
            if nfc_feature_result.returncode == 0:
                capabilities['has_nfc_feature'] = 'android.hardware.nfc' in nfc_feature_result.stdout
            
            # Check NFC enabled status
            nfc_enabled_result = subprocess.run([
                'adb', '-s', device_id, 'shell', 'settings', 'get', 'secure', 'nfc_enabled'
            ], capture_output=True, text=True, timeout=10)
            
            if nfc_enabled_result.returncode == 0:
                enabled_value = nfc_enabled_result.stdout.strip()
                capabilities['nfc_enabled'] = enabled_value == '1'
            
            # Determine overall status
            if capabilities['has_nfc_feature'] and capabilities['nfc_enabled']:
                capabilities['status'] = 'available'
            elif capabilities['has_nfc_feature'] and not capabilities['nfc_enabled']:
                capabilities['status'] = 'disabled'
            else:
                capabilities['status'] = 'unavailable'
            
            return capabilities
            
        except Exception as e:
            self.logger.debug(f"NFC capability check failed for {device_id}: {e}", "NFC_CAPABILITY")
            return capabilities
    
    @handle_errors("Hardware NFC device scan", return_on_error=[])
    def scan_hardware_devices(self) -> List[NFCDevice]:
        """Scan for hardware NFC devices."""
        if not self.hardware_available:
            self.logger.debug("Hardware NFC not available - skipping scan", "HW_NFC_SCAN")
            return []
        
        try:
            from smartcard.System import readers
            from smartcard.CardType import AnyCardType
            from smartcard.CardRequest import CardRequest
            
            available_readers = readers()
            devices = []
            
            for i, reader in enumerate(available_readers):
                device_id = f"pcsc_{i}"
                capabilities = {
                    'reader_name': str(reader),
                    'status': 'available',
                    'supports_card_detection': True
                }
                
                nfc_device = NFCDevice(
                    device_id=device_id,
                    device_type='pcsc',
                    name=str(reader),
                    status='available',
                    capabilities=capabilities,
                    connection_info={'reader': reader, 'index': i}
                )
                devices.append(nfc_device)
            
            self.hardware_devices = devices
            self.logger.info(f"Found {len(devices)} hardware NFC devices", "HW_NFC_SCAN")
            return devices
            
        except Exception as e:
            self.logger.error(f"Hardware NFC scan failed: {e}", "HW_NFC_SCAN")
            return []
    
    @log_operation("Complete device scan")
    def scan_all_devices(self) -> List[NFCDevice]:
        """Scan for all available NFC devices (Android + Hardware)."""
        all_devices = []
        
        if self.config.nfc.use_android:
            android_devices = self.scan_android_devices()
            all_devices.extend(android_devices)
        
        if self.config.nfc.use_hardware:
            hardware_devices = self.scan_hardware_devices()
            all_devices.extend(hardware_devices)
        
        # Update internal device registry
        self.devices.clear()
        for device in all_devices:
            self.devices[device.device_id] = device
        
        self.logger.info(f"Total NFC devices found: {len(all_devices)}", "DEVICE_SCAN")
        return all_devices
    
    def get_device(self, device_id: str) -> Optional[NFCDevice]:
        """Get device by ID."""
        return self.devices.get(device_id)
    
    def get_devices_by_type(self, device_type: str) -> List[NFCDevice]:
        """Get all devices of specified type."""
        return [device for device in self.devices.values() if device.device_type == device_type]
    
    def get_available_devices(self) -> List[NFCDevice]:
        """Get all available devices."""
        return [device for device in self.devices.values() if device.status == 'available']
    
    @handle_errors("Android NFC enablement", return_on_error={'success': False, 'error': 'Operation failed'})
    def enable_android_nfc(self, device_id: str, use_apk: bool = False) -> Dict[str, Any]:
        """Enable NFC on Android device using ADB commands (and optionally APK)."""
        if not self.adb_available:
            return {'success': False, 'error': 'ADB not available'}
        
        device = self.get_device(device_id)
        if not device or device.device_type != 'android':
            return {'success': False, 'error': 'Invalid Android device'}
        
        # Use the existing enablement logic
        return self._execute_android_nfc_enablement(device_id, use_apk)
    
    @track_operation("Android NFC Enable")
    def _execute_android_nfc_enablement(self, device_id: str, use_apk: bool) -> Dict[str, Any]:
        """Execute Android NFC enablement with comprehensive ADB commands."""
        results = []
        
        # Settings database commands
        settings_cmds = [
            (['shell', 'settings', 'put', 'secure', 'nfc_enabled', '1'], 'Set secure NFC enabled'),
            (['shell', 'settings', 'put', 'global', 'nfc_enabled', '1'], 'Set global NFC enabled'),
            (['shell', 'settings', 'put', 'secure', 'nfc_always_on', '1'], 'Set NFC always on'),
            (['shell', 'settings', 'put', 'global', 'android_beam_on', '1'], 'Set Android Beam on'),
        ]
        
        for cmd_args, description in settings_cmds:
            success = self._run_adb_command(device_id, cmd_args, description)
            results.append({'method': description, 'success': success})
        
        # Service commands
        service_cmds = [
            (['shell', 'service', 'call', 'nfc', '6'], 'NFC service enable call'),
            (['shell', 'svc', 'nfc', 'enable'], 'SVC NFC enable'),
        ]
        
        for cmd_args, description in service_cmds:
            success = self._run_adb_command(device_id, cmd_args, description)
            results.append({'method': description, 'success': success})
        
        # Root commands (may fail if not rooted)
        root_cmds = [
            (['shell', 'su', '-c', 'settings put secure nfc_enabled 1'], 'Root: Set secure NFC'),
            (['shell', 'su', '-c', 'settings put global nfc_enabled 1'], 'Root: Set global NFC'),
            (['shell', 'su', '-c', 'service call nfc 6'], 'Root: NFC service call'),
        ]
        
        for cmd_args, description in root_cmds:
            success = self._run_adb_command(device_id, cmd_args, description)
            results.append({'method': description, 'success': success})
        
        # Service restart
        restart_cmds = [
            (['shell', 'am', 'force-stop', 'com.android.nfc'], 'Stop NFC app'),
            (['shell', 'am', 'broadcast', '-a', 'android.intent.action.NFC_STATE_CHANGED'], 'Broadcast NFC change'),
        ]
        
        for cmd_args, description in restart_cmds:
            success = self._run_adb_command(device_id, cmd_args, description)
            results.append({'method': description, 'success': success})
        
        # Wait for changes to take effect
        time.sleep(3)
        
        # Verify final status
        final_capabilities = self._check_android_nfc_capability(device_id)
        success_count = sum(1 for r in results if r['success'])
        
        return {
            'success': final_capabilities.get('nfc_enabled', False),
            'methods_attempted': len(results),
            'methods_successful': success_count,
            'results': results,
            'final_status': final_capabilities
        }
    
    @handle_errors("ADB command execution", return_on_error=False)
    def _run_adb_command(self, device_id: str, cmd_args: List[str], description: str) -> bool:
        """Run ADB command and return success status."""
        try:
            full_cmd = ['adb', '-s', device_id] + cmd_args
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=15)
            success = result.returncode == 0
            self.logger.debug(f"{description}: {'✅' if success else '❌'}", "ADB_CMD")
            return success
        except Exception as e:
            self.logger.debug(f"{description} failed: {e}", "ADB_CMD")
            return False
    
    def start_continuous_monitoring(self):
        """Start continuous device monitoring in background thread."""
        if self.running:
            self.logger.warning("Continuous monitoring already running", "MONITORING")
            return
        
        self.running = True
        self.scan_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.scan_thread.start()
        self.logger.info("Started continuous NFC device monitoring", "MONITORING")
    
    def stop_continuous_monitoring(self):
        """Stop continuous device monitoring."""
        self.running = False
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        self.logger.info("Stopped continuous NFC device monitoring", "MONITORING")
    
    def _monitoring_loop(self):
        """Background monitoring loop."""
        while self.running:
            try:
                # Rescan devices periodically
                self.scan_all_devices()
                
                # Log device status changes
                available_count = len(self.get_available_devices())
                self.logger.debug(f"Monitoring: {available_count} devices available", "MONITORING")
                
                # Wait before next scan
                time.sleep(self.config.nfc.timeout)
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}", "MONITORING")
                time.sleep(5)  # Wait before retrying
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get comprehensive status summary."""
        android_devices = self.get_devices_by_type('android')
        hardware_devices = self.get_devices_by_type('pcsc')
        available_devices = self.get_available_devices()
        
        return {
            'total_devices': len(self.devices),
            'android_devices': len(android_devices),
            'hardware_devices': len(hardware_devices),
            'available_devices': len(available_devices),
            'adb_available': self.adb_available,
            'hardware_available': self.hardware_available,
            'monitoring_active': self.running,
            'devices': {device.device_id: {
                'name': device.name,
                'type': device.device_type,
                'status': device.status
            } for device in self.devices.values()}
        }

# Global NFC manager instance
_nfc_manager = None

def get_nfc_manager() -> UnifiedNFCManager:
    """Get the global NFC manager instance."""
    global _nfc_manager
    if _nfc_manager is None:
        _nfc_manager = UnifiedNFCManager()
    return _nfc_manager