"""
GREENWIRE Android/ADB Integration Manager
Handles Android device management, ADB command execution, and NFC enablement.
"""

import subprocess
import threading
import time
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

from .logging_system import get_logger, handle_errors
from .config import get_config

class AndroidManager:
    """Manages Android device interactions via ADB."""
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        self.adb_cache = {}
        self.cache_timeout = 30  # seconds
        self.device_monitoring_active = False
        self.monitoring_thread = None
        self.nfc_listeners = {}
        
    @handle_errors("ADB command execution", return_on_error="")
    def adb_cmd(self, cmd: str, device_id: Optional[str] = None, timeout: int = 10) -> str:
        """
        Execute ADB command with caching and restart logic.
        
        Args:
            cmd: ADB command to execute
            device_id: Specific device ID (optional)
            timeout: Command timeout in seconds
            
        Returns:
            Command output as string
        """
        # Create cache key
        cache_key = f"{device_id or 'default'}:{cmd}"
        current_time = datetime.now()
        
        # Check cache for recent results
        if cache_key in self.adb_cache:
            cached_result, cached_time = self.adb_cache[cache_key]
            if current_time - cached_time < timedelta(seconds=self.cache_timeout):
                self.logger.debug(f"Using cached ADB result for: {cmd}")
                return cached_result
        
        # Build ADB command
        adb_command = ["adb"]
        if device_id:
            adb_command.extend(["-s", device_id])
        adb_command.extend(cmd.split())
        
        try:
            start_time = time.time()
            result = subprocess.run(
                adb_command, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            end_time = time.time()
            
            if result.returncode != 0:
                # Try restarting ADB server if command failed
                self.logger.warning(f"ADB command failed, attempting restart: {result.stderr}")
                self._restart_adb_server()
                
                # Retry the command once
                result = subprocess.run(
                    adb_command, 
                    capture_output=True, 
                    text=True, 
                    timeout=timeout
                )
            
            output = result.stdout.strip()
            
            # Cache successful results
            if result.returncode == 0:
                self.adb_cache[cache_key] = (output, current_time)
                
            # Log timing metrics
            execution_time = end_time - start_time
            self.logger.debug(f"ADB command '{cmd}' took {execution_time:.3f}s")
            
            return output
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"ADB command timed out: {cmd}")
            return ""
        except Exception as e:
            self.logger.error(f"ADB command error: {e}")
            return ""
    
    @handle_errors("ADB server restart", return_on_error=False)
    def _restart_adb_server(self) -> bool:
        """Restart the ADB server."""
        try:
            # Kill ADB server
            subprocess.run(["adb", "kill-server"], capture_output=True, timeout=10)
            time.sleep(2)
            
            # Start ADB server
            subprocess.run(["adb", "start-server"], capture_output=True, timeout=10)
            time.sleep(2)
            
            # Clear cache after restart
            self.adb_cache.clear()
            
            self.logger.info("ADB server restarted successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restart ADB server: {e}")
            return False
    
    @handle_errors("Device listing", return_on_error=[])
    def get_connected_devices(self) -> List[Dict[str, str]]:
        """Get list of connected Android devices."""
        output = self.adb_cmd("devices -l")
        devices = []
        
        for line in output.split('\n')[1:]:  # Skip header
            if line.strip() and 'device' in line:
                parts = line.split()
                if len(parts) >= 2:
                    device_id = parts[0]
                    status = parts[1]
                    
                    # Extract additional info
                    model = ""
                    product = ""
                    for part in parts[2:]:
                        if part.startswith('model:'):
                            model = part.split(':', 1)[1]
                        elif part.startswith('product:'):
                            product = part.split(':', 1)[1]
                    
                    devices.append({
                        'id': device_id,
                        'status': status,
                        'model': model,
                        'product': product
                    })
        
        return devices
    
    @handle_errors("Device monitoring start", return_on_error=False)
    def start_device_monitoring(self) -> bool:
        """Start monitoring Android devices in background thread."""
        if self.device_monitoring_active:
            self.logger.warning("Device monitoring already active")
            return True
            
        self.device_monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._device_monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        
        self.logger.info("Started Android device monitoring")
        return True
    
    @handle_errors("Device monitoring stop", return_on_error=False)
    def stop_device_monitoring(self) -> bool:
        """Stop device monitoring."""
        self.device_monitoring_active = False
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        self.logger.info("Stopped Android device monitoring")
        return True
    
    def _device_monitoring_loop(self):
        """Background device monitoring loop."""
        last_device_count = 0
        
        while self.device_monitoring_active:
            try:
                devices = self.get_connected_devices()
                current_count = len(devices)
                
                if current_count != last_device_count:
                    if current_count > last_device_count:
                        self.logger.info(f"Device connected: {current_count} total devices")
                        # Trigger NFC status check for new devices
                        for device in devices:
                            self._check_nfc_status(device['id'])
                    else:
                        self.logger.info(f"Device disconnected: {current_count} total devices")
                    
                    last_device_count = current_count
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Device monitoring error: {e}")
                time.sleep(10)  # Wait longer on error
    
    @handle_errors("NFC status check", return_on_error=False)
    def _check_nfc_status(self, device_id: str) -> bool:
        """Check NFC status on specific device."""
        try:
            # Check if NFC is enabled
            nfc_status = self.adb_cmd(
                "shell settings get secure nfc_enabled", 
                device_id=device_id
            )
            
            if nfc_status == "1":
                self.logger.info(f"NFC enabled on device {device_id}")
                return True
            else:
                self.logger.warning(f"NFC disabled on device {device_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to check NFC status: {e}")
            return False
    
    @handle_errors("NFC enablement", return_on_error={'success': False})
    def enable_nfc(self, device_id: str, method: str = "auto") -> Dict[str, Any]:
        """
        Enable NFC on Android device.
        
        Args:
            device_id: Target device ID
            method: Method to use ('adb', 'apk', 'auto')
            
        Returns:
            Dictionary with operation results
        """
        initial_status = self._check_nfc_status(device_id)
        
        if initial_status:
            return {
                'initial_status': True,
                'final_status': True,
                'success': True,
                'method_used': 'already_enabled',
                'message': 'NFC was already enabled'
            }
        
        if method in ["adb", "auto"]:
            # Try ADB method first
            try:
                # Enable NFC via settings
                result = self.adb_cmd(
                    "shell settings put secure nfc_enabled 1",
                    device_id=device_id
                )
                
                # Restart NFC service
                self.adb_cmd(
                    "shell am stopservice com.android.nfc/.NfcService",
                    device_id=device_id
                )
                time.sleep(1)
                self.adb_cmd(
                    "shell am startservice com.android.nfc/.NfcService", 
                    device_id=device_id
                )
                
                # Check if successful
                time.sleep(2)
                final_status = self._check_nfc_status(device_id)
                
                if final_status:
                    return {
                        'initial_status': initial_status,
                        'final_status': final_status,
                        'success': True,
                        'method_used': 'adb',
                        'message': 'NFC enabled via ADB'
                    }
                    
            except Exception as e:
                self.logger.warning(f"ADB NFC enablement failed: {e}")
        
        if method in ["apk", "auto"]:
            # APK method available but not implemented in this extraction
            return {
                'initial_status': initial_status,
                'adb_result': False,
                'final_status': False,
                'success': False,
                'method_used': 'adb_only_failed',
                'error': 'ADB enablement unsuccessful - APK method available if requested',
                'apk_available': True
            }
        
        return {
            'initial_status': initial_status,
            'final_status': False,
            'success': False,
            'method_used': 'failed',
            'error': 'All NFC enablement methods failed'
        }
    
    @handle_errors("NFC listener management", return_on_error=False)
    def manage_nfc_listeners(self, device_id: str, action: str = "start") -> bool:
        """
        Manage NFC listeners on Android device.
        
        Args:
            device_id: Target device ID
            action: Action to perform ('start', 'stop', 'restart')
            
        Returns:
            Success status
        """
        if action == "stop":
            if device_id in self.nfc_listeners:
                # Stop NFC listener
                self.adb_cmd(
                    "shell am force-stop com.android.nfc",
                    device_id=device_id
                )
                del self.nfc_listeners[device_id]
                self.logger.info(f"Stopped NFC listener on {device_id}")
                return True
        
        elif action in ["start", "restart"]:
            if action == "restart" and device_id in self.nfc_listeners:
                # Stop first
                self.manage_nfc_listeners(device_id, "stop")
            
            # Start NFC listener
            try:
                self.adb_cmd(
                    "shell am startservice com.android.nfc/.NfcService",
                    device_id=device_id
                )
                
                # Enable HCE if available
                self.adb_cmd(
                    "shell settings put secure nfc_hce_enabled 1",
                    device_id=device_id
                )
                
                self.nfc_listeners[device_id] = {
                    'started': datetime.now(),
                    'status': 'active'
                }
                
                self.logger.info(f"Started NFC listener on {device_id}")
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to start NFC listener: {e}")
                return False
        
        return False
    
    @handle_errors("NFC daemon management", return_on_error=False)
    def manage_nfc_daemon(self, action: str = "start") -> bool:
        """
        Manage NFC daemon across all connected devices.
        
        Args:
            action: Action to perform ('start', 'stop', 'restart', 'status')
            
        Returns:
            Success status
        """
        devices = self.get_connected_devices()
        
        if not devices:
            self.logger.warning("No Android devices connected")
            return False
        
        success_count = 0
        
        for device in devices:
            device_id = device['id']
            
            if action == "status":
                status = self._check_nfc_status(device_id)
                listener_active = device_id in self.nfc_listeners
                self.logger.info(f"Device {device_id}: NFC={'ON' if status else 'OFF'}, Listener={'Active' if listener_active else 'Inactive'}")
                success_count += 1
            
            else:
                if self.manage_nfc_listeners(device_id, action):
                    success_count += 1
        
        return success_count > 0
    
    def clear_cache(self):
        """Clear ADB command cache."""
        self.adb_cache.clear()
        self.logger.info("ADB cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get ADB cache statistics."""
        current_time = datetime.now()
        valid_entries = 0
        expired_entries = 0
        
        for cache_key, (result, cached_time) in self.adb_cache.items():
            if current_time - cached_time < timedelta(seconds=self.cache_timeout):
                valid_entries += 1
            else:
                expired_entries += 1
        
        return {
            'total_entries': len(self.adb_cache),
            'valid_entries': valid_entries,
            'expired_entries': expired_entries,
            'cache_timeout': self.cache_timeout
        }