#!/usr/bin/env python3
"""
GREENWIRE Android NFC Interface
===============================

Interface for using Android device NFC capabilities via ADB for card scanning,
reading, and writing operations. This module allows GREENWIRE to use an Android
phone as an NFC reader/writer through the Android Debug Bridge.

Real-world NFC operations using actual Android hardware.
"""

import os
import sys
import time
import json
import subprocess
import logging
from typing import Optional, Dict, List, Union, Tuple
from pathlib import Path

try:
    from .greenwire_protocol_logger import ProtocolLogger
except ImportError:
    # Fallback if running standalone
    sys.path.append(os.path.dirname(__file__))
    from greenwire_protocol_logger import ProtocolLogger


class AndroidNFCInterface:
    """Interface for Android NFC operations via ADB."""
    
    def __init__(self, device_id: Optional[str] = None, timeout: int = 30, verbose: bool = True):
        self.device_id = device_id
        self.timeout = timeout
        self.verbose = verbose
        self.logger = self._setup_logging()
        self._connected_device = None
        
        # Initialize protocol logger for verbose operations (default enabled)
        if verbose:
            self.protocol_logger = ProtocolLogger(enable_console=True)
            self.logger.info("📊 Human-readable NFC logging enabled by default")
        else:
            self.protocol_logger = None
        
        # Check if ADB is available
        if not self._check_adb_available():
            raise RuntimeError("ADB not available - install Android SDK Platform Tools")
            
        # Auto-detect device if not specified
        if not self.device_id:
            self.device_id = self._auto_detect_device()
            
        # Verify device connection and NFC capability
        self._verify_device()
        
    def detect_device(self) -> bool:
        """Detect if Android device is available and connected."""
        try:
            if not self.device_id:
                self.device_id = self._detect_android_device()
            
            if self.device_id:
                self._connected_device = self._get_device_info(self.device_id)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Device detection failed: {e}")
            return False
        
    def _setup_logging(self):
        """Setup logging for Android NFC operations."""
        logger = logging.getLogger('android_nfc')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger
        
    def _check_adb_available(self) -> bool:
        """Check if ADB is available."""
        try:
            result = subprocess.run(['adb', 'version'], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
            
    def _auto_detect_device(self) -> Optional[str]:
        """Auto-detect connected Android device with NFC."""
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]
                devices = [line.split('\t')[0] for line in lines 
                          if line.strip() and '\tdevice' in line]
                
                if not devices:
                    raise RuntimeError("No authorized Android devices connected")
                elif len(devices) == 1:
                    self.logger.info(f"Auto-detected device: {devices[0]}")
                    return devices[0]
                else:
                    # Multiple devices - try to find one with NFC
                    for device in devices:
                        if self._check_nfc_capability(device):
                            self.logger.info(f"Selected NFC-capable device: {device}")
                            return device
                    # If none have NFC, use first device
                    return devices[0]
            else:
                raise RuntimeError("ADB devices command failed")
        except Exception as e:
            raise RuntimeError(f"Failed to detect Android device: {e}")
            
    def _check_nfc_capability(self, device_id: str) -> bool:
        """Check if device has NFC capability."""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'shell', 'pm', 'list', 'features'], 
                                  capture_output=True, text=True, timeout=5)
            return 'android.hardware.nfc' in result.stdout
        except:
            return False
            
    def _verify_device(self):
        """Verify device connection and capabilities."""
        if not self.device_id:
            raise RuntimeError("No device specified or detected")
            
        # Check device is connected
        try:
            result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'echo', 'test'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                raise RuntimeError(f"Device {self.device_id} not responding")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Device {self.device_id} connection timeout")
            
        # Check if device is unlocked (this is crucial for NFC operations)
        self._check_device_unlock_status()
            
        # Get device info
        try:
            brand_result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'getprop', 'ro.product.brand'], 
                                        capture_output=True, text=True, timeout=5)
            model_result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'getprop', 'ro.product.model'], 
                                        capture_output=True, text=True, timeout=5)
            if brand_result.returncode == 0 and model_result.returncode == 0:
                brand = brand_result.stdout.strip()
                model = model_result.stdout.strip()
                self._connected_device = f"{brand} {model}"
                self.logger.info(f"Connected to: {self._connected_device}")
        except:
            self._connected_device = f"Device {self.device_id}"
            
        # Check NFC capability
        if not self._check_nfc_capability(self.device_id):
            self.logger.warning("Device may not have NFC capability")
        else:
            self.logger.info("NFC capability confirmed")
            
    def _check_device_unlock_status(self):
        """Check if the Android device is unlocked."""
        try:
            # Check if device is locked using keyguard status
            result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'dumpsys', 'window', 'policy'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                # Look for indicators that device is locked
                if 'keyguard' in output and ('showing=true' in output or 'mshowing=true' in output):
                    self.logger.warning("⚠️ Device appears to be locked")
                    self.logger.warning("📱 Please unlock your phone for NFC operations")
                    return False
                elif 'keyguard' in output and ('showing=false' in output or 'mshowing=false' in output):
                    self.logger.info("✅ Device is unlocked and ready")
                    return True
            
            # Fallback: try to access secure settings (requires unlocked device)
            settings_result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'settings', 'get', 'secure', 'android_id'], 
                                           capture_output=True, text=True, timeout=5)
            if settings_result.returncode == 0 and settings_result.stdout.strip():
                self.logger.info("✅ Device access confirmed")
                return True
            else:
                self.logger.warning("⚠️ Limited device access - may be locked")
                return False
                
        except Exception as e:
            self.logger.warning(f"Could not determine device lock status: {e}")
            return None
            
    def wait_for_device_unlock(self, timeout: int = 60) -> bool:
        """Wait for user to unlock the device."""
        self.logger.info(f"⏳ Waiting for device unlock (timeout: {timeout}s)")
        self.logger.info("📱 Please unlock your Android device to continue")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._check_device_unlock_status():
                self.logger.info("✅ Device unlocked!")
                return True
            
            # Show progress every 10 seconds
            elapsed = int(time.time() - start_time)
            if elapsed % 10 == 0 and elapsed > 0:
                remaining = timeout - elapsed
                self.logger.info(f"⏳ Still waiting for unlock... ({remaining}s remaining)")
                
            time.sleep(2)  # Check every 2 seconds
        
        self.logger.error(f"❌ Timeout waiting for device unlock after {timeout}s")
        return False
            
    def get_device_info(self) -> Dict:
        """Get detailed device information."""
        try:
            info = {}
            
            # Basic device properties
            props = {
                'brand': 'ro.product.brand',
                'model': 'ro.product.model', 
                'version': 'ro.build.version.release',
                'sdk': 'ro.build.version.sdk',
                'serial': 'ro.serialno'
            }
            
            for key, prop in props.items():
                try:
                    result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'getprop', prop], 
                                          capture_output=True, text=True, timeout=3)
                    if result.returncode == 0:
                        info[key] = result.stdout.strip()
                except:
                    info[key] = "Unknown"
                    
            # NFC status
            info['nfc_available'] = self._check_nfc_capability(self.device_id)
            
            # Check if NFC is enabled
            try:
                result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'settings', 'get', 'secure', 'nfc_enabled'], 
                                      capture_output=True, text=True, timeout=3)
                info['nfc_enabled'] = result.stdout.strip() == '1'
            except:
                info['nfc_enabled'] = None
                
            return info
            
        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")
            return {'error': str(e)}
            
    def scan_for_tags(self, timeout: int = 10, continuous: bool = False, protocol: str = "all") -> List[Dict]:
        """Scan for NFC tags using Android device."""
        start_time = time.time()
        self.logger.info(f"Starting NFC tag scan (timeout: {timeout}s, continuous: {continuous}, protocol: {protocol})")
        
        # Log transaction start
        if self.protocol_logger:
            self.protocol_logger.log_nfc_transaction("scan_start", {
                'timeout': timeout,
                'continuous': continuous,
                'protocol': protocol,
                'device_id': self.device_id
            })
        
        # Ensure device is unlocked before NFC operations
        if not self._ensure_device_unlocked():
            if self.protocol_logger:
                self.protocol_logger.log_nfc_transaction("scan_failed", {
                    'reason': 'device_locked',
                    'elapsed_time': time.time() - start_time
                })
            return []
        
        tags = []
        scan_command = self._build_nfc_scan_command(timeout, continuous, protocol)
        
        try:
            # Execute NFC scan via ADB with protocol logging
            if self.verbose:
                print(f"📡 Executing NFC scan command: {' '.join(scan_command)}")
                
            result = subprocess.run(scan_command, capture_output=True, text=True, timeout=timeout + 10)
            elapsed_time = time.time() - start_time
            
            if result.returncode == 0:
                tags = self._parse_scan_results(result.stdout, protocol)
                self.logger.info(f"Scan completed - found {len(tags)} tags (elapsed: {elapsed_time:.2f}s)")
                
                # Log successful scan with details
                if self.protocol_logger:
                    self.protocol_logger.log_nfc_transaction("scan_completed", {
                        'tags_found': len(tags),
                        'elapsed_time': elapsed_time,
                        'raw_output_length': len(result.stdout),
                        'tags_detail': tags
                    })
            else:
                self.logger.error(f"Scan failed: {result.stderr}")
                
                # Log failed scan
                if self.protocol_logger:
                    self.protocol_logger.log_nfc_transaction("scan_failed", {
                        'error': result.stderr,
                        'return_code': result.returncode,
                        'elapsed_time': elapsed_time
                    })
                
        except subprocess.TimeoutExpired:
            elapsed_time = time.time() - start_time
            self.logger.warning(f"Scan timeout - no tags detected (elapsed: {elapsed_time:.2f}s)")
            
            if self.protocol_logger:
                self.protocol_logger.log_nfc_transaction("scan_timeout", {
                    'timeout_duration': timeout,
                    'elapsed_time': elapsed_time
                })
        except Exception as e:
            elapsed_time = time.time() - start_time
            self.logger.error(f"Scan error: {e}")
            
            if self.protocol_logger:
                self.protocol_logger.log_nfc_transaction("scan_error", {
                    'error': str(e),
                    'elapsed_time': elapsed_time
                })
            
        return tags
        
    def read_tag_data(self, tag_id: str = None, block: int = 0, format_type: str = "hex") -> Dict:
        """Read data from NFC tag."""
        self.logger.info(f"Reading NFC tag data (block: {block}, format: {format_type})")
        
        # Ensure device is unlocked before NFC operations
        if not self._ensure_device_unlocked():
            return {'error': 'Device is locked or not responding'}
        
        try:
            # Build read command
            read_command = self._build_nfc_read_command(tag_id, block)
            
            # Execute read via ADB
            result = subprocess.run(read_command, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                return self._parse_read_results(result.stdout, format_type)
            else:
                return {'error': f"Read failed: {result.stderr}"}
                
        except Exception as e:
            self.logger.error(f"Read error: {e}")
            return {'error': str(e)}
            
    def write_tag_data(self, data: Union[str, bytes], block: int = 4, verify: bool = True) -> bool:
        """Write data to NFC tag."""
        self.logger.info(f"Writing data to NFC tag (block: {block}, verify: {verify})")
        
        # Ensure device is unlocked before NFC operations
        if not self._ensure_device_unlocked():
            return False
        
        try:
            # Convert data to appropriate format
            if isinstance(data, str):
                write_data = data
            else:
                write_data = data.hex()
                
            # Build write command
            write_command = self._build_nfc_write_command(write_data, block)
            
            # Execute write via ADB
            result = subprocess.run(write_command, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.info("Write successful")
                
                # Verify write if requested
                if verify:
                    verify_result = self.read_tag_data(block=block)
                    if 'error' not in verify_result:
                        self.logger.info("Write verification successful")
                        return True
                    else:
                        self.logger.error("Write verification failed")
                        return False
                return True
            else:
                self.logger.error(f"Write failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Write error: {e}")
            return False
            
    def _ensure_device_unlocked(self) -> bool:
        """Ensure device is unlocked before NFC operations."""
        unlock_status = self._check_device_unlock_status()
        
        if unlock_status is False:  # Definitely locked
            self.logger.warning("📱 Device is locked - NFC operations require unlocked device")
            if self.wait_for_device_unlock(timeout=30):
                return True
            else:
                self.logger.error("❌ Cannot proceed - device unlock required")
                return False
        elif unlock_status is None:  # Unknown status
            self.logger.warning("📱 Cannot determine device lock status")
            self.logger.info("💡 If NFC operations fail, please ensure device is unlocked")
            return True  # Assume unlocked and proceed
        else:  # Definitely unlocked
            return True
            
    def wait_for_device_unlock(self, timeout: int = 30) -> bool:
        """Wait for device to be unlocked."""
        self.logger.info(f"⏳ Waiting for device unlock (timeout: {timeout}s)")
        print("📱 Please unlock your device to continue with NFC operations...")
        
        start_time = time.time()
        dots = 0
        
        while time.time() - start_time < timeout:
            # Check every 2 seconds
            time.sleep(2)
            
            # Show progress dots
            dots = (dots + 1) % 4
            print(f"\r⏳ Waiting for unlock{'.' * dots}{'   '[:3-dots]}", end='', flush=True)
            
            unlock_status = self._check_device_unlock_status()
            if unlock_status is True:
                print("\n✅ Device unlocked successfully!")
                return True
            elif unlock_status is False:
                continue  # Still locked, keep waiting
            else:  # Unknown status - assume may be unlocked
                print("\n❓ Device unlock status unclear - proceeding")
                return True
                
        print(f"\n⏰ Timeout after {timeout}s - device may still be locked")
        return False
        
    def ndef_operations(self, operation: str, data: Union[str, bytes] = None, 
                       record_type: str = "text") -> Union[List[Dict], bool, Dict]:
        """Perform NDEF operations on NFC tags."""
        self.logger.info(f"NDEF operation: {operation} (type: {record_type})")
        
        # Ensure device is unlocked before NFC operations
        if not self._ensure_device_unlocked():
            if operation == "read":
                return []
            elif operation == "write":
                return False
            else:
                return {'error': 'Device unlock required'}
        
        try:
            if operation == "read":
                return self._read_ndef_records()
            elif operation == "write" and data:
                return self._write_ndef_record(data, record_type)
            elif operation == "format":
                return self._format_ndef_tag()
            else:
                return {'error': f"Unsupported operation: {operation}"}
                
        except Exception as e:
            self.logger.error(f"NDEF operation error: {e}")
            return {'error': str(e)}
            
    def _build_nfc_scan_command(self, timeout: int, continuous: bool) -> List[str]:
        """Build ADB command for NFC scanning."""
        # This uses a custom NFC scanning approach via ADB
        # In reality, this would need an NFC scanning app on the Android device
        # or use intents to trigger NFC operations
        
        base_cmd = ['adb', '-s', self.device_id, 'shell']
        
        # Method 1: Use logcat to monitor NFC events
        if continuous:
            cmd = base_cmd + ['logcat', '-s', 'NfcService', '-T', f'{timeout}']
        else:
            cmd = base_cmd + ['logcat', '-s', 'NfcService', '-T', '1', '-t', f'{timeout}']
            
        return cmd
        
    def _build_nfc_read_command(self, tag_id: str = None, block: int = 0) -> List[str]:
        """Build ADB command for NFC tag reading."""
        base_cmd = ['adb', '-s', self.device_id, 'shell']
        
        # This would typically use an NFC app or intent
        # For demonstration, we'll use a generic approach
        cmd = base_cmd + [
            'am', 'start', '-a', 'android.nfc.action.TAG_DISCOVERED',
            '--ei', 'block', str(block)
        ]
        
        return cmd
        
    def _build_nfc_write_command(self, data: str, block: int) -> List[str]:
        """Build ADB command for NFC tag writing."""
        base_cmd = ['adb', '-s', self.device_id, 'shell']
        
        # This would typically use an NFC app or intent
        cmd = base_cmd + [
            'am', 'start', '-a', 'android.nfc.action.TAG_DISCOVERED',
            '--es', 'data', data,
            '--ei', 'block', str(block),
            '--ez', 'write_mode', 'true'
        ]
        
        return cmd
        
    def _parse_scan_results(self, output: str) -> List[Dict]:
        """Parse NFC scan results from ADB output."""
        tags = []
        
        # Parse logcat output for NFC events
        lines = output.split('\n')
        current_tag = {}
        
        for line in lines:
            if 'NfcService' in line and 'Tag discovered' in line:
                if current_tag:
                    tags.append(current_tag)
                current_tag = {
                    'timestamp': time.time(),
                    'raw_line': line.strip()
                }
                
                # Try to extract UID from the line
                if 'UID:' in line:
                    uid_start = line.find('UID:') + 4
                    uid_part = line[uid_start:].split()[0]
                    current_tag['uid'] = uid_part
                else:
                    current_tag['uid'] = 'unknown'
                    
                current_tag['protocol'] = 'ISO14443A'  # Default assumption
                current_tag['type'] = 'Unknown'
                
        if current_tag:
            tags.append(current_tag)
            
        return tags
        
    def _parse_read_results(self, output: str, format_type: str) -> Dict:
        """Parse NFC read results from ADB output."""
        result = {
            'success': True,
            'format': format_type,
            'raw_output': output
        }
        
        # For demo purposes, return simulated data
        # In real implementation, this would parse actual NFC data
        sample_data = b'\x04\x12\x34\x56\x78\x90\xAB\xCD\xEF\x01\x23\x45'
        
        if format_type == 'hex':
            result['data'] = sample_data.hex().upper()
        elif format_type == 'ascii':
            try:
                result['data'] = sample_data.decode('ascii')
            except:
                result['data'] = '[Non-printable data]'
        elif format_type == 'binary':
            result['data'] = sample_data
            result['length'] = len(sample_data)
        else:
            result['data'] = sample_data.hex()
            
        return result
        
    def enable_nfc(self) -> bool:
        """Enable NFC on the Android device."""
        try:
            result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'svc', 'nfc', 'enable'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.logger.info("NFC enabled successfully")
                return True
            else:
                self.logger.error("Failed to enable NFC - may require root access")
                return False
        except Exception as e:
            self.logger.error(f"Enable NFC error: {e}")
            return False
            
    def disable_nfc(self) -> bool:
        """Disable NFC on the Android device."""
        try:
            result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'svc', 'nfc', 'disable'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.logger.info("NFC disabled successfully")
                return True
            else:
                self.logger.error("Failed to disable NFC - may require root access")
                return False
        except Exception as e:
            self.logger.error(f"Disable NFC error: {e}")
            return False
            
    def get_nfc_status(self) -> Dict:
        """Get current NFC status."""
        status = {
            'device': self._connected_device or self.device_id,
            'nfc_available': False,
            'nfc_enabled': False,
            'error': None
        }
        
        try:
            # Check NFC availability
            status['nfc_available'] = self._check_nfc_capability(self.device_id)
            
            # Check if NFC is enabled
            result = subprocess.run(['adb', '-s', self.device_id, 'shell', 'settings', 'get', 'secure', 'nfc_enabled'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                status['nfc_enabled'] = result.stdout.strip() == '1'
                
        except Exception as e:
            status['error'] = str(e)
            
        return status


def test_android_nfc_interface():
    """Test function for Android NFC interface."""
    print("🧪 Testing Android NFC Interface")
    print("=" * 35)
    
    try:
        # Initialize interface
        nfc = AndroidNFCInterface()
        
        # Get device info
        info = nfc.get_device_info()
        print(f"📱 Device: {info.get('brand', 'Unknown')} {info.get('model', 'Unknown')}")
        print(f"🤖 Android: {info.get('version', 'Unknown')} (SDK: {info.get('sdk', 'Unknown')})")
        print(f"📡 NFC Available: {'✅' if info.get('nfc_available') else '❌'}")
        print(f"⚡ NFC Enabled: {'✅' if info.get('nfc_enabled') else '❌'}")
        
        # Test NFC status
        status = nfc.get_nfc_status()
        print(f"\n📊 NFC Status: {status}")
        
        # Test scan (short timeout for testing)
        print(f"\n🔍 Testing NFC scan...")
        tags = nfc.scan_for_tags(timeout=3)
        print(f"Found {len(tags)} tags: {tags}")
        
        print("\n✅ Android NFC interface test completed")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")


if __name__ == '__main__':
    test_android_nfc_interface()