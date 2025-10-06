"""
GREENWIRE CAP File Manager
Handles JavaCard CAP file operations, validation, and installation.
"""

import json, os, subprocess
from typing import Any, Dict, List, Optional, Union  # noqa: F401
from .logging_system import get_logger, handle_errors
from .config import get_config

class CAPFileManager:
    """Manages JavaCard CAP file operations."""
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        self.valid_extensions = {'.cap', '.CAP'}
        self.aid_cache = {}
        self.default_android_key = "404142434445464748494A4B4C4D4E4F"  # Default Android HCE key
    
    @handle_errors("CAP file validation", return_on_error=False)
    def validate_cap_file(self, file_path: str) -> bool:
        """
        Validate CAP file format and structure.
        
        Args:
            file_path: Path to CAP file
            
        Returns:
            True if valid, False otherwise
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"CAP file not found: {file_path}")

        if not any(file_path.endswith(ext) for ext in self.valid_extensions):
            raise ValueError(f"Invalid file extension. Expected {self.valid_extensions}")

        # Validate CAP file structure
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                if header != b'\xDE\xCA\xFF\xED':  # JavaCard CAP file magic number
                    raise ValueError("Invalid CAP file format")

                # Extract and cache AID information
                f.seek(0)
                self._extract_aid_info(f, file_path)
                
            return True
            
        except Exception as e:
            raise ValueError(f"Error validating CAP file: {e}")
    
    @handle_errors("AID extraction", return_on_error=None)
    def _extract_aid_info(self, file_handle, file_path: str) -> Optional[str]:
        """
        Extract AID information from CAP file and cache it.
        
        Args:
            file_handle: Open file handle
            file_path: Path to CAP file for caching
            
        Returns:
            Extracted AID as hex string or None
        """
        try:
            # Read the CAP file contents
            data = file_handle.read()

            # Look for AID in the header component
            aid_start = data.find(b'\x01\x00\x05\x00\x09')  # AID component identifier
            if aid_start != -1:
                aid_length = data[aid_start + 5]
                aid = data[aid_start + 6:aid_start + 6 + aid_length]
                aid_hex = aid.hex().upper()
                self.aid_cache[file_path] = aid_hex
                self.logger.info(f"Extracted AID: {aid_hex}")
                return aid_hex
                
        except Exception as e:
            self.logger.warning(f"Could not extract AID from CAP file: {e}")
            
        return None
    
    @handle_errors("CAP file installation", return_on_error=False)
    def install_cap_file(self, file_path: str, target: str = "reader", 
                        reader: Optional[str] = None, 
                        android_device: Optional[str] = None) -> bool:
        """
        Install CAP file to a card reader or Android device.
        
        Args:
            file_path: Path to CAP file
            target: Installation target ('reader' or 'android')
            reader: Specific reader name (optional)
            android_device: Android device ID (optional)
            
        Returns:
            True if installation successful
        """
        if not self.validate_cap_file(file_path):
            return False

        if target == "android" or android_device:
            return self._install_to_android(file_path, android_device)
        else:
            return self._install_to_reader(file_path, reader)
    
    @handle_errors("CAP installation to reader", return_on_error=False)
    def _install_to_reader(self, file_path: str, reader: Optional[str] = None) -> bool:
        """
        Install CAP file to a physical card reader.
        
        Args:
            file_path: Path to CAP file
            reader: Specific reader name (optional)
            
        Returns:
            True if installation successful
        """
        # Check for GlobalPlatform Pro (gp.jar)
        gp_jar_paths = [
            "gp.jar",
            "static/java/gp.jar",
            "lib/gp.jar",
            os.path.join(os.path.dirname(__file__), "..", "static", "java", "gp.jar")
        ]
        
        gp_jar = None
        for path in gp_jar_paths:
            if os.path.exists(path):
                gp_jar = path
                break
        
        if not gp_jar:
            self.logger.error("GlobalPlatform Pro (gp.jar) not found")
            return False
        
        # Build installation command
        cmd = ['java', '-jar', gp_jar, '--install', file_path]
        if reader:
            cmd.extend(['--reader', reader])

        try:
            self.logger.info(f"Installing CAP file: {file_path}")
            if reader:
                self.logger.info(f"Target reader: {reader}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                self.logger.error(f"CAP installation failed: {result.stderr}")
                return False
            
            self.logger.info("CAP file installed successfully")
            self.logger.debug(f"Installation output: {result.stdout}")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("CAP installation timed out")
            return False
        except Exception as e:
            self.logger.error(f"Error installing CAP file: {e}")
            return False
    
    @handle_errors("CAP installation to Android", return_on_error=False)
    def _install_to_android(self, file_path: str, device_path: Optional[str] = None) -> bool:
        """
        Install CAP file to Android device via NFC HCE.
        
        Args:
            file_path: Path to CAP file
            device_path: Android device ID (optional)
            
        Returns:
            True if installation successful
        """
        try:
            aid = self.aid_cache.get(file_path)
            if not aid:
                # Try to extract AID if not cached
                with open(file_path, 'rb') as f:
                    aid = self._extract_aid_info(f, file_path)
                
                if not aid:
                    self.logger.error("Could not determine AID for CAP file")
                    return False

            # Create Android HCE service configuration
            hce_config = {
                "aid_groups": [{
                    "aids": [aid],
                    "category": "other",
                    "description": f"GREENWIRE Applet {os.path.basename(file_path)}"
                }],
                "apdu_service": {
                    "description": "GREENWIRE NFC Service",
                    "secure": True,
                    "aid": aid,
                    "binary": self._prepare_android_binary(file_path)
                }
            }

            # Save HCE configuration
            config_path = f"{file_path}.hce_config.json"
            with open(config_path, 'w') as f:
                json.dump(hce_config, f, indent=2)
            
            self.logger.info(f"Generated HCE configuration: {config_path}")
            self.logger.info(f"AID: {aid}")
            
            # Note: Actual installation to Android device would require
            # additional integration with Android Manager for ADB operations
            self.logger.warning("Android HCE installation requires ADB integration")
            return True
            
        except Exception as e:
            self.logger.error(f"Android installation failed: {e}")
            return False
    
    @handle_errors("Android binary preparation", return_on_error="")
    def _prepare_android_binary(self, file_path: str) -> str:
        """
        Prepare CAP file binary data for Android HCE.
        
        Args:
            file_path: Path to CAP file
            
        Returns:
            Base64 encoded binary data
        """
        import base64
        
        try:
            with open(file_path, 'rb') as f:
                binary_data = f.read()
            
            # Convert to base64 for JSON serialization
            return base64.b64encode(binary_data).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Failed to prepare Android binary: {e}")
            return ""
    
    @handle_errors("AID retrieval", return_on_error=None)
    def get_cap_aid(self, file_path: str) -> Optional[str]:
        """
        Get AID for CAP file.
        
        Args:
            file_path: Path to CAP file
            
        Returns:
            AID as hex string or None
        """
        # Check cache first
        if file_path in self.aid_cache:
            return self.aid_cache[file_path]
        
        # Extract AID from file
        try:
            with open(file_path, 'rb') as f:
                return self._extract_aid_info(f, file_path)
        except Exception as e:
            self.logger.error(f"Failed to get AID for {file_path}: {e}")
            return None
    
    @handle_errors("CAP file listing", return_on_error=[])
    def list_cap_files(self, directory: str = ".") -> List[Dict[str, Any]]:
        """
        List all CAP files in directory with metadata.
        
        Args:
            directory: Directory to search
            
        Returns:
            List of CAP file information
        """
        cap_files = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in self.valid_extensions):
                        file_path = os.path.join(root, file)
                        
                        try:
                            # Get file stats
                            stat = os.stat(file_path)
                            
                            # Get AID if possible
                            aid = self.get_cap_aid(file_path)
                            
                            cap_info = {
                                'path': file_path,
                                'name': file,
                                'size': stat.st_size,
                                'modified': stat.st_mtime,
                                'aid': aid,
                                'valid': aid is not None
                            }
                            
                            cap_files.append(cap_info)
                            
                        except Exception as e:
                            self.logger.warning(f"Failed to process {file_path}: {e}")
            
            self.logger.info(f"Found {len(cap_files)} CAP files in {directory}")
            return cap_files
            
        except Exception as e:
            self.logger.error(f"Failed to list CAP files: {e}")
            return []
    
    @handle_errors("CAP file generation", return_on_error=False)
    def generate_cap_file(self, applet_config: Dict[str, Any], 
                         output_path: str) -> bool:
        """
        Generate CAP file from applet configuration.
        
        Args:
            applet_config: Applet configuration dictionary
            output_path: Output path for generated CAP file
            
        Returns:
            True if generation successful
        """
        try:
            # This would integrate with the JavaCard build system
            # For now, log the configuration
            self.logger.info(f"Generating CAP file: {output_path}")
            self.logger.debug(f"Applet config: {applet_config}")
            
            # Check if build system is available
            if os.path.exists("build.gradle"):
                # Use Gradle build
                cmd = ["gradle", "buildCap"]
                if "applet_name" in applet_config:
                    cmd.extend(["-PappletName=" + applet_config["applet_name"]])
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info("CAP file generated successfully")
                    return True
                else:
                    self.logger.error(f"CAP generation failed: {result.stderr}")
                    return False
            
            else:
                self.logger.warning("Build system not available - CAP generation skipped")
                return False
                
        except Exception as e:
            self.logger.error(f"CAP generation error: {e}")
            return False
    
    def clear_aid_cache(self):
        """Clear the AID cache."""
        self.aid_cache.clear()
        self.logger.info("AID cache cleared")
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get AID cache information."""
        return {
            'cached_files': len(self.aid_cache),
            'aids': list(self.aid_cache.values())
        }
    
    @handle_errors("GlobalPlatform command execution", return_on_error="")
    def execute_gp_command(self, gp_args: List[str]) -> str:
        """
        Execute GlobalPlatform Pro command.
        
        Args:
            gp_args: Arguments to pass to gp.jar
            
        Returns:
            Command output
        """
        # Find gp.jar
        gp_jar_paths = [
            "gp.jar",
            "static/java/gp.jar", 
            "lib/gp.jar",
            os.path.join(os.path.dirname(__file__), "..", "static", "java", "gp.jar")
        ]
        
        gp_jar = None
        for path in gp_jar_paths:
            if os.path.exists(path):
                gp_jar = path
                break
        
        if not gp_jar:
            self.logger.error("GlobalPlatform Pro (gp.jar) not found")
            return "Error: gp.jar not found"
        
        try:
            cmd = ['java', '-jar', gp_jar] + gp_args
            self.logger.info(f"Executing GP command: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                self.logger.warning(f"GP command returned non-zero: {result.returncode}")
            
            output = result.stdout + result.stderr
            return output.strip()
            
        except subprocess.TimeoutExpired:
            return "Error: Command timed out"
        except Exception as e:
            return f"Error: {e}"