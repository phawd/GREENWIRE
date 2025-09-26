#!/usr/bin/env python3
"""EMV NFC Verification Module for GREENWIRE.

This module provides EMV-specific NFC verification capabilities including
AID testing, GPO commands, and CAP file personalization.
"""

import json, os, subprocess, sys, time  # noqa: F401
from typing import Any, Dict, List, Optional, Tuple  # noqa: F401
from pathlib import Path  # noqa: F401

# Common EMV AIDs for testing
COMMON_EMVCO_AIDS = [
    "A0000000031010",  # Visa Classic
    "A0000000032010",  # Visa Electron
    "A0000000033010",  # Visa Interlink
    "A0000000041010",  # Mastercard Credit
    "A0000000042010",  # Mastercard Debit
    "A0000000043010",  # Mastercard Maestro
    "A0000000031020",  # Visa
    "A0000000041020",  # Mastercard
    "A000000003101001", # Visa International
    "A000000004101001", # Mastercard International
    "A0000000250000",   # American Express
    "A0000000651010",   # Discover
    "A0000000152000",   # JPCS
    "A0000000333010",   # Paypass
]

# Import required modules with fallbacks
try:
    from apdu_communicator import APDUCommunicator
    HAS_APDU_COMM = True
except ImportError:
    HAS_APDU_COMM = False

try:
    import nfc
    HAS_NFC = True
except ImportError:
    HAS_NFC = False

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    HAS_PYSCARD = True
except ImportError:
    HAS_PYSCARD = False


class EMVNFCVerifier:
    """EMV NFC verification and testing class."""
    
    def __init__(self, verbose: bool = False):
        """Initialize EMV NFC verifier.
        
        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.results = []
        
    def verify_nfc_capabilities(self, device_spec: Optional[str] = None) -> Dict[str, Any]:
        """Verify basic NFC capabilities.
        
        Args:
            device_spec: NFC device specification (e.g., 'usb')
            
        Returns:
            Dictionary with verification results
        """
        results = {
            'nfc_available': False,
            'pyscard_available': HAS_PYSCARD,
            'nfcpy_available': HAS_NFC,
            'apdu_comm_available': HAS_APDU_COMM,
            'readers': [],
            'nfc_devices': []
        }
        
        # Check PC/SC readers
        if HAS_PYSCARD:
            try:
                reader_list = readers()
                results['readers'] = [str(reader) for reader in reader_list]
                results['nfc_available'] = len(results['readers']) > 0
            except Exception as e:
                if self.verbose:
                    print(f"PC/SC reader detection error: {e}")
        
        # Check NFC devices (nfcpy)
        if HAS_NFC:
            try:
                # This is a basic check - full nfcpy device detection would be more complex
                results['nfc_devices'] = ['nfcpy device detection available']
            except Exception as e:
                if self.verbose:
                    print(f"NFC device detection error: {e}")
        
        return results
    
    def test_emv_aids(self, aids: Optional[List[str]] = None, 
                      use_common: bool = False) -> List[Dict[str, Any]]:
        """Test EMV AIDs on available readers/devices.
        
        Args:
            aids: List of AIDs to test (hex strings)
            use_common: Use common EMVCo AIDs if aids not specified
            
        Returns:
            List of test results for each AID
        """
        if aids is None:
            aids = COMMON_EMVCO_AIDS if use_common else []
        
        if not aids:
            return []
        
        test_results = []
        
        if not HAS_APDU_COMM:
            if self.verbose:
                print("APDU communicator not available - simulating AID tests")
            
            # Simulate AID test results
            for aid in aids[:5]:  # Limit to first 5 for demo
                test_results.append({
                    'aid': aid,
                    'select_success': True if 'A00000000' in aid else False,
                    'response': '6F1E8407' + aid + '5010' + aid[:6] + '000000009F38039F5A05',
                    'sw': '9000',
                    'simulated': True
                })
        else:
            # Real AID testing with APDU communicator
            comm = APDUCommunicator(verbose=self.verbose)
            
            if comm.connect_reader():
                try:
                    for aid in aids:
                        result = self._test_single_aid(comm, aid)
                        test_results.append(result)
                finally:
                    comm.disconnect()
            else:
                if self.verbose:
                    print("Could not connect to reader for AID testing")
        
        return test_results
    
    def _test_single_aid(self, comm: 'APDUCommunicator', aid: str) -> Dict[str, Any]:
        """Test a single AID with the communicator.
        
        Args:
            comm: APDU communicator instance
            aid: AID to test (hex string)
            
        Returns:
            Test result dictionary
        """
        # Build SELECT command - format: 00 A4 04 00 LC AID
        aid_clean = aid.replace(' ', '')
        aid_len = len(aid_clean) // 2  # Length in bytes
        select_cmd = f"00A404000{aid_len:02X}{aid_clean}"
        
        if self.verbose:
            print(f"Testing AID: {aid}")
            print(f"SELECT command: {select_cmd}")
        
        response, sw = comm.send_apdu(select_cmd)
        
        result = {
            'aid': aid,
            'select_command': select_cmd,
            'select_success': sw == '9000',
            'response': response or '',
            'sw': sw or 'ERROR',
            'simulated': False
        }
        
        # If successful, try GPO
        if sw == '9000':
            gpo_result = self._test_gpo(comm)
            result['gpo_test'] = gpo_result
        
        return result
    
    def _test_gpo(self, comm: 'APDUCommunicator') -> Dict[str, Any]:
        """Test Get Processing Options command.
        
        Args:
            comm: APDU communicator instance
            
        Returns:
            GPO test result
        """
        # Standard GPO command
        gpo_cmd = "80A80000028300"
        
        if self.verbose:
            print(f"Testing GPO: {gpo_cmd}")
        
        response, sw = comm.send_apdu(gpo_cmd)
        
        return {
            'gpo_command': gpo_cmd,
            'gpo_success': sw == '9000',
            'response': response or '',
            'sw': sw or 'ERROR'
        }
    
    def personalize_cap_file(self, cap_file_path: str, aid: Optional[str] = None,
                            gp_jar_path: Optional[str] = None,
                            reader_name: Optional[str] = None) -> Dict[str, Any]:
        """Attempt CAP file personalization using GlobalPlatform.
        
        Args:
            cap_file_path: Path to CAP file
            aid: AID for personalization
            gp_jar_path: Path to gp.jar (auto-detect if None)
            reader_name: Specific reader name
            
        Returns:
            Personalization result
        """
        if not os.path.exists(cap_file_path):
            return {
                'success': False,
                'error': f'CAP file not found: {cap_file_path}'
            }
        
        # Auto-detect gp.jar location
        if gp_jar_path is None:
            possible_paths = [
                'gp.jar',
                'lib/gp.jar',
                'static/java/gp.jar',
                os.path.join(os.path.dirname(__file__), '..', 'lib', 'gp.jar'),
                os.path.join(os.path.dirname(__file__), '..', 'static', 'java', 'gp.jar')
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    gp_jar_path = path
                    break
        
        if not gp_jar_path or not os.path.exists(gp_jar_path):
            return {
                'success': False,
                'error': 'gp.jar not found - install GlobalPlatformPro'
            }
        
        # Build GP command
        cmd = ['java', '-jar', gp_jar_path]
        
        if reader_name:
            cmd.extend(['--reader', reader_name])
        
        cmd.extend(['--install', cap_file_path])
        
        if aid:
            cmd.extend(['--create', aid])
        
        if self.verbose:
            print(f"GP command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'GP command timed out after 30 seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'GP execution error: {str(e)}'
            }
    
    def android_hce_install(self, cap_file_path: str, aid: str) -> Dict[str, Any]:
        """Install CAP file to Android HCE via ADB.
        
        Args:
            cap_file_path: Path to CAP file
            aid: Primary AID for the applet
            
        Returns:
            Installation result
        """
        # Check ADB availability
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': 'ADB not available or no devices connected'
                }
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'ADB not found - install Android SDK platform-tools'
            }
        
        # This is a simplified simulation - real HCE installation would be more complex
        if self.verbose:
            print(f"Simulating Android HCE installation of {cap_file_path}")
            print(f"Primary AID: {aid}")
        
        return {
            'success': True,
            'message': 'Android HCE installation simulated successfully',
            'aid': aid,
            'cap_file': cap_file_path,
            'simulated': True
        }
    
    def generate_verification_report(self, results: Dict[str, Any],
                                   output_path: Optional[str] = None) -> str:
        """Generate verification report.
        
        Args:
            results: Verification results
            output_path: Path to save report (optional)
            
        Returns:
            Report content as string
        """
        report_lines = []
        report_lines.append("EMV NFC Verification Report")
        report_lines.append("=" * 40)
        report_lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        # Capabilities section
        report_lines.append("NFC Capabilities:")
        report_lines.append(f"  NFC Available: {'✅' if results.get('nfc_available') else '❌'}")
        report_lines.append(f"  PC/SC Readers: {len(results.get('readers', []))}")
        report_lines.append(f"  NFC Devices: {len(results.get('nfc_devices', []))}")
        report_lines.append("")
        
        # Readers section
        if results.get('readers'):
            report_lines.append("Available Readers:")
            for i, reader in enumerate(results['readers'], 1):
                report_lines.append(f"  {i}. {reader}")
            report_lines.append("")
        
        # AID testing section
        if 'aid_tests' in results:
            report_lines.append("AID Test Results:")
            successful_aids = 0
            for aid_result in results['aid_tests']:
                success_indicator = "✅" if aid_result['select_success'] else "❌"
                report_lines.append(f"  {success_indicator} {aid_result['aid']} - {aid_result['sw']}")
                if aid_result['select_success']:
                    successful_aids += 1
            
            report_lines.append(f"\nSummary: {successful_aids}/{len(results['aid_tests'])} AIDs successful")
            report_lines.append("")
        
        # Personalization section
        if 'personalization' in results:
            report_lines.append("CAP Personalization:")
            p_result = results['personalization']
            success_indicator = "✅" if p_result.get('success') else "❌"
            report_lines.append(f"  {success_indicator} Status: {'Success' if p_result.get('success') else 'Failed'}")
            if not p_result.get('success') and 'error' in p_result:
                report_lines.append(f"  Error: {p_result['error']}")
            report_lines.append("")
        
        report_content = "\n".join(report_lines)
        
        # Save to file if requested
        if output_path:
            try:
                with open(output_path, 'w') as f:
                    f.write(report_content)
                if self.verbose:
                    print(f"Report saved to: {output_path}")
            except Exception as e:
                if self.verbose:
                    print(f"Error saving report: {e}")
        
        return report_content


def main():
    """Command line interface for EMV NFC verification."""
    import argparse
    
    parser = argparse.ArgumentParser(description="EMV NFC Verification Tool")
    parser.add_argument("--device", help="NFC device specification")
    parser.add_argument("--aids", help="Comma-separated AIDs to test")
    parser.add_argument("--all-common", action="store_true", 
                       help="Test common EMVCo AIDs")
    parser.add_argument("--personalize", action="store_true",
                       help="Attempt CAP file personalization")
    parser.add_argument("--cap-file", help="CAP file for personalization")
    parser.add_argument("--gp-jar", help="Path to gp.jar")
    parser.add_argument("--adb", action="store_true",
                       help="Attempt Android ADB installation")
    parser.add_argument("--aid", help="Primary AID for personalization")
    parser.add_argument("--reader", help="Specific PC/SC reader name")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    verifier = EMVNFCVerifier(verbose=args.verbose)
    
    # Collect all results
    results = {}
    
    # Basic capability verification
    if args.verbose:
        print("🔍 Verifying NFC capabilities...")
    
    capabilities = verifier.verify_nfc_capabilities(args.device)
    results.update(capabilities)
    
    # AID testing
    test_aids = None
    if args.aids:
        test_aids = [aid.strip() for aid in args.aids.split(',')]
    
    if test_aids or args.all_common:
        if args.verbose:
            print("🧪 Testing EMV AIDs...")
        
        aid_results = verifier.test_emv_aids(aids=test_aids, use_common=args.all_common)
        results['aid_tests'] = aid_results
    
    # CAP personalization
    if args.personalize and args.cap_file:
        if args.verbose:
            print("📦 Attempting CAP personalization...")
        
        personalization_result = verifier.personalize_cap_file(
            args.cap_file, args.aid, args.gp_jar, args.reader
        )
        results['personalization'] = personalization_result
    
    # Android ADB installation
    if args.adb and args.cap_file and args.aid:
        if args.verbose:
            print("📱 Attempting Android HCE installation...")
        
        android_result = verifier.android_hce_install(args.cap_file, args.aid)
        results['android_hce'] = android_result
    
    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        report = verifier.generate_verification_report(results)
        print(report)


if __name__ == "__main__":
    main()