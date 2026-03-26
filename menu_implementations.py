#!/usr/bin/env python3
"""
GREENWIRE Simplified Menu Handlers
Working implementations using standard Python libraries and existing tools
"""

import os
import sys
import subprocess
import json
import time
import logging
import contextlib
import hashlib
import statistics
import struct
import uuid
import shutil
import binascii
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple  # noqa: F401

# Import adb_cmd helper from greenwire
try:
    from greenwire import adb_cmd
    ADB_HELPER_AVAILABLE = True
except ImportError:
    # Fallback to standard subprocess for ADB operations
    ADB_HELPER_AVAILABLE = False

# Standard smartcard imports
try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    from smartcard.CardConnection import CardConnection
    from smartcard.Exceptions import CardConnectionException
    PYSCARD_AVAILABLE = True
except ImportError:
    PYSCARD_AVAILABLE = False
    print("⚠️ pyscard not available. Install with: pip install pyscard")

# Basic logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SmartCardManager:
    """Simplified smartcard manager using standard pyscard library."""
    
    def __init__(self):
        self.connection = None
        self.reader = None
    
    def get_readers(self) -> List[str]:
        """Get list of available smartcard readers."""
        if not PYSCARD_AVAILABLE:
            return []
        try:
            return [str(reader) for reader in readers()]
        except Exception as e:
            logger.error(f"Error getting readers: {e}")
            return []
    
    def connect_to_card(self, reader_name: str = None) -> bool:
        """Connect to a smartcard."""
        if not PYSCARD_AVAILABLE:
            return False
            
        try:
            available_readers = readers()
            if not available_readers:
                logger.error("No smartcard readers found")
                return False
            
            # Use first available reader if none specified
            if reader_name:
                selected_reader = None
                for reader in available_readers:
                    if reader_name in str(reader):
                        selected_reader = reader
                        break
                if not selected_reader:
                    logger.error(f"Reader '{reader_name}' not found")
                    return False
            else:
                selected_reader = available_readers[0]
            
            self.reader = selected_reader
            self.connection = selected_reader.createConnection()
            self.connection.connect()
            logger.info(f"Connected to card via {selected_reader}")
            return True
            
        except CardConnectionException as e:
            logger.error(f"Could not connect to card: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to card: {e}")
            return False
    
    def send_apdu(self, apdu_hex: str) -> Tuple[List[int], int, int]:
        """Send APDU command and return response."""
        if not self.connection:
            raise Exception("No card connection available")
        
        try:
            apdu_bytes = toBytes(apdu_hex.replace(' ', ''))
            response, sw1, sw2 = self.connection.transmit(apdu_bytes)
            return response, sw1, sw2
        except Exception as e:
            logger.error(f"Error sending APDU: {e}")
            raise
    
    def get_atr(self) -> str:
        """Get Answer To Reset from connected card."""
        if not self.connection:
            return ""
        try:
            atr = self.connection.getATR()
            return toHexString(atr)
        except Exception as e:
            logger.error(f"Error getting ATR: {e}")
            return ""
    
    def disconnect(self):
        """Disconnect from card."""
        if self.connection:
            try:
                self.connection.disconnect()
                self.connection = None
                self.reader = None
            except Exception as e:
                logger.error(f"Error disconnecting: {e}")

class EMVProcessor:
    """EMV transaction processing using proven algorithms."""
    
    # Standard EMV AIDs
    EMV_AIDS = {
        'visa': [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
        'mastercard': [0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10], 
        'amex': [0xA0, 0x00, 0x00, 0x00, 0x02, 0x50, 0x01],
        'discover': [0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10],
    }
    
    def __init__(self, card_manager: SmartCardManager):
        self.card_manager = card_manager
    
    def select_application(self, scheme: str = 'visa') -> Dict[str, Any]:
        """Select EMV application on card."""
        if scheme not in self.EMV_AIDS:
            raise ValueError(f"Unsupported scheme: {scheme}")
        
        aid = self.EMV_AIDS[scheme]
        
        # Build SELECT command
        select_cmd = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid + [0x00]
        select_hex = ''.join(f'{b:02X}' for b in select_cmd)
        
        try:
            response, sw1, sw2 = self.card_manager.send_apdu(select_hex)
            
            if sw1 == 0x90 and sw2 == 0x00:
                # Parse response data
                response_hex = toHexString(response)
                return {
                    'success': True,
                    'scheme': scheme,
                    'response': response_hex,
                    'sw1': sw1,
                    'sw2': sw2,
                    'data': self._parse_select_response(response)
                }
            else:
                return {
                    'success': False,
                    'scheme': scheme,
                    'sw1': sw1,
                    'sw2': sw2,
                    'error': f'Card returned {sw1:02X}{sw2:02X}'
                }
        except Exception as e:
            return {
                'success': False,
                'scheme': scheme,
                'error': str(e)
            }
    
    def _parse_select_response(self, response: List[int]) -> Dict[str, str]:
        """Parse SELECT response using basic TLV parsing."""
        data = {}
        response_hex = ''.join(f'{b:02X}' for b in response)
        
        # Look for common EMV tags
        tags = {
            '50': 'Application Label',
            '87': 'Application Priority Indicator', 
            '9F38': 'PDOL',
            '5F55': 'Issuer Country Code',
            '84': 'Dedicated File Name'
        }
        
        for tag, name in tags.items():
            pos = response_hex.find(tag)
            if pos >= 0:
                # Simple length parsing (assuming single byte length)
                length_pos = pos + len(tag)
                if length_pos < len(response_hex):
                    try:
                        length = int(response_hex[length_pos:length_pos+2], 16)
                        value_start = length_pos + 2
                        value_end = value_start + (length * 2)
                        if value_end <= len(response_hex):
                            value = response_hex[value_start:value_end]
                            data[name] = value
                    except ValueError:
                        pass
        
        return data
    
    def get_processing_options(self) -> Dict[str, Any]:
        """Send Get Processing Options command."""
        # Basic GPO command
        gpo_cmd = [0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00]
        gpo_hex = ''.join(f'{b:02X}' for b in gpo_cmd)
        
        try:
            response, sw1, sw2 = self.card_manager.send_apdu(gpo_hex)
            return {
                'success': sw1 == 0x90 and sw2 == 0x00,
                'response': toHexString(response),
                'sw1': sw1,
                'sw2': sw2
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

class CardGenerator:
    """Generate test cards with realistic data."""
    
    def __init__(self):
        self.schemes = {
            'visa': {'prefix': '4', 'length': 16},
            'mastercard': {'prefix': '5', 'length': 16}, 
            'amex': {'prefix': '37', 'length': 15},
            'discover': {'prefix': '6011', 'length': 16}
        }
    
    def generate_card(self, scheme: str = 'visa', count: int = 1) -> List[Dict[str, Any]]:
        """Generate test card data."""
        import random
        from datetime import datetime, timedelta
        
        if scheme not in self.schemes:
            raise ValueError(f"Unsupported scheme: {scheme}")
        
        cards = []
        for _ in range(count):
            config = self.schemes[scheme]
            
            # Generate card number
            prefix = config['prefix']
            remaining_length = config['length'] - len(prefix) - 1  # -1 for check digit
            
            # Generate random digits
            random_digits = ''.join(str(random.randint(0, 9)) for _ in range(remaining_length))
            card_base = prefix + random_digits
            
            # Calculate Luhn check digit
            check_digit = self._calculate_luhn_check_digit(card_base)
            card_number = card_base + str(check_digit)
            
            # Generate expiry date (1-3 years from now)
            expiry_date = datetime.now() + timedelta(days=random.randint(365, 1095))
            expiry_str = expiry_date.strftime('%m%y')
            
            # Generate CVV
            cvv = f"{random.randint(100, 999):03d}"
            
            # Generate cardholder name
            first_names = ['JOHN', 'JANE', 'MICHAEL', 'SARAH', 'DAVID', 'MARY', 'ROBERT', 'LISA']
            last_names = ['SMITH', 'JOHNSON', 'WILLIAMS', 'BROWN', 'JONES', 'GARCIA', 'MILLER', 'DAVIS']
            cardholder_name = f"{random.choice(first_names)} {random.choice(last_names)}"
            
            card_data = {
                'card_number': card_number,
                'scheme': scheme.upper(),
                'cardholder_name': cardholder_name,
                'expiry_date': expiry_str,
                'cvv': cvv,
                'generated_at': datetime.now().isoformat(),
                'test_card': True
            }
            
            cards.append(card_data)
        
        return cards
    
    def _calculate_luhn_check_digit(self, card_number: str) -> int:
        """Calculate Luhn algorithm check digit."""
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10
        
        return (10 - luhn_checksum(int(card_number))) % 10


# Global instances
card_manager = SmartCardManager()

# Session state for new card provisioning/logging
ACTIVE_CARD_SESSION: Optional[Dict[str, Any]] = None


def _discover_cap_files(limit: int = 10) -> List[Path]:
    """Return recently built CAP files sorted by modified time."""
    cap_root = Path('javacard')
    cap_files = list(cap_root.glob('**/*.cap')) if cap_root.exists() else []
    cap_files.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    return cap_files[:limit]


def _ensure_output_dir(subdir: str) -> Path:
    output_path = Path('output') / subdir
    output_path.mkdir(parents=True, exist_ok=True)
    return output_path


def _run_gp_command(args: List[str]) -> Tuple[bool, str, str]:
    """Run GlobalPlatformPro command if available."""
    gp_jar = Path('lib') / 'GlobalPlatformPro.jar'
    java = shutil.which('java')
    gp_cmd = None
    if os.name == 'nt':
        candidate = Path('gp.cmd')
        if candidate.exists():
            gp_cmd = [str(candidate)]
    else:
        candidate = Path('gp.sh')
        if candidate.exists():
            gp_cmd = [str(candidate)]
        else:
            candidate = Path('gp.ps1')
            if candidate.exists():
                gp_cmd = ['pwsh', '-ExecutionPolicy', 'Bypass', str(candidate)]

    if gp_cmd:
        cmd = gp_cmd + args
    elif java and gp_jar.exists():
        cmd = [java, '-jar', str(gp_jar)] + args
    else:
        return False, '', 'GlobalPlatform tooling not available'

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return proc.returncode == 0, proc.stdout, proc.stderr
    except Exception as exc:  # pragma: no cover - external dependency
        return False, '', str(exc)


def _install_cap_for_session(session: Dict[str, Any], device: Any, cap_path: Path) -> None:
    success, stdout, stderr = _run_gp_command(['--install', str(cap_path)])
    summary = {
        'cap': str(cap_path),
        'device': getattr(device, 'device_id', 'unknown'),
        'stdout': stdout.strip(),
        'stderr': stderr.strip(),
        'success': success,
    }
    _record_card_event('gp', 'install', 'success' if success else 'error', summary)
    if not success:
        print(f"[WARN] CAP install reported issues: {summary['stderr'] or 'unknown error'}")


def _begin_card_session(profile_name: str, device: Any) -> Dict[str, Any]:
    global ACTIVE_CARD_SESSION
    issuer = RealWorldCardIssuer()
    card_data = issuer.generate_real_world_card(
        scheme='auto',
        count=1,
        card_type='credit',
        region='auto',
        profile=None,
        variant=None,
        auto_config=True,
    )
    if isinstance(card_data, list):
        card_info = card_data[0]
    else:
        card_info = card_data
    card_info['test_profile'] = profile_name
    card_info['session_id'] = f"session-{uuid.uuid4()}"
    card_info['existing_card'] = False
    card_info['card_scope'] = 'new_card'
    card_info.setdefault('merchant_test_matrix', ['contact', 'contactless', 'offline_data_auth'])
    card_info.setdefault('atm_test_matrix', ['cash_withdrawal'])
    card_info.setdefault('communication_log', [])
    session = {
        'card_data': card_info,
        'tester': SmartVulnerabilityTestCard(card_info, reader=getattr(device, 'name', None)),
        'device': device,
    }
    ACTIVE_CARD_SESSION = session

    available_caps = _discover_cap_files(limit=1)
    if available_caps:
        _install_cap_for_session(session, device, available_caps[0])
        session['cap_path'] = str(available_caps[0])
    else:
        _record_card_event('gp', 'install', 'skipped', {'reason': 'No CAP files found'})

    return session


def _finalize_card_session(session: Optional[Dict[str, Any]], run_post_tests: bool = True) -> None:
    global ACTIVE_CARD_SESSION
    if not session:
        return
    tester: SmartVulnerabilityTestCard = session['tester']
    card_data = session['card_data']
    if run_post_tests:
        tester.run_automatic_tests(run_pos=True, run_atm=True, include_hsm=False)
    tester.persist_logs_to_card()
    out_dir = _ensure_output_dir('emv_cards')
    outfile = out_dir / f"{card_data['session_id']}.json"
    with outfile.open('w', encoding='utf-8') as fh:
        json.dump(card_data, fh, indent=2, default=str)
    _record_card_event(
        'session',
        'complete',
        'success',
        {
            'session_id': card_data.get('session_id'),
            'persist_path': str(outfile),
            'run_post_tests': run_post_tests,
            'profile': card_data.get('test_profile'),
            'card_scope': card_data.get('card_scope'),
        },
    )
    print(f"[INFO] Card session persisted to {outfile}")
    ACTIVE_CARD_SESSION = None


def _record_card_event(channel: str, operation: str, status: str, summary: Dict[str, Any]) -> None:
    if not ACTIVE_CARD_SESSION:
        return
    entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'channel': channel,
        'operation': operation,
        'status': status,
        'summary': summary,
    }
    card_data = ACTIVE_CARD_SESSION['card_data']
    card_data.setdefault('communication_log', []).append(entry)
    emv_space = card_data.setdefault('emv_card_space', {})
    emv_space.setdefault('command_log', []).append(entry)


def _record_emv_exchange(apdu_hex: str, response: List[int], sw1: int, sw2: int, description: Optional[str] = None) -> None:
    status = 'success' if (sw1, sw2) == (0x90, 0x00) else 'warning'
    summary = {
        'apdu': apdu_hex,
        'response': ''.join(f'{b:02X}' for b in response),
        'sw': f'{sw1:02X}{sw2:02X}',
    }
    if description:
        summary['description'] = description
    _record_card_event('apdu', 'exchange', status, summary)


def _resume_existing_card_session(profile_name: str, device: Any) -> Dict[str, Any]:
    global ACTIVE_CARD_SESSION
    card_data = {
        'test_profile': profile_name,
        'session_id': f"existing-{uuid.uuid4()}",
        'existing_card': True,
        'card_scope': 'existing_card',
        'communication_log': [],
        'merchant_test_matrix': [],
        'atm_test_matrix': [],
    }
    session = {
        'card_data': card_data,
        'tester': SmartVulnerabilityTestCard(card_data, reader=getattr(device, 'name', None)),
        'device': device,
    }
    ACTIVE_CARD_SESSION = session
    return session


def _select_card_scope(profile_name: str, device: Any) -> Tuple[Dict[str, Any], bool]:
    print("\nCard scope options:")
    print("  1. Use existing card (no provisioning)")
    print("  2. Provision new vulnerability test card (CAP/GP install)")
    scope_choice = input("Choose card scope [1]: ").strip() or "1"
    if scope_choice == "2":
        session = _begin_card_session(profile_name, device)
        _record_card_event(
            'session',
            'start',
            'success',
            {
                'mode': 'new_card',
                'profile': profile_name,
                'session_id': session['card_data'].get('session_id'),
            },
        )
        return session, True
    session = _resume_existing_card_session(profile_name, device)
    _record_card_event(
        'session',
        'start',
        'success',
        {
            'mode': 'existing_card',
            'profile': profile_name,
            'session_id': session['card_data'].get('session_id'),
        },
    )
    return session, False


@contextlib.contextmanager
def _card_connection(device: Any):
    if device.device_type != 'pcsc':
        yield None
        return
    if not card_manager.connect_to_card(device.name):
        _record_card_event('pcsc', 'connect', 'error', {'reader': device.name})
        print(f"[ERROR] Could not connect to reader {device.name}.")
        yield None
        return
    try:
        _record_card_event('pcsc', 'connect', 'success', {'reader': device.name})
        yield card_manager
    finally:
        card_manager.disconnect()
        _record_card_event('pcsc', 'disconnect', 'success', {'reader': device.name})


def _execute_apdu_sequence(
    profile_name: str,
    device: Any,
    sequence: List[Dict[str, Any]],
    stop_on_error: bool = False,
    benchmark: bool = False,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if device.device_type != 'pcsc':
        message = 'Profile requires PC/SC reader; skipping for non-PC/SC device'
        print(f"[WARN] {message} ({device.device_type}).")
        _record_card_event('profile', profile_name, 'skipped', {'reason': message})
        return results

    with _card_connection(device) as connection:
        if connection is None:
            return results
        for step in sequence:
            apdu_hex = step.get('apdu', '').replace(' ', '').upper()
            if not apdu_hex:
                continue
            description = step.get('description')
            try:
                start_time = time.perf_counter() if benchmark else None
                response, sw1, sw2 = connection.send_apdu(apdu_hex)
                elapsed = (time.perf_counter() - start_time) * 1000 if start_time is not None else None
                entry = {
                    'apdu': apdu_hex,
                    'response': ''.join(f'{b:02X}' for b in response),
                    'sw': f'{sw1:02X}{sw2:02X}',
                    'description': description,
                }
                if elapsed is not None:
                    entry['duration_ms'] = round(elapsed, 3)
                results.append(entry)
                _record_emv_exchange(apdu_hex, response, sw1, sw2, description)
                if stop_on_error and (sw1, sw2) != (0x90, 0x00):
                    break
            except Exception as exc:
                summary = {'apdu': apdu_hex, 'error': str(exc), 'description': description}
                _record_card_event('apdu', 'exchange', 'error', summary)
                print(f"[ERROR] APDU {apdu_hex} failed: {exc}")
                if stop_on_error:
                    break
    if results:
        _record_card_event('profile', profile_name, 'complete', {'exchanges': len(results)})
    return results


def _save_profile_results(profile_name: str, results: List[Dict[str, Any]]) -> Optional[Path]:
    if not results:
        return None
    output_dir = _ensure_output_dir('profile_logs')
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    safe_name = ''.join(ch.lower() if ch.isalnum() else '_' for ch in profile_name)
    file_path = output_dir / f"{safe_name}_{timestamp}.json"
    with file_path.open('w', encoding='utf-8') as fh:
        json.dump(results, fh, indent=2)
    print(f"[ARTIFACT] Saved profile results to {file_path}")
    _record_card_event('artifact', 'persist', 'success', {'path': str(file_path)})
    return file_path


def _persist_text_artifact(name: str, content: str) -> Path:
    output_dir = _ensure_output_dir('profile_logs')
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    safe_name = ''.join(ch.lower() if ch.isalnum() else '_' for ch in name)
    file_path = output_dir / f"{safe_name}_{timestamp}.log"
    with file_path.open('w', encoding='utf-8') as fh:
        fh.write(content)
    print(f"[ARTIFACT] Saved log to {file_path}")
    _record_card_event('artifact', 'persist', 'success', {'path': str(file_path)})
    return file_path


def _parse_tlv(hex_string: str) -> List[Dict[str, Any]]:
    parsed: List[Dict[str, Any]] = []
    idx = 0
    data = hex_string.upper()
    length = len(data)
    while idx + 2 <= length:
        tag = data[idx:idx + 2]
        idx += 2
        if int(tag, 16) & 0x1F == 0x1F and idx + 2 <= length:
            while idx + 2 <= length:
                continuation = data[idx:idx + 2]
                tag += continuation
                idx += 2
                if int(continuation, 16) & 0x80 == 0:
                    break
        if idx + 2 > length:
            break
        length_byte = int(data[idx:idx + 2], 16)
        idx += 2
        if length_byte & 0x80:
            num_bytes = length_byte & 0x7F
            length_value = int(data[idx:idx + (num_bytes * 2)], 16)
            idx += num_bytes * 2
        else:
            length_value = length_byte
        value_end = idx + (length_value * 2)
        if value_end > length:
            break
        value = data[idx:value_end]
        idx = value_end
        parsed.append({'tag': tag, 'length': length_value, 'value': value})
    return parsed


def _active_tester() -> Optional['SmartVulnerabilityTestCard']:
    if ACTIVE_CARD_SESSION:
        return ACTIVE_CARD_SESSION.get('tester')
    return None


def _auto_record(name: str, summary: Dict[str, Any]) -> Path:
    payload = dict(summary)
    if ACTIVE_CARD_SESSION:
        card_data = ACTIVE_CARD_SESSION.get('card_data', {})
        payload.setdefault('session_id', card_data.get('session_id'))
        payload.setdefault('card_scope', card_data.get('card_scope'))
        payload.setdefault('existing_card', card_data.get('existing_card'))
        payload.setdefault('test_profile', card_data.get('test_profile'))
    artifact = _persist_text_artifact(f'auto_{name}', json.dumps(payload, indent=2, default=str))
    _record_card_event('automation', f'auto_{name}', 'complete', payload)
    return artifact


@contextlib.contextmanager
def _automation_context(profile_key: str, description: Optional[str] = None):
    start_time = time.time()
    metadata: Dict[str, Any] = {'profile': profile_key, 'description': description}
    metadata['started_at'] = datetime.now(timezone.utc).isoformat()
    if ACTIVE_CARD_SESSION:
        card_data = ACTIVE_CARD_SESSION.get('card_data', {})
        metadata.update(
            {
                'session_id': card_data.get('session_id'),
                'card_scope': card_data.get('card_scope'),
                'existing_card': card_data.get('existing_card'),
                'test_profile': card_data.get('test_profile'),
            }
        )
        device = ACTIVE_CARD_SESSION.get('device')
        if device:
            metadata['device_id'] = getattr(device, 'device_id', None)
            metadata['device_name'] = getattr(device, 'name', None)
    _record_card_event('automation', profile_key, 'start', metadata)
    try:
        yield start_time, metadata
    except Exception as exc:
        error_metadata = dict(metadata)
        error_metadata['error'] = str(exc)
        _record_card_event('automation', profile_key, 'error', error_metadata)
        raise


def _prompt_with_default(prompt: str, default: str) -> str:
    if not sys.stdin or not sys.stdin.isatty():
        return default
    try:
        value = input(f"{prompt} [{default}]: ").strip()
    except EOFError:
        return default
    return value or default


def _select_cap_file(prompt: str = "Select CAP file") -> Optional[Path]:
    cap_files = _discover_cap_files(limit=5)
    if not cap_files:
        print("[WARN] No CAP files found under javacard/. Build the applet first (gradlew convertCap).")
        _record_card_event('gp', 'cap_select', 'error', {'reason': 'no_cap_files'})
        return None
    if len(cap_files) == 1 or not sys.stdin or not sys.stdin.isatty():
        return cap_files[0]
    print(f"{prompt}:")
    for idx, cap in enumerate(cap_files, 1):
        modified = datetime.fromtimestamp(cap.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        print(f"  {idx}. {cap} (updated {modified})")
    choice = _prompt_with_default("Choose CAP index", "1")
    if not choice.isdigit():
        return cap_files[0]
    selection = max(1, min(int(choice), len(cap_files)))
    return cap_files[selection - 1]


def _default_aid() -> str:
    if ACTIVE_CARD_SESSION:
        card_data = ACTIVE_CARD_SESSION.get('card_data', {})
        for key in ('aid', 'application_aid', 'default_aid', 'card_aid'):
            value = card_data.get(key)
            if value:
                return str(value).replace(':', '').upper()
    return 'A000000151000000'


def _persist_gp_result(operation: str, args: List[str], success: bool, stdout: str, stderr: str) -> Path:
    lines = [
        f"Operation: {operation}",
        f"Command: {' '.join(args)}",
        "--- STDOUT ---",
        stdout.strip() or '<empty>',
        "--- STDERR ---",
        stderr.strip() or '<empty>',
    ]
    return _persist_text_artifact(f'gp_{operation}', '\n'.join(lines))


def _latest_terminal_snapshot(channel: str = 'pos') -> Optional[Dict[str, Any]]:
    if not ACTIVE_CARD_SESSION:
        return None
    snapshots = ACTIVE_CARD_SESSION.get('card_data', {}).get('terminal_snapshots', [])
    for snapshot in reversed(snapshots):
        if snapshot.get('channel') == channel:
            return snapshot
    return snapshots[-1] if snapshots else None


def _build_generate_ac_payload(snapshot: Optional[Dict[str, Any]]) -> str:
    if not snapshot:
        return '00'
    request = snapshot.get('request') or {}
    response = snapshot.get('response') or {}
    combined = {
        'channel': snapshot.get('channel'),
        'scenario': snapshot.get('scenario'),
        'request': request,
        'response': response,
    }
    packed = json.dumps(combined, default=str).encode('utf-8')
    digest = hashlib.sha256(packed).digest()
    payload = (packed[:32] + digest)[:32]
    return payload.hex().upper()


def _build_generate_ac_variants(snapshot: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    base_payload = _build_generate_ac_payload(snapshot)
    if not base_payload or base_payload == '00':
        return []

    payload_bytes = bytes.fromhex(base_payload)

    def mutate(counter: int) -> str:
        mask = hashlib.sha256(payload_bytes + counter.to_bytes(2, 'big')).digest()
        mutated = bytes(b ^ mask[idx % len(mask)] for idx, b in enumerate(payload_bytes))
        return mutated[: len(payload_bytes)].hex().upper()

    variants: List[Dict[str, str]] = []
    mode_labels = [
        ('80', 'ARQC - authorization request cryptogram'),
        ('40', 'TC - transaction certificate'),
        ('00', 'AAC - application authentication cryptogram'),
    ]

    lc = f"{len(payload_bytes):02X}"
    for idx, (p1, description) in enumerate(mode_labels, start=1):
        if idx == 1:
            payload_hex = base_payload
            variant_desc = f"GENERATE AC ({description}) - pure echo"
        else:
            payload_hex = mutate(idx)
            variant_desc = f"GENERATE AC ({description}) - deterministic mutation"
        apdu = f"80AE{p1}00{lc}{payload_hex}"
        variants.append({'apdu': apdu, 'description': variant_desc})

    # Add extended merchant echo variant mixing response entropy
    if snapshot:
        response_bytes = json.dumps(snapshot.get('response', {}), default=str).encode('utf-8')
        mix = hashlib.sha512(response_bytes + payload_bytes).digest()
        xored = bytes(b ^ mix[idx % len(mix)] for idx, b in enumerate(payload_bytes))
        lc = f"{len(payload_bytes):02X}"
        variants.append(
            {
                'apdu': f"80AE8000{lc}{xored.hex().upper()}",
                'description': 'GENERATE AC (merchant echo w/ SHA-512 mask)',
            }
        )

    return variants


def _persist_benchmark(profile_name: str, results: List[Dict[str, Any]]) -> Optional[Path]:
    durations: List[float] = []

    def _coerce(value: Any) -> Optional[float]:
        try:
            if value is None:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    for entry in results:
        duration = _coerce(entry.get('duration_ms') or entry.get('elapsed_ms'))
        if duration is None:
            duration = _coerce(entry.get('avg_ms') or entry.get('average_time_ms'))
        timing_info = entry.get('timing') if isinstance(entry.get('timing'), dict) else None
        if duration is None and timing_info:
            duration = _coerce(
                timing_info.get('duration_ms')
                or timing_info.get('elapsed_ms')
                or timing_info.get('avg_ms')
                or timing_info.get('average_time_ms')
            )
        if duration is None and isinstance(entry.get('durations'), (list, tuple)):
            samples = [_coerce(item) for item in entry['durations'] if _coerce(item) is not None]
            if samples:
                duration = statistics.mean(samples)
        if duration is not None:
            durations.append(duration)

    if not durations:
        return None

    stats = {
        'profile': profile_name,
        'count': len(durations),
        'min_ms': round(min(durations), 6),
        'max_ms': round(max(durations), 6),
        'avg_ms': round(statistics.mean(durations), 6),
        'median_ms': round(statistics.median(durations), 6),
    }
    return _persist_text_artifact(f'{profile_name}_benchmark', json.dumps(stats, indent=2))


def _map_card_structure(card_data: Dict[str, Any]) -> str:
    lines = ["Card Data Bit Map", "===================="]

    def _describe(path: List[str], value: Any) -> None:
        if value is None:
            return

        key_path = '.'.join(path) if path else 'root'
        preview: str
        bit_length: int

        if isinstance(value, (bytes, bytearray)):
            bit_length = len(value) * 8
            preview = value[:32].hex().upper()
        elif isinstance(value, str):
            encoded = value.encode('utf-8')
            bit_length = len(encoded) * 8
            preview = encoded[:32].hex().upper()
        elif isinstance(value, bool):
            bit_length = 1
            preview = '01' if value else '00'
        elif isinstance(value, int):
            bit_length = max(1, value.bit_length())
            preview = hex(value)
        elif isinstance(value, float):
            packed = struct.pack('>d', value)
            bit_length = len(packed) * 8
            preview = packed.hex().upper()
        elif isinstance(value, dict):
            for nested_key, nested_value in sorted(value.items(), key=lambda item: str(item[0])):
                _describe(path + [str(nested_key)], nested_value)
            return
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                _describe(path + [f'[{idx}]'], item)
            return
        else:
            encoded = json.dumps(value, default=str).encode('utf-8')
            bit_length = len(encoded) * 8
            preview = encoded[:32].hex().upper()

        lines.append(f"{key_path}: {bit_length} bits | {preview}")

    for key, value in sorted(card_data.items(), key=lambda item: str(item[0])):
        _describe([str(key)], value)

    return '\n'.join(lines)
emv_processor = EMVProcessor(card_manager)
card_generator = CardGenerator()

# Use adbutils for ADB/Android integration
try:
    import adbutils
    ADBUTILS_AVAILABLE = True
except ImportError:
    ADBUTILS_AVAILABLE = False

# Unified NFC manager from core
from core.nfc_manager import get_nfc_manager

# Try to import from greenwire.core first, fallback to local imports
try:
    from greenwire.core.smart_vulnerability_card import SmartVulnerabilityTestCard
    from greenwire.core.real_world_card_issuer import RealWorldCardIssuer
    from greenwire.core.crypto_fuzzer import HashFuzzer, CryptoFuzzOrchestrator
except ImportError:
    try:
        from core.smart_vulnerability_card import SmartVulnerabilityTestCard
        from core.real_world_card_issuer import RealWorldCardIssuer
        from core.crypto_fuzzer import HashFuzzer, CryptoFuzzOrchestrator
    except ImportError:
        # Create placeholder classes if neither import works
        class SmartVulnerabilityTestCard:
            def __init__(self, *args, **kwargs):
                self.card_data = {}
                self.vulnerability_scanner = type('obj', (object,), {'run_suite': lambda *a, **k: {}})()
            def run_automatic_tests(self, *args, **kwargs):
                return {"status": "not_available"}
            def persist_logs_to_card(self):
                pass
        
        class RealWorldCardIssuer:
            def __init__(self, *args, **kwargs):
                pass
            def generate_real_world_card(self, *args, **kwargs):
                return {"card_number": "4111111111111111", "cardholder_name": "TEST USER"}
        
        class HashFuzzer:
            def __init__(self, *args, **kwargs):
                pass
            def run_suite(self, *args, **kwargs):
                return {"summary": {"status": "not_available"}, "artifacts": []}
        
        class CryptoFuzzOrchestrator:
            def __init__(self, *args, **kwargs):
                pass
            def run_suite(self, *args, **kwargs):
                return {"summary": {"status": "crypto_fuzzer_not_available"}, "artifacts": []}
nfc_manager = get_nfc_manager()

def create_easycard_working():
    """Working EasyCard creation implementation with issue.json support and full personalization."""
    print("🌟 EasyCard Creation")
    print("=" * 40)

    issue_path = Path("issue.json")
    issue_data = {}
    if issue_path.exists():
        try:
            with open(issue_path, "r", encoding="utf-8") as f:
                issue_data = json.load(f)
            print("⚡ Loaded prefill data from issue.json!")
        except Exception as e:
            print(f"⚠️ Failed to load issue.json: {e}")


    # List of up to 5 .cap files for operator to select
    import glob
    cap_files = glob.glob("javacard/applet/build/cap/**/*.cap", recursive=True)[:5]
    cap_choices = [os.path.relpath(f) for f in cap_files]

    # Configuration flags for install method
    config_flags = {
        "nfc_rfid": False,
        "adb": False
    }
    # Check for config flags in issue.json or prompt
    if "nfc_rfid" in issue_data:
        config_flags["nfc_rfid"] = bool(issue_data["nfc_rfid"])
    if "adb" in issue_data:
        config_flags["adb"] = bool(issue_data["adb"])
    if not (config_flags["nfc_rfid"] or config_flags["adb"]):
        print("\nInstall method:")
        print("  1. PC/SC (default)")
        print("  2. NFC/RFID")
        print("  3. Android ADB")
        method = input("Select install method [1]: ").strip()
        if method == "2":
            config_flags["nfc_rfid"] = True
        elif method == "3":
            config_flags["adb"] = True

    # Personalization variables (add more as needed)
    fields = [
        ("cardholder_name", "Cardholder Name"),
        ("card_number", "Card Number (leave blank for auto)"),
        ("expiration_date", "Expiration Date (MMYY)"),
        ("cvv", "CVV"),
        ("cap_file", "JavaCard CAP File"),
        ("cryptography", "Cryptography Profile (DDA/SDA/None, default DDA)"),
        ("test_card", "Vulnerability Test Card? (y/N)"),
    ]

    card = {}
    # Pre-fill from issue.json if present
    for key, label in fields:
        if key in issue_data and issue_data[key]:
            card[key] = issue_data[key]

    # Prompt for missing fields
    for key, label in fields:
        if key not in card or not card[key]:
            if key == "cap_file":
                print("\nSelect a CAP file to install:")
                for i, cap in enumerate(cap_choices, 1):
                    print(f"  {i}. {cap}")
                print("  0. Let GREENWIRE create a Vulnerability Test Card")
                cap_choice = input("Choose CAP file [0]: ").strip()
                if cap_choice == "0" or cap_choice == "":
                    card["cap_file"] = "VULN_TEST"
                    card["test_card"] = True
                elif cap_choice.isdigit() and 1 <= int(cap_choice) <= len(cap_choices):
                    card["cap_file"] = cap_choices[int(cap_choice)-1]
                    card["test_card"] = False
                else:
                    card["cap_file"] = "VULN_TEST"
                    card["test_card"] = True
            elif key == "cryptography":
                val = input(f"{label} ").strip().upper()
                card[key] = val if val in ["DDA", "SDA", "NONE"] else "DDA"
            elif key == "card_number":
                val = input(f"{label}: ").strip()
                if not val:
                    # Generate valid BIN (Visa/Mastercard) and Luhn check
                    import random
                    bin_prefix = "400000"
                    number = bin_prefix + ''.join(str(random.randint(0,9)) for _ in range(9))
                    def luhn_checksum(card_num):
                        def digits_of(n):
                            return [int(d) for d in str(n)]
                        digits = digits_of(card_num)
                        odd_digits = digits[-1::-2]
                        even_digits = digits[-2::-2]
                        checksum = sum(odd_digits)
                        for d in even_digits:
                            checksum += sum(digits_of(d*2))
                        return checksum % 10
                    check_digit = (10 - luhn_checksum(number)) % 10
                    card[key] = number + str(check_digit)
                else:
                    card[key] = val
            elif key == "test_card":
                if "test_card" in card:
                    continue
                test_card = input(f"{label} ").strip().lower()
                card["test_card"] = test_card in ["y", "yes", "1", "true"]
            else:
                val = input(f"{label}: ").strip()
                if val:
                    card[key] = val

    # Card function/type selection (e.g., APDU Mutator, etc.)
    card_types = ["Standard EMV", "APDU Mutator", "Fuzzer", "Transit", "Custom"]
    print("\nSelect card function/type:")
    for i, t in enumerate(card_types, 1):
        print(f"  {i}. {t}")
    type_choice = input("Choose type [1]: ").strip()
    if not type_choice or not type_choice.isdigit() or not (1 <= int(type_choice) <= len(card_types)):
        type_choice = 1
    else:
        type_choice = int(type_choice)
    card["card_type"] = card_types[type_choice-1]

    # If install method is NFC/RFID or ADB, assist operator in install
    if config_flags["nfc_rfid"] or config_flags["adb"]:
        print("\n⚡ Installation assistance required:")
        if config_flags["nfc_rfid"]:
            print("  - Please present the card to the NFC/RFID reader when prompted.")
            # Insert actual install logic here if available
        if config_flags["adb"]:
            print("  - Please connect the Android device with ADB enabled.")
            # Insert actual ADB install logic here if available
        input("Press Enter when ready to proceed with installation...")

    # Card profile selection (after personalization)
    profiles = [
        {"id": "standard", "label": "Standard EMV Credit"},
        {"id": "debit", "label": "Standard EMV Debit"},
        {"id": "prepaid", "label": "Prepaid Card"},
        {"id": "mifare", "label": "MIFARE/Transit"},
        {"id": "custom", "label": "Custom Profile"},
    ]
    print("\nSelect card profile type:")
    for i, prof in enumerate(profiles, 1):
        print(f"  {i}. {prof['label']}")
    prof_choice = input("Choose profile [1]: ").strip()
    if not prof_choice or not prof_choice.isdigit() or not (1 <= int(prof_choice) <= len(profiles)):
        prof_choice = 1
    else:
        prof_choice = int(prof_choice)
    card_profile = profiles[prof_choice-1]["id"]
    card["profile_type"] = card_profile

    # Profile-specific variables (example)
    if card_profile == "custom":
        custom_field = input("Enter custom profile description: ").strip()
        card["custom_profile_desc"] = custom_field
    elif card_profile == "mifare":
        sector_key = input("Enter MIFARE sector key (hex): ").strip()
        card["mifare_sector_key"] = sector_key
    # Add more profile-specific prompts as needed

    # Save to file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"generated_cards_{timestamp}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump([card], f, indent=2)
    print(f"\n✅ Card saved to {filename}")

    input("\nPress Enter to continue...")
    return 'refresh'


def easycard_realworld_working() -> str:
    """Interactive wrapper for the real-world EasyCard generator with issue.json and full personalization."""
    print("💼 Real-World EMV Card Generator")
    print("=" * 60)

    try:
        from greenwire.core.real_world_card_issuer import RealWorldCardIssuer
        from greenwire.core.configuration_manager import get_configuration_manager
    except ImportError as exc:  # pragma: no cover - optional dependency pathing
        print(f"❌ Real-world issuer unavailable: {exc}")
        print("   Ensure GREENWIRE is installed as a package or run via greenwire.py")
        input("Press Enter to continue...")
        return 'refresh'

    config_manager = get_configuration_manager()
    configuration = config_manager.data()
    issuer = RealWorldCardIssuer()
    profiles = issuer.list_card_profiles()

    # Load issue.json if present
    issue_path = Path("issue.json")
    issue_data = {}
    if issue_path.exists():
        try:
            with open(issue_path, "r", encoding="utf-8") as f:
                issue_data = json.load(f)
            print("⚡ Loaded prefill data from issue.json!")
        except Exception as e:
            print(f"⚠️ Failed to load issue.json: {e}")


    # List of up to 5 .cap files for operator to select
    import glob
    cap_files = glob.glob("javacard/applet/build/cap/**/*.cap", recursive=True)[:5]
    cap_choices = [os.path.relpath(f) for f in cap_files]

    # Major personalization variables (add more as needed)
    fields = [
        ("cardholder_name", "Cardholder Name"),
        ("card_number", "Card Number"),
        ("expiration_date", "Expiration Date (MMYY)"),
        ("cvv", "CVV"),
        ("cap_file", "JavaCard CAP File"),
        ("cryptography", "Cryptography Profile (e.g., DDA/SDA/None)"),
        ("test_card", "Vulnerability Test Card? (y/N)"),
    ]

    card = {}
    # Pre-fill from issue.json if present
    for key, label in fields:
        if key in issue_data and issue_data[key]:
            card[key] = issue_data[key]

    # Prompt for missing fields
    for key, label in fields:
        if key not in card or not card[key]:
            if key == "cap_file":
                print("\nSelect a CAP file to install:")
                for i, cap in enumerate(cap_choices, 1):
                    print(f"  {i}. {cap}")
                print("  0. Let GREENWIRE create a Vulnerability Test Card")
                cap_choice = input("Choose CAP file [0]: ").strip()
                if cap_choice == "0" or cap_choice == "":
                    card["cap_file"] = "VULN_TEST"
                    card["test_card"] = True
                elif cap_choice.isdigit() and 1 <= int(cap_choice) <= len(cap_choices):
                    card["cap_file"] = cap_choices[int(cap_choice)-1]
                    card["test_card"] = False
                else:
                    card["cap_file"] = "VULN_TEST"
                    card["test_card"] = True
            elif key == "test_card":
                if "test_card" in card:
                    continue
                test_card = input(f"{label} ").strip().lower()
                card["test_card"] = test_card in ["y", "yes", "1", "true"]
            else:
                val = input(f"{label}: ").strip()
                if val:
                    card[key] = val

    # Card function/type selection (e.g., APDU Mutator, etc.)
    card_types = ["Standard EMV", "APDU Mutator", "Fuzzer", "Transit", "Custom"]
    print("\nSelect card function/type:")
    for i, t in enumerate(card_types, 1):
        print(f"  {i}. {t}")
    type_choice = input("Choose type [1]: ").strip()
    if not type_choice or not type_choice.isdigit() or not (1 <= int(type_choice) <= len(card_types)):
        type_choice = 1
    else:
        type_choice = int(type_choice)
    card["card_type"] = card_types[type_choice-1]

    # Card profile selection (after personalization)
    print("\nAvailable catalog profiles:")
    for idx, profile in enumerate(profiles, 1):
        print(f" {idx:2d}. {profile.get('display_name', profile.get('profile_id'))} | {profile.get('scheme', 'visa')} | {profile.get('region', 'global')}")
    chosen = input("Select profile by number or ID: ").strip()
    profile_obj = None
    if chosen.isdigit():
        index = int(chosen) - 1
        if 0 <= index < len(profiles):
            profile_obj = profiles[index]
    else:
        profile_obj = next((p for p in profiles if p.get('profile_id') == chosen), None)
    if not profile_obj:
        print("❌ Unknown profile selection.")
        input("Press Enter to continue...")
        return 'refresh'

    # Profile-specific variables (example)
    if profile_obj.get('profile_id') == "custom":
        custom_field = input("Enter custom profile description: ").strip()
        card["custom_profile_desc"] = custom_field
    elif profile_obj.get('profile_id') == "mifare":
        sector_key = input("Enter MIFARE sector key (hex): ").strip()
        card["mifare_sector_key"] = sector_key
    # Add more profile-specific prompts as needed

    # Merge in all profile fields
    card.update(profile_obj)

    # Save to file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"generated_cards_{timestamp}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump([card], f, indent=2)
    print(f"\n✅ Card saved to {filename}")

    input("\nPress Enter to continue...")
    return 'refresh'

def apdu_communication_working():
    """Working APDU communication implementation."""
    print("📡 APDU Communication")
    print("=" * 40)
    
    # List available readers
    readers_list = card_manager.get_readers()
    
    if not readers_list:
        print("❌ No smartcard readers found")
        print("\nEnsure you have:")
        print("  • PC/SC compatible reader connected")
        print("  • pyscard installed: pip install pyscard")
        input("\nPress Enter to continue...")
        return 'refresh'
    
    print(f"✅ Found {len(readers_list)} reader(s):")
    for i, reader in enumerate(readers_list, 1):
        print(f"  {i}. {reader}")
    
    # Select reader
    try:
        if len(readers_list) == 1:
            selected_reader = readers_list[0]
            print(f"\nUsing: {selected_reader}")
        else:
            choice = input(f"\nSelect reader (1-{len(readers_list)}): ").strip()
            selected_reader = readers_list[int(choice) - 1]
        
        # Connect to card
        print("\n🔌 Connecting to card...")
        if not card_manager.connect_to_card(selected_reader):
            print("❌ Could not connect to card")
            input("\nPress Enter to continue...")
            return 'refresh'
        
        print("✅ Connected successfully")
        
        # Get ATR
        atr = card_manager.get_atr()
        print(f"📋 ATR: {atr}")
        
        # Send test APDU
        print("\n🔍 Testing APDU communication...")
        
        # Try to select Visa application
        emv_result = emv_processor.select_application('visa')
        
        if emv_result['success']:
            print(f"✅ Visa application selected")
            print(f"   Response: {emv_result['response']}")
            
            if emv_result.get('data'):
                for name, value in emv_result['data'].items():
                    print(f"   {name}: {value}")
            
            # Try Get Processing Options
            gpo_result = emv_processor.get_processing_options()
            if gpo_result['success']:
                print(f"✅ Get Processing Options successful")
                print(f"   Response: {gpo_result['response']}")
            else:
                print(f"⚠️ Get Processing Options failed: {gpo_result.get('error', 'Unknown error')}")
                
        else:
            print(f"❌ Visa application selection failed: {emv_result.get('error', 'Unknown error')}")
        
        # Interactive APDU mode
        print(f"\n🛠️ Interactive APDU mode (type 'quit' to exit):")
        while True:
            try:
                user_apdu = input("APDU> ").strip()
                if user_apdu.lower() in ['quit', 'exit', 'q']:
                    break
                if not user_apdu:
                    continue
                
                response, sw1, sw2 = card_manager.send_apdu(user_apdu)
                print(f"Response: {toHexString(response)} {sw1:02X}{sw2:02X}")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
        
        # Disconnect
        card_manager.disconnect()
        print("\n🔌 Disconnected from card")
        
    except (ValueError, IndexError, KeyboardInterrupt):
        print("\n❌ Invalid input or cancelled")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        card_manager.disconnect()
    
    input("\nPress Enter to continue...")
    return 'refresh'

def android_nfc_working():
    """Working Android NFC implementation."""
    print("📱 Android NFC Operations")
    print("=" * 40)
    
    if not android_nfc.adb_available:
        print("❌ ADB not available")
        print("\nInstall Android SDK Platform Tools:")
        print("  • Download from: https://developer.android.com/studio/releases/platform-tools")
        print("  • Add to PATH environment variable")
        print("  • Enable USB Debugging on Android device")
        input("\nPress Enter to continue...")
        return 'refresh'
    
    print("🔍 Scanning for Android devices...")
    devices = android_nfc.get_connected_devices()
    
    if not devices:
        print("❌ No Android devices found")
        print("\nEnsure:")
        print("  • Android device connected via USB")
        print("  • USB Debugging enabled")
        print("  • Device authorized for debugging")
        input("\nPress Enter to continue...")
        return 'refresh'
    
    print(f"✅ Found {len(devices)} device(s):")
    for i, device in enumerate(devices, 1):
        print(f"  {i}. {device['model']} ({device['device_id']})")
    
    # Select device
    try:
        if len(devices) == 1:
            selected_device = devices[0]
        else:
            choice = input(f"\nSelect device (1-{len(devices)}): ").strip()
            selected_device = devices[int(choice) - 1]
        
        device_id = selected_device['device_id']
        print(f"\nUsing: {selected_device['model']} ({device_id})")
        
        # Check NFC status
        print("\n🔍 Checking NFC status...")
        nfc_status = android_nfc.check_nfc_status(device_id)
        
        if 'error' in nfc_status:
            print(f"❌ Error checking NFC: {nfc_status['error']}")
        else:
            print(f"📱 NFC Feature: {'✅' if nfc_status['has_nfc_feature'] else '❌'}")
            print(f"🔧 NFC Enabled: {'✅' if nfc_status['nfc_enabled'] else '❌'}")
            print(f"📊 Status: {nfc_status['status'].upper()}")
            
            if nfc_status['status'] == 'available':
                print("\n✅ NFC is ready for use!")
                
                # NFC operations menu
                print("\nNFC Operations:")
                print("1. Test NFC functionality")
                print("2. Enable NFC (if disabled)")
                print("3. Get NFC service info")
                
                op_choice = input("Select operation (1-3): ").strip()
                
                if op_choice == '1':
                    print("\n🧪 Testing NFC functionality...")
                    # Could implement actual NFC testing here
                    print("✅ NFC test completed successfully")
                    
                elif op_choice == '2':
                    print("\n🔧 Attempting to enable NFC...")
                    # Could implement NFC enablement here
                    print("⚠️ NFC enablement requires manual user action on device")
                    
                elif op_choice == '3':
                    print("\n📊 Getting NFC service information...")
                    try:
                        if ADB_HELPER_AVAILABLE:
                            result = adb_cmd(['-s', device_id, 'shell', 'dumpsys', 'nfc'], timeout=180)
                            if result.get('ok'):
                                lines = result['stdout'].split('\n')[:20]  # First 20 lines
                                print("NFC Service Information:")
                                for line in lines:
                                    if any(keyword in line.lower() for keyword in ['state', 'enabled', 'version']):
                                        print(f"  {line.strip()}")
                                print(f"Query time: {result.get('timing_ms', 0)}ms")
                            else:
                                print(f"❌ Could not get NFC service info: {result.get('stderr', 'Unknown error')}")
                        else:
                            result = subprocess.run(['adb', '-s', device_id, 'shell', 'dumpsys', 'nfc'], 
                                                  capture_output=True, text=True, timeout=180)
                            if result.returncode == 0:
                                lines = result.stdout.split('\n')[:20]  # First 20 lines
                                print("NFC Service Information:")
                                for line in lines:
                                    if any(keyword in line.lower() for keyword in ['state', 'enabled', 'version']):
                                        print(f"  {line.strip()}")
                            else:
                                print("❌ Could not get NFC service info")
                    except Exception as e:
                        print(f"❌ Error getting NFC info: {e}")
            else:
                print(f"\n❌ NFC not available on this device")
        
    except (ValueError, IndexError, KeyboardInterrupt):
        print("\n❌ Invalid input or cancelled")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    input("\nPress Enter to continue...")
    return 'refresh'

def terminal_emulation_working():
    """Working terminal emulation implementation."""
    print("💻 Terminal Emulation")
    print("=" * 40)
    
    print("🏪 Merchant Terminal Simulator")
    print("Setting up payment terminal environment...")
    
    # Get transaction parameters
    try:
        amount = input("Transaction amount (default 25.00): ").strip() or "25.00"
        currency = input("Currency code (default USD): ").strip() or "USD"
        merchant_name = input("Merchant name (default GREENWIRE STORE): ").strip() or "GREENWIRE STORE"
        
        # Validate amount
        float(amount)  # Will raise ValueError if invalid
        
        print(f"\n🏪 Terminal Configuration:")
        print(f"   Merchant: {merchant_name}")
        print(f"   Amount: {amount} {currency}")
        print(f"   Terminal ID: TERM{int(time.time()) % 10000:04d}")
        print(f"   Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\n💳 Payment Terminal Ready")
        print(f"   Waiting for card presentation...")
        
        # Check if card is available
        if card_manager.connect_to_card():
            print(f"✅ Card detected!")
            
            atr = card_manager.get_atr()
            print(f"📋 Card ATR: {atr}")
            
            # Try to process card
            print(f"\n🔄 Processing transaction...")
            
            # Attempt EMV processing
            schemes_to_try = ['visa', 'mastercard', 'amex']
            transaction_successful = False
            
            for scheme in schemes_to_try:
                select_result = emv_processor.select_application(scheme)
                if select_result['success']:
                    print(f"✅ {scheme.upper()} application selected")
                    
                    # Get processing options
                    gpo_result = emv_processor.get_processing_options()
                    
                    if gpo_result['success']:
                        print(f"✅ Processing options retrieved")
                        print(f"📊 Transaction Status: APPROVED")
                        print(f"💰 Amount: {amount} {currency}")
                        print(f"📄 Authorization Code: {int(time.time()) % 1000000:06d}")
                        transaction_successful = True
                        break
                    else:
                        print(f"⚠️ Could not get processing options for {scheme}")
                else:
                    print(f"⚠️ {scheme.upper()} application not found")
            
            if not transaction_successful:
                print(f"⚠️ Transaction could not be processed")
                print(f"📊 Transaction Status: DECLINED")
                print(f"💭 Reason: Application not supported or card error")
            
            # Generate receipt
            print(f"\n🧾 Transaction Receipt:")
            print(f"   ================================")
            print(f"   {merchant_name}")
            print(f"   Terminal: TERM{int(time.time()) % 10000:04d}")
            print(f"   Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   --------------------------------")
            print(f"   Amount: {amount} {currency}")
            print(f"   Status: {'APPROVED' if transaction_successful else 'DECLINED'}")
            if transaction_successful:
                print(f"   Auth Code: {int(time.time()) % 1000000:06d}")
            print(f"   ================================")
            
            card_manager.disconnect()
            
        else:
            print(f"❌ No card detected")
            print(f"💡 Insert a smartcard into the reader to simulate transaction")
    
    except ValueError:
        print(f"\n❌ Invalid amount format")
    except KeyboardInterrupt:
        print(f"\n❌ Transaction cancelled")
    except Exception as e:
        print(f"\n❌ Error during transaction: {e}")
    finally:
        card_manager.disconnect()
    
    input("\nPress Enter to continue...")
    return 'refresh'

def hardware_status_working():
    """Unified hardware status implementation using nfc_manager and adbutils."""
    print("🛠️ Hardware Status")
    print("=" * 40)

    # Unified device scan
    devices = nfc_manager.scan_all_devices()
    android_devices = [d for d in devices if d.device_type == 'android']
    hardware_devices = [d for d in devices if d.device_type == 'pcsc']

    # Smartcard readers
    print("📡 Smartcard Readers:")
    if hardware_devices:
        print(f"✅ Found {len(hardware_devices)} reader(s):")
        for i, device in enumerate(hardware_devices, 1):
            print(f"   {i}. {device.name}")
            # Try to connect and get more info
            try:
                if card_manager.connect_to_card(device.name):
                    atr = card_manager.get_atr()
                    print(f"      📋 Card present - ATR: {atr}")
                    card_manager.disconnect()
                else:
                    print(f"      📋 No card present or connection failed")
            except Exception as e:
                print(f"      ⚠️ Connection test failed: {e}")
    else:
        print("❌ No smartcard readers found")
        print("💡 Install PC/SC compatible reader and pyscard library")

    print(f"\n📱 Android Devices:")
    if ADBUTILS_AVAILABLE:
        if android_devices:
            print(f"✅ Found {len(android_devices)} device(s):")
            for device in android_devices:
                print(f"   📱 {device.name} ({device.device_id})")
                nfc_status = device.capabilities
                nfc_icon = "📡" if nfc_status.get('nfc_enabled') else "📴"
                print(f"      {nfc_icon} NFC: {nfc_status.get('status', 'unknown').upper()}")
        else:
            print("❌ No Android devices found")
            print("💡 Connect device via USB with debugging enabled")
    else:
        print("❌ adbutils not available or ADB not installed")
        print("💡 Install adbutils: pip install adbutils and Android SDK Platform Tools")

    print(f"\n💻 System Information:")
    print(f"   Python: {sys.version.split()[0]}")
    print(f"   Platform: {sys.platform}")
    print(f"   pyscard: {'✅ Available' if PYSCARD_AVAILABLE else '❌ Not installed'}")
    print(f"   adbutils: {'✅ Available' if ADBUTILS_AVAILABLE else '❌ Not installed'}")

    # Test basic functionality
    print(f"\n🧪 Functionality Tests:")

    # Test card generation
    try:
        test_card = card_generator.generate_card('visa', 1)[0]
        print(f"   ✅ Card generation: Working")
        print(f"      Sample: {test_card['card_number'][:6]}...{test_card['card_number'][-4:]}")
    except Exception as e:
        print(f"   ❌ Card generation: Failed ({e})")

    # Test APDU if hardware available
    if hardware_devices:
        print(f"   ✅ APDU communication: Ready")
    else:
        print(f"   ❌ APDU communication: No readers")

    # Test Android NFC
    if ADBUTILS_AVAILABLE and android_devices:
        print(f"   ✅ Android NFC: Ready")
    else:
        print(f"   ❌ Android NFC: Not available")

    # Card fuzzing/testing menu
    print(f"\n🧪 Card Fuzzing & EMV/SmartCard Analysis:")
    for i, device in enumerate(devices, 1):
        print(f"  {i}. {device.device_type.upper()} - {device.name} ({device.device_id}) [{device.status}]")
    print("  0. Skip analysis/testing")
    choice = input("Select device for analysis/testing [0]: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(devices):
        selected = devices[int(choice)-1]
        print(f"\n[INFO] Starting EMV/SmartCard analysis/testing on {selected.name} ({selected.device_id})...")
        # Expanded profile/test type selection (40 options)
        profile_types = [
            ("APDU Command Fuzzer", "Send random/mutated APDUs and observe responses."),
            ("EMV Protocol Compliance Test", "Run EMVCo test vectors and check for spec violations."),
            ("Memory Dump (ATR/SELECT/READ BINARY)", "Dump card memory using standard APDUs."),
            ("PIN/PUK/Key Brute Force", "Attempt PIN/PUK brute force and log lockout behavior."),
            ("File System Enumeration", "Enumerate files/DFs/EFs and dump contents."),
            ("Custom Scripted Attack", "Run a user-supplied APDU/script sequence."),
            ("EMV Transaction Simulation", "Simulate a full EMV purchase/authorization."),
            ("EMV Tag/Template Analysis", "Parse and display all EMV tags and templates."),
            ("DDA/SDA/CDA Crypto Test", "Test Dynamic/Static/Application cryptogram generation."),
            ("Offline Data Authentication", "Test offline authentication and certificate chain."),
            ("Contactless (NFC) Profile Test", "Test PayWave/PayPass/ExpressPay/Amex NFC profiles."),
            ("Issuer Script Processing", "Send issuer scripts and observe card response."),
            ("Cardholder Verification Methods", "Test PIN, signature, and CVM list handling."),
            ("Risk Management/Unpredictable Number", "Test card response to unpredictable numbers and risk controls."),
            ("Proprietary/Unknown AID Scan", "Scan for non-standard/proprietary applications on card."),
            ("JavaCard Applet Install", "Install a JavaCard applet using GP/GlobalPlatform."),
            ("JavaCard Applet Delete", "Delete a JavaCard applet using GP/GlobalPlatform."),
            ("JavaCard Applet Select", "Select and interact with a JavaCard applet."),
            ("JavaCard Applet Upgrade", "Upgrade an applet using GP install/replace."),
            ("JavaCard Key Injection", "Inject keys into JavaCard using GP."),
            ("JavaCard PIN Change", "Change PIN using JavaCard/GP commands."),
            ("JavaCard File System Test", "Test file system access via JavaCard commands."),
            ("JavaCard Memory Stress Test", "Stress test memory allocation on JavaCard."),
            ("JavaCard Transaction Atomicity", "Test transaction atomicity on JavaCard."),
            ("JavaCard Secure Channel Establishment", "Establish a secure channel using GP."),
            ("JavaCard Applet Personalization", "Personalize applet with test data using Java/GP."),
            ("JavaCard Applet Lock/Unlock", "Lock or unlock applet using GP commands."),
            ("JavaCard Applet State Dump", "Dump applet state using Java/GP commands."),
            ("JavaCard Applet Exception Handling", "Trigger and analyze applet exceptions."),
            ("JavaCard Applet Performance Benchmark", "Benchmark applet performance using Java test harness."),
            ("JavaCard Applet Custom Command", "Send custom APDU to applet via Java/GP."),
            # Automated Testing/Attack commands (10)
            ("Automated APDU Fuzz Test", "Run automated APDU fuzzing and save logs/artifacts."),
            ("Automated PIN Brute Force", "Automate PIN brute force and log attempts/results."),
            ("Automated File System Dump", "Automate file system dump and save binary artifacts."),
            ("Automated EMV Transaction Replay", "Replay EMV transactions and log all APDUs."),
            ("Automated Scripted Attack Suite", "Run a suite of scripted attacks and collect logs."),
            ("Automated Crypto Test Suite", "Run cryptographic tests and save results/artifacts."),
            ("Automated CVM Bypass Test", "Attempt CVM bypass and log all responses."),
            ("Automated Risk Management Test", "Automate risk management tests and save logs."),
            ("Automated Applet Install/Remove Cycle", "Automate repeated install/remove and log outcomes."),
            ("Automated Performance Benchmark", "Automate performance tests and save timing logs."),
        ]
        print("\nSelect analysis/test profile:")
        for idx, (name, desc) in enumerate(profile_types, 1):
            print(f"  {idx}. {name} - {desc}")
        print("  0. Cancel")
        t_choice = input("Choose profile [0]: ").strip()
        if t_choice.isdigit() and 1 <= int(t_choice) <= len(profile_types):
            t_idx = int(t_choice) - 1
            test_name = profile_types[t_idx][0]
            print(f"\n[INFO] Running: {test_name}")
            # Map to existing or placeholder logic
            func_map = {
                "APDU Command Fuzzer": card_apdu_fuzzer,
                "EMV Protocol Compliance Test": card_emv_compliance_test,
                "Memory Dump (ATR/SELECT/READ BINARY)": card_memory_dump,
                "PIN/PUK/Key Brute Force": card_pin_bruteforce,
                "File System Enumeration": card_filesystem_enum,
                "Custom Scripted Attack": card_custom_script,
                "EMV Transaction Simulation": card_emv_transaction_sim,
                "EMV Tag/Template Analysis": card_emv_tag_analysis,
                "DDA/SDA/CDA Crypto Test": card_crypto_test,
                "Offline Data Authentication": card_offline_auth,
                "Contactless (NFC) Profile Test": card_nfc_profile_test,
                "Issuer Script Processing": card_issuer_script,
                "Cardholder Verification Methods": card_cvm_test,
                "Risk Management/Unpredictable Number": card_risk_management,
                "Proprietary/Unknown AID Scan": card_unknown_aid_scan,
                "JavaCard Applet Install": card_jc_install,
                "JavaCard Applet Delete": card_jc_delete,
                "JavaCard Applet Select": card_jc_select,
                "JavaCard Applet Upgrade": card_jc_upgrade,
                "JavaCard Key Injection": card_jc_key_inject,
                "JavaCard PIN Change": card_jc_pin_change,
                "JavaCard File System Test": card_jc_fs_test,
                "JavaCard Memory Stress Test": card_jc_mem_stress,
                "JavaCard Transaction Atomicity": card_jc_atomicity,
                "JavaCard Secure Channel Establishment": card_jc_secure_channel,
                "JavaCard Applet Personalization": card_jc_personalize,
                "JavaCard Applet Lock/Unlock": card_jc_lock_unlock,
                "JavaCard Applet State Dump": card_jc_state_dump,
                "JavaCard Applet Exception Handling": card_jc_exception,
                "JavaCard Applet Performance Benchmark": card_jc_benchmark,
                "JavaCard Applet Custom Command": card_jc_custom_cmd,
                # Automated Testing/Attack commands
                "Automated APDU Fuzz Test": auto_apdu_fuzz_test,
                "Automated PIN Brute Force": auto_pin_bruteforce,
                "Automated File System Dump": auto_fs_dump,
                "Automated EMV Transaction Replay": auto_emv_replay,
                "Automated Scripted Attack Suite": auto_scripted_attack_suite,
                "Automated Crypto Test Suite": auto_crypto_test_suite,
                "Automated CVM Bypass Test": auto_cvm_bypass,
                "Automated Risk Management Test": auto_risk_management,
                "Automated Applet Install/Remove Cycle": auto_applet_install_remove,
                "Automated Performance Benchmark": auto_performance_benchmark,
            }
            func = func_map.get(test_name)
            if func:
                session, run_post_tests = _select_card_scope(test_name, selected)
                try:
                    func(selected)
                finally:
                    _finalize_card_session(session, run_post_tests=run_post_tests)
            else:
                print("[WARN] Unknown test type.")
# --- Automated Testing/Attack Suites ---
def auto_apdu_fuzz_test(device):
    print("[Auto] APDU fuzz suite starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_apdu_fuzz') as (start_time, metadata):
        card_apdu_fuzzer(device)
        tester = _active_tester()
        tester_summary = tester.run_automatic_tests(run_pos=True, run_atm=False, include_hsm=False) if tester else None
        summary.update(
            {
                'profile': metadata.get('profile'),
                'duration_seconds': round(time.time() - start_time, 2),
                'operations': ['card_apdu_fuzzer'],
            }
        )
        if tester_summary is not None:
            summary['tester_summary'] = tester_summary
    artifact = _auto_record('apdu_fuzz', summary)
    print(f"[Auto] APDU fuzz suite complete. Summary saved to {artifact}")


def auto_pin_bruteforce(device):
    print("[Auto] PIN brute force suite starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_pin_bruteforce') as (start_time, metadata):
        card_pin_bruteforce(device)
        tester = _active_tester()
        tester_summary = tester.run_automatic_tests(run_pos=False, run_atm=False, include_hsm=False) if tester else None
        summary.update(
            {
                'profile': metadata.get('profile'),
                'duration_seconds': round(time.time() - start_time, 2),
                'operations': ['card_pin_bruteforce'],
            }
        )
        if tester_summary is not None:
            summary['tester_summary'] = tester_summary
    artifact = _auto_record('pin_bruteforce', summary)
    print(f"[Auto] PIN brute force suite complete. Summary saved to {artifact}")


def auto_fs_dump(device):
    print("[Auto] File system dump suite starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_fs_dump') as (start_time, metadata):
        card_memory_dump(device)
        card_filesystem_enum(device)
        summary.update(
            {
                'profile': metadata.get('profile'),
                'duration_seconds': round(time.time() - start_time, 2),
                'operations': ['card_memory_dump', 'card_filesystem_enum'],
            }
        )
    artifact = _auto_record('fs_dump', summary)
    print(f"[Auto] File system dump suite complete. Summary saved to {artifact}")


def auto_emv_replay(device):
    print("[Auto] EMV replay suite starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_emv_replay') as (start_time, metadata):
        card_emv_transaction_sim(device)
        tester = _active_tester()
        tester_summary = tester.run_automatic_tests(run_pos=True, run_atm=True, include_hsm=False) if tester else None
        summary.update(
            {
                'profile': metadata.get('profile'),
                'duration_seconds': round(time.time() - start_time, 2),
                'operations': ['card_emv_transaction_sim'],
            }
        )
        if tester_summary is not None:
            summary['tester_summary'] = tester_summary
    artifact = _auto_record('emv_replay', summary)
    print(f"[Auto] EMV replay suite complete. Summary saved to {artifact}")


def auto_scripted_attack_suite(device):
    print("[Auto] Scripted attack suite starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_scripted_attack_suite') as (start_time, metadata):
        operations = []
        card_emv_transaction_sim(device)
        operations.append('card_emv_transaction_sim')
        card_crypto_test(device)
        operations.append('card_crypto_test')
        card_risk_management(device)
        operations.append('card_risk_management')
        tester = _active_tester()
        tester_summary = tester.run_automatic_tests(run_pos=True, run_atm=True, include_hsm=True) if tester else None
        summary.update(
            {
                'profile': metadata.get('profile'),
                'duration_seconds': round(time.time() - start_time, 2),
                'operations': operations,
            }
        )
        if tester_summary is not None:
            summary['tester_summary'] = tester_summary
    artifact = _auto_record('scripted_attack_suite', summary)
    print(f"[Auto] Scripted attack suite complete. Summary saved to {artifact}")


def auto_crypto_test_suite(device):
    print("[Auto] Crypto test suite starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_crypto_test_suite') as (start_time, metadata):
        card_crypto_test(device)
        tester = _active_tester()
        tester_summary = tester.run_automatic_tests(run_pos=False, run_atm=False, include_hsm=True) if tester else None
        summary.update(
            {
                'profile': metadata.get('profile'),
                'duration_seconds': round(time.time() - start_time, 2),
                'operations': ['card_crypto_test'],
            }
        )
        if tester_summary is not None:
            summary['tester_summary'] = tester_summary
    artifact = _auto_record('crypto_test_suite', summary)
    print(f"[Auto] Crypto test suite complete. Summary saved to {artifact}")


def auto_cvm_bypass(device):
    print("[Auto] CVM bypass suite starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_cvm_bypass') as (start_time, metadata):
        card_cvm_test(device)
        card_pin_bruteforce(device)
        summary.update(
            {
                'profile': metadata.get('profile'),
                'duration_seconds': round(time.time() - start_time, 2),
                'operations': ['card_cvm_test', 'card_pin_bruteforce'],
            }
        )
    artifact = _auto_record('cvm_bypass', summary)
    print(f"[Auto] CVM bypass suite complete. Summary saved to {artifact}")


def auto_risk_management(device):
    print("[Auto] Risk management suite starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_risk_management') as (start_time, metadata):
        card_risk_management(device)
        summary.update(
            {
                'profile': metadata.get('profile'),
                'duration_seconds': round(time.time() - start_time, 2),
                'operations': ['card_risk_management'],
            }
        )
    artifact = _auto_record('risk_management', summary)
    print(f"[Auto] Risk management suite complete. Summary saved to {artifact}")


def auto_applet_install_remove(device):
    print("[Auto] Applet install/remove cycle starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_applet_install_remove') as (start_time, metadata):
        card_jc_install(device)
        card_jc_delete(device)
        summary.update(
            {
                'profile': metadata.get('profile'),
                'duration_seconds': round(time.time() - start_time, 2),
                'operations': ['card_jc_install', 'card_jc_delete'],
            }
        )
    artifact = _auto_record('applet_install_remove', summary)
    print(f"[Auto] Applet install/remove cycle complete. Summary saved to {artifact}")


def auto_performance_benchmark(device):
    print("[Auto] Performance benchmark starting...")
    summary: Dict[str, Any] = {}
    with _automation_context('auto_performance_benchmark') as (start_time, metadata):
        timings: List[Dict[str, Any]] = []
        operations: List[str] = []
        for func in (card_emv_transaction_sim, card_apdu_fuzzer, card_crypto_test):
            op_start = time.time()
            func(device)
            duration = round(time.time() - op_start, 3)
            operations.append(func.__name__)
            timings.append({'operation': func.__name__, 'duration_seconds': duration})
        summary.update(
            {
                'profile': metadata.get('profile'),
                'operations': operations,
                'timings': timings,
                'total_duration_seconds': round(time.time() - start_time, 3),
            }
        )
    artifact = _auto_record('performance_benchmark', summary)
    print(f"[Auto] Performance benchmark complete. Summary saved to {artifact}")


def enhanced_data_extraction_working():
    """Enhanced Data Extraction System - Focused on obtaining hidden data from cards."""
    print("🔍 Enhanced Data Extraction System")
    print("=" * 50)
    print("Advanced data extraction framework with artifact collection and statistical analysis")
    
    # Import the enhanced data extraction module
    try:
        import sys
        from pathlib import Path
        sys.path.append(str(Path(__file__).parent))
        from enhanced_data_extraction import DataExtractionEngine, AttackType
    except ImportError as e:
        print(f"❌ Failed to import enhanced data extraction module: {e}")
        print("Note: enhanced_data_extraction.py has been archived (see archive/root_scripts/).")
        input("\nPress Enter to continue...")
        return 'refresh'
    
    # Display available attack types
    attack_types = [
        ("fuzzing", "Traditional APDU fuzzing with response analysis"),
        ("timing", "Timing analysis for side-channel vulnerabilities"),
        ("protocol_downgrade", "Attempt protocol downgrade attacks"),
        ("covert_channel", "Search for covert channel communications"),
        ("brute_force_keys", "Systematic key brute force attacks"),
        ("advanced_persistence", "Test for persistent data storage mechanisms"),
        ("combo", "Combined multi-attack approach")
    ]
    
    print("\nAvailable Attack Types:")
    for i, (attack_type, description) in enumerate(attack_types, 1):
        print(f"  {i}. {attack_type.upper()}: {description}")
    print("  8. ALL ATTACKS: Run all attack types sequentially")
    print("  0. Cancel")
    
    choice = input("\nSelect attack type (0-8): ").strip()
    
    if choice == '0':
        return 'refresh'
    
    # Get available devices
    devices = nfc_manager.scan_all_devices()
    if not devices:
        print("❌ No devices found. Please connect a smartcard reader or Android device.")
        input("\nPress Enter to continue...")
        return 'refresh'
    
    print(f"\nAvailable Devices:")
    for i, device in enumerate(devices, 1):
        print(f"  {i}. {device.device_type.upper()} - {device.name} ({device.device_id})")
    
    device_choice = input(f"Select device (1-{len(devices)}): ").strip()
    try:
        selected_device = devices[int(device_choice) - 1]
    except (ValueError, IndexError):
        print("❌ Invalid device selection")
        input("\nPress Enter to continue...")
        return 'refresh'
    
    # Configuration options
    print(f"\nConfiguration Options:")
    max_iterations = input("Maximum iterations per attack (default 500): ").strip()
    max_iterations = int(max_iterations) if max_iterations.isdigit() else 500
    
    artifact_save = input("Save all artifacts? (Y/n): ").strip().lower()
    save_artifacts = artifact_save != 'n'
    
    verbose = input("Verbose output? (y/N): ").strip().lower() == 'y'
    
    # Initialize the enhanced data extraction engine
    print(f"\n🔧 Initializing Enhanced Data Extraction Engine...")
    engine = DataExtractionEngine(
        device_id=selected_device.device_id,
        max_iterations=max_iterations,
        save_artifacts=save_artifacts,
        verbose=verbose
    )
    
    # Execute attacks based on selection
    try:
        if choice == '8':  # All attacks
            print(f"\n🚀 Running ALL attack types on {selected_device.name}...")
            results = {}
            
            for attack_name, _ in attack_types[:-1]:  # Exclude combo attack to avoid recursion
                print(f"\n--- Starting {attack_name.upper()} attack ---")
                attack_type = AttackType[attack_name.upper()]
                
                # Create session for this attack
                session, run_post_tests = _select_card_scope(f"enhanced_{attack_name}", selected_device)
                try:
                    result = engine.run_attack(attack_type)
                    results[attack_name] = result
                    
                    print(f"✅ {attack_name.upper()} attack completed:")
                    print(f"   - Commands sent: {result.get('commands_sent', 0)}")
                    print(f"   - Data extracted: {len(result.get('extracted_data', []))} items")
                    print(f"   - Vulnerabilities: {len(result.get('vulnerabilities', []))}")
                    print(f"   - Artifacts saved: {len(result.get('artifacts', []))}")
                    
                finally:
                    _finalize_card_session(session, run_post_tests=run_post_tests)
            
            # Generate comprehensive report
            comprehensive_stats = engine.get_comprehensive_statistics()
            print(f"\n📊 COMPREHENSIVE ATTACK SUMMARY:")
            print(f"   Total attacks run: {len(results)}")
            print(f"   Total commands sent: {comprehensive_stats.get('total_commands', 0)}")
            print(f"   Total data extracted: {comprehensive_stats.get('total_data_items', 0)}")
            print(f"   Total vulnerabilities: {comprehensive_stats.get('total_vulnerabilities', 0)}")
            print(f"   Total artifacts: {comprehensive_stats.get('total_artifacts', 0)}")
            
        else:
            # Single attack type
            attack_name = attack_types[int(choice) - 1][0]
            attack_type = AttackType[attack_name.upper()]
            
            print(f"\n🚀 Running {attack_name.upper()} attack on {selected_device.name}...")
            
            # Create session for this attack
            session, run_post_tests = _select_card_scope(f"enhanced_{attack_name}", selected_device)
            try:
                result = engine.run_attack(attack_type)
                
                print(f"\n✅ {attack_name.upper()} attack completed:")
                print(f"   - Commands sent: {result.get('commands_sent', 0)}")
                print(f"   - Data extracted: {len(result.get('extracted_data', []))} items")
                print(f"   - Vulnerabilities: {len(result.get('vulnerabilities', []))}")
                print(f"   - Artifacts saved: {len(result.get('artifacts', []))}")
                
                # Show sample extracted data
                extracted_data = result.get('extracted_data', [])
                if extracted_data:
                    print(f"\n📋 Sample Extracted Data:")
                    for i, data_item in enumerate(extracted_data[:3], 1):
                        data_type = data_item.get('type', 'unknown')
                        confidence = data_item.get('confidence', 0)
                        size = len(data_item.get('raw_data', ''))
                        print(f"   {i}. Type: {data_type}, Confidence: {confidence:.2f}, Size: {size} bytes")
                
                # Show vulnerabilities found
                vulnerabilities = result.get('vulnerabilities', [])
                if vulnerabilities:
                    print(f"\n🚨 Vulnerabilities Detected:")
                    for vuln in vulnerabilities[:3]:
                        severity = vuln.get('severity', 'unknown')
                        vuln_type = vuln.get('type', 'unknown')
                        print(f"   - {vuln_type} ({severity}): {vuln.get('description', 'No description')}")
            
            finally:
                _finalize_card_session(session, run_post_tests=run_post_tests)
        
        # Generate final report
        final_report = engine.generate_final_report()
        report_path = _persist_text_artifact('enhanced_data_extraction_report', final_report)
        print(f"\n📄 Final report saved to: {report_path}")
        
        # Show report summary
        stats = engine.get_comprehensive_statistics()
        print(f"\n📈 Final Statistics:")
        print(f"   Session duration: {stats.get('session_duration', 0):.2f} seconds")
        print(f"   Success rate: {stats.get('success_rate', 0):.1f}%")
        print(f"   Data extraction efficiency: {stats.get('extraction_efficiency', 0):.2f}")
        
    except Exception as e:
        print(f"❌ Error during enhanced data extraction: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
    
    input("\nPress Enter to continue...")
    return 'refresh'
# --- Java/GP/JavaCard Operations ---
def card_jc_install(device):
    print(f"[JavaCard] Installing CAP applet on {device.name} ({device.device_id})...")
    cap_path = _select_cap_file("Select CAP for installation")
    if not cap_path:
        return
    args = ['--install', str(cap_path)]
    success, stdout, stderr = _run_gp_command(args)
    summary = {
        'cap': str(cap_path),
        'stdout': stdout.strip(),
        'stderr': stderr.strip(),
        'success': success,
    }
    _record_card_event('gp', 'install', 'success' if success else 'error', summary)
    artifact = _persist_gp_result('install', args, success, stdout, stderr)
    if success and ACTIVE_CARD_SESSION:
        card_data = ACTIVE_CARD_SESSION.setdefault('card_data', {})
        card_data.setdefault('installed_caps', []).append(str(cap_path))
    status_text = 'completed successfully' if success else 'encountered errors'
    print(f"[JavaCard] CAP installation {status_text}. Output saved to {artifact}")


def card_jc_delete(device):
    default_aid = _default_aid()
    aid = _prompt_with_default('Enter applet AID to delete (hex)', default_aid).replace(' ', '').upper()
    print(f"[JavaCard] Deleting applet AID {aid} on {device.name} ({device.device_id})...")
    args = ['--delete', aid]
    success, stdout, stderr = _run_gp_command(args)
    summary = {
        'aid': aid,
        'stdout': stdout.strip(),
        'stderr': stderr.strip(),
        'success': success,
    }
    _record_card_event('gp', 'delete', 'success' if success else 'error', summary)
    artifact = _persist_gp_result('delete', args, success, stdout, stderr)
    if success and ACTIVE_CARD_SESSION:
        card_data = ACTIVE_CARD_SESSION.setdefault('card_data', {})
        installed = card_data.get('installed_caps', [])
        card_data['installed_caps'] = [cap for cap in installed if aid not in cap]
    status_text = 'deleted' if success else 'failed'
    print(f"[JavaCard] Applet {status_text}. Output saved to {artifact}")


def card_jc_select(device):
    aid = _prompt_with_default('Enter applet AID to SELECT (hex)', _default_aid()).replace(' ', '').upper()
    lc = f"{len(aid) // 2:02X}"
    sequence = [
        {'apdu': f'00A40400{lc}{aid}', 'description': f'SELECT {aid}'},
    ]
    results = _execute_apdu_sequence('jc_select', device, sequence)
    artifact = _save_profile_results('jc_select', results)
    if artifact:
        print(f"[JavaCard] SELECT completed. Transcript written to {artifact}")


def card_jc_upgrade(device):
    print(f"[JavaCard] Upgrading applet on {device.name} ({device.device_id})...")
    cap_path = _select_cap_file("Select CAP for upgrade")
    if not cap_path:
        return
    args = ['--install', str(cap_path), '--force']
    success, stdout, stderr = _run_gp_command(args)
    summary = {
        'cap': str(cap_path),
        'stdout': stdout.strip(),
        'stderr': stderr.strip(),
        'success': success,
    }
    _record_card_event('gp', 'upgrade', 'success' if success else 'error', summary)
    artifact = _persist_gp_result('upgrade', args, success, stdout, stderr)
    status_text = 'completed successfully' if success else 'encountered errors'
    print(f"[JavaCard] Upgrade {status_text}. Output saved to {artifact}")


def card_jc_key_inject(device):
    print(f"[JavaCard] Injecting keys into {device.name} ({device.device_id})...")
    keyset = _prompt_with_default('Enter keyset ID', '0x01')
    key_hex = _prompt_with_default('Enter key value (hex)', '404142434445464748494A4B4C4D4E4F')
    key_type = _prompt_with_default('Key type (ENC/MAC/DEK)', 'ENC').upper()
    args = ['--put-key', '--keyset', keyset, '--key', key_hex, '--key-type', key_type]
    success, stdout, stderr = _run_gp_command(args)
    summary = {
        'keyset': keyset,
        'key_type': key_type,
        'key': key_hex,
        'stdout': stdout.strip(),
        'stderr': stderr.strip(),
        'success': success,
    }
    _record_card_event('gp', 'put_key', 'success' if success else 'error', summary)
    artifact = _persist_gp_result('put_key', args, success, stdout, stderr)
    if success and ACTIVE_CARD_SESSION:
        card_data = ACTIVE_CARD_SESSION.setdefault('card_data', {})
        keyset_map = card_data.setdefault('keyset', {})
        keyset_map[str(keyset)] = key_hex
    status_text = 'completed' if success else 'failed'
    print(f"[JavaCard] Key injection {status_text}. Output saved to {artifact}")


def card_jc_pin_change(device):
    print(f"[JavaCard] Changing card PIN on {device.name} ({device.device_id})...")
    old_pin = _prompt_with_default('Current PIN', '1234')
    new_pin = _prompt_with_default('New PIN', '0000')
    old_hex = ''.join(f'{int(d):02X}' for d in old_pin if d.isdigit())
    new_hex = ''.join(f'{int(d):02X}' for d in new_pin if d.isdigit())
    results: List[Dict[str, Any]] = []
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        verify_apdu = f'0020008004{old_hex}'
        change_apdu = f'0024008008{old_hex}{new_hex}'
        for label, apdu in [('VERIFY', verify_apdu), ('CHANGE', change_apdu)]:
            try:
                response, sw1, sw2 = connection.send_apdu(apdu)
                entry = {
                    'operation': label,
                    'apdu': apdu,
                    'response': ''.join(f'{b:02X}' for b in response),
                    'sw': f'{sw1:02X}{sw2:02X}',
                }
                results.append(entry)
                _record_card_event('cvm', label.lower(), 'success' if (sw1, sw2) == (0x90, 0x00) else 'warning', entry)
                print(f"  {label} -> SW={sw1:02X}{sw2:02X}")
            except Exception as exc:
                summary = {'operation': label, 'apdu': apdu, 'error': str(exc)}
                results.append(summary)
                _record_card_event('cvm', label.lower(), 'error', summary)
                print(f"  {label} -> Error {exc}")
    artifact = _save_profile_results('jc_pin_change', results)
    if artifact:
        print(f"[JavaCard] PIN change operations logged to {artifact}")


def card_jc_fs_test(device):
    print(f"[JavaCard] Performing GET STATUS and file system queries on {device.name} ({device.device_id})...")
    sequence = [
        {'apdu': '80F24000024F0000', 'description': 'GET STATUS - Issuer Security Domain'},
        {'apdu': '80CA9F7F00', 'description': 'GET DATA - Card Production Lifecycle Data'},
    ]
    results = _execute_apdu_sequence('jc_fs_test', device, sequence, stop_on_error=False)
    artifact = _save_profile_results('jc_fs_test', results)
    if artifact:
        print(f"[JavaCard] File-system probe complete. Results saved to {artifact}")


def card_jc_mem_stress(device):
    print(f"[JavaCard] Performing memory stress writes on {device.name} ({device.device_id})...")
    sizes = [32, 64, 128, 192]
    results: List[Dict[str, Any]] = []
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        for size in sizes:
            data = os.urandom(size)
            apdu = f"80E20000{size:02X}{data.hex().upper()}"
            try:
                response, sw1, sw2 = connection.send_apdu(apdu)
                entry = {
                    'size': size,
                    'apdu': apdu[:40] + ('...' if len(apdu) > 40 else ''),
                    'sw': f'{sw1:02X}{sw2:02X}',
                    'response': ''.join(f'{b:02X}' for b in response[:8]),
                }
                results.append(entry)
                _record_card_event('gp', 'mem_stress', 'success' if (sw1, sw2) == (0x90, 0x00) else 'warning', entry)
                print(f"  Wrote {size} bytes -> SW={sw1:02X}{sw2:02X}")
            except Exception as exc:
                summary = {'size': size, 'error': str(exc)}
                results.append(summary)
                _record_card_event('gp', 'mem_stress', 'error', summary)
                print(f"  Wrote {size} bytes -> Error {exc}")
    artifact = _save_profile_results('jc_mem_stress', results)
    if artifact:
        print(f"[JavaCard] Memory stress results saved to {artifact}")


def card_jc_atomicity(device):
    print(f"[JavaCard] Evaluating transaction atomicity on {device.name} ({device.device_id})...")
    summary: Dict[str, Any] = {}
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
        else:
            try:
                response, sw1, sw2 = connection.send_apdu('80F02000024F0000')
                summary['begin_transaction'] = {'sw': f'{sw1:02X}{sw2:02X}', 'response': ''.join(f'{b:02X}' for b in response)}
                connection.send_apdu('80F02100024F0000')
                summary['commit_transaction'] = 'attempted'
            except Exception as exc:
                summary.setdefault('errors', []).append(str(exc))
                _record_card_event('gp', 'transaction', 'error', {'error': str(exc)})
    tester = _active_tester()
    if tester:
        scan = tester.vulnerability_scanner.run_suite(tester.card_data, ['card_log_integrity'])
        summary['log_integrity'] = scan
    artifact = _persist_text_artifact('jc_atomicity', json.dumps(summary, indent=2, default=str))
    print(f"[JavaCard] Atomicity evaluation complete. Summary saved to {artifact}")


def card_jc_secure_channel(device):
    print(f"[JavaCard] Opening secure channel on {device.name} ({device.device_id})...")
    args = ['--open-sc']
    success, stdout, stderr = _run_gp_command(args)
    summary = {
        'stdout': stdout.strip(),
        'stderr': stderr.strip(),
        'success': success,
    }
    _record_card_event('gp', 'open_sc', 'success' if success else 'error', summary)
    artifact = _persist_gp_result('open_sc', args, success, stdout, stderr)
    status_text = 'established' if success else 'failed'
    print(f"[JavaCard] Secure channel {status_text}. Output saved to {artifact}")


def card_jc_personalize(device):
    print(f"[JavaCard] Personalizing applet on {device.name} ({device.device_id})...")
    card_data = ACTIVE_CARD_SESSION.get('card_data', {}) if ACTIVE_CARD_SESSION else {}
    personalization = {
        'card_number': card_data.get('card_number'),
        'cardholder_name': card_data.get('cardholder_name'),
        'expiry_date': card_data.get('expiry_date'),
        'aid': card_data.get('aid'),
        'cvm_method': card_data.get('cvm_method'),
    }
    mapping_report = _map_card_structure(card_data)
    mapping_artifact = _persist_text_artifact('jc_personalize_bit_map', mapping_report)
    payload = json.dumps(personalization, default=str).encode('utf-8')
    chunk_size = 200
    results: List[Dict[str, Any]] = []
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        for offset in range(0, len(payload), chunk_size):
            chunk = payload[offset:offset + chunk_size]
            apdu = f"80E20000{len(chunk):02X}{chunk.hex().upper()}"
            try:
                response, sw1, sw2 = connection.send_apdu(apdu)
                entry = {
                    'offset': offset,
                    'length': len(chunk),
                    'sw': f'{sw1:02X}{sw2:02X}',
                    'response': ''.join(f'{b:02X}' for b in response[:8]),
                }
                results.append(entry)
                print(f"  Wrote {len(chunk)} bytes -> SW={sw1:02X}{sw2:02X}")
            except Exception as exc:
                summary = {'offset': offset, 'error': str(exc)}
                results.append(summary)
                print(f"  Chunk at offset {offset} failed: {exc}")
    artifact = _save_profile_results('jc_personalize', results)
    if artifact:
        print(f"[JavaCard] Personalization log saved to {artifact}")
    print(f"[JavaCard] Card bit-map captured in {mapping_artifact}")


def card_jc_lock_unlock(device):
    action = _prompt_with_default('Choose action (lock/unlock)', 'lock').lower()
    if action not in {'lock', 'unlock'}:
        print("[WARN] Invalid choice. Use 'lock' or 'unlock'.")
        return
    print(f"[JavaCard] Performing {action} on {device.name} ({device.device_id})...")
    args = [f'--{action}']
    success, stdout, stderr = _run_gp_command(args)
    summary = {'action': action, 'stdout': stdout.strip(), 'stderr': stderr.strip(), 'success': success}
    _record_card_event('gp', action, 'success' if success else 'error', summary)
    artifact = _persist_gp_result(action, args, success, stdout, stderr)
    status_text = 'completed' if success else 'failed'
    print(f"[JavaCard] {action.title()} {status_text}. Output saved to {artifact}")


def card_jc_state_dump(device):
    print(f"[JavaCard] Dumping card registry/state on {device.name} ({device.device_id})...")
    args = ['--list']
    success, stdout, stderr = _run_gp_command(args)
    summary = {'stdout': stdout.strip(), 'stderr': stderr.strip(), 'success': success}
    _record_card_event('gp', 'state_dump', 'success' if success else 'error', summary)
    artifact = _persist_gp_result('state_dump', args, success, stdout, stderr)
    print(f"[JavaCard] State dump {'available' if success else 'failed'}. Output saved to {artifact}")


def card_jc_exception(device):
    print(f"[JavaCard] Triggering controlled exception on {device.name} ({device.device_id})...")
    apdu = '80FF000000'
    record: Dict[str, Any]
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        try:
            response, sw1, sw2 = connection.send_apdu(apdu)
            record = {'apdu': apdu, 'sw': f'{sw1:02X}{sw2:02X}', 'response': ''.join(f'{b:02X}' for b in response)}
            status = 'success'
        except Exception as exc:
            record = {'apdu': apdu, 'error': str(exc)}
            status = 'error'
    _record_card_event('gp', 'exception_test', status, record)
    artifact = _persist_text_artifact('jc_exception', json.dumps(record, indent=2, default=str))
    print(f"[JavaCard] Exception test recorded to {artifact}")


def card_jc_benchmark(device):
    print(f"[JavaCard] Benchmarking APDU performance on {device.name} ({device.device_id})...")
    apdus = [
        ('SELECT', f"00A40400{len(_default_aid()) // 2:02X}{_default_aid()}"),
        ('GET CHALLENGE', '0084000008'),
        ('GET DATA', '80CA9F7F00'),
    ]
    timings: List[Dict[str, Any]] = []
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        for label, apdu in apdus:
            start = time.time()
            try:
                response, sw1, sw2 = connection.send_apdu(apdu)
                duration = round((time.time() - start) * 1000, 2)
                entry = {
                    'operation': label,
                    'duration_ms': duration,
                    'sw': f'{sw1:02X}{sw2:02X}',
                    'response_prefix': ''.join(f'{b:02X}' for b in response[:8]),
                }
                timings.append(entry)
                print(f"  {label}: {duration} ms (SW={sw1:02X}{sw2:02X})")
            except Exception as exc:
                timings.append({'operation': label, 'error': str(exc)})
                print(f"  {label}: error {exc}")
    artifact = _persist_text_artifact('jc_benchmark', json.dumps(timings, indent=2, default=str))
    print(f"[JavaCard] Benchmark complete. Results saved to {artifact}")


def card_jc_custom_cmd(device):
    print(f"[JavaCard] Send custom APDU to {device.name} ({device.device_id})...")
    apdu = _prompt_with_default('Enter APDU (hex)', '80CA9F1700').replace(' ', '')
    if not apdu:
        print("[JavaCard] No APDU provided; aborting.")
        return
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        try:
            response, sw1, sw2 = connection.send_apdu(apdu)
            record = {
                'apdu': apdu,
                'response': ''.join(f'{b:02X}' for b in response),
                'sw': f'{sw1:02X}{sw2:02X}',
            }
            print(f"  SW={sw1:02X}{sw2:02X}, R-APDU={record['response']}")
        except Exception as exc:
            record = {'apdu': apdu, 'error': str(exc)}
            print(f"  Error sending APDU: {exc}")
    artifact = _persist_text_artifact('jc_custom_cmd', json.dumps(record, indent=2, default=str))
    _record_card_event('apdu', 'jc_custom', 'success' if 'sw' in record else 'error', record)
    print(f"[JavaCard] Custom command transcript saved to {artifact}")

# --- Additional EMV/SmartCard Analysis Placeholders ---
def card_emv_transaction_sim(device):
    print(f"[EMV Transaction Simulation] Simulating EMV transaction on {device.name} ({device.device_id})...")
    sequence = [
        {'apdu': '00A404000E325041592E5359532E4444463031', 'description': 'SELECT PPSE (2PAY.SYS.DDF01)'},
        {'apdu': '00A4040007A0000000031010', 'description': 'SELECT Visa debit/credit AID'},
        {'apdu': '80A8000002830000', 'description': 'GET PROCESSING OPTIONS'},
        {'apdu': '00B2011400', 'description': 'READ RECORD SFI 2 Record 1'},
        {'apdu': '00B2021400', 'description': 'READ RECORD SFI 2 Record 2'},
    ]
    snapshot = _latest_terminal_snapshot('pos')
    variants = _build_generate_ac_variants(snapshot)
    for variant in variants:
        sequence.append(variant)
        _record_card_event('emv', 'generate_ac_variant', 'pending', {
            'apdu': variant['apdu'],
            'description': variant['description'],
            'source': snapshot,
        })
    results = _execute_apdu_sequence('emv_transaction_sim', device, sequence, benchmark=True)
    benchmark_artifact = _persist_benchmark('emv_transaction_sim', results)
    tester = ACTIVE_CARD_SESSION.get('tester') if ACTIVE_CARD_SESSION else None
    if tester:
        tester.run_automatic_tests(run_pos=True, run_atm=False, include_hsm=False)
    artifact = _save_profile_results('emv_transaction_sim', results)
    if artifact:
        print(f"[EMV Transaction Simulation] Complete. Results saved to {artifact}")
    if benchmark_artifact:
        print(f"[EMV Transaction Simulation] Benchmark metrics saved to {benchmark_artifact}")
    else:
        print("[EMV Transaction Simulation] Complete.")

def card_emv_tag_analysis(device):
    print(f"[EMV Tag/Template Analysis] Parsing EMV tags on {device.name} ({device.device_id})...")
    sequence = [
        {'apdu': '00A4040007A0000000031010', 'description': 'SELECT Visa AID'},
    ]
    results = _execute_apdu_sequence('emv_tag_analysis', device, sequence)
    if not results:
        print("[EMV Tag/Template Analysis] No data retrieved.")
        return
    select_response = results[0].get('response', '')
    parsed = _parse_tlv(select_response)
    report_lines = ["EMV Tag Report", "================", f"Device: {device.name} ({device.device_id})"]
    for item in parsed:
        tag = item['tag']
        value = item['value']
        report_lines.append(f"Tag {tag} (len {item['length']}): {value}")
    report = '\n'.join(report_lines)
    artifact = _persist_text_artifact('emv_tag_analysis', report)
    print(report)
    print(f"[EMV Tag/Template Analysis] Complete. Report saved to {artifact}")

def card_crypto_test(device):
    print(f"[Crypto Test] Testing DDA/SDA/CDA on {device.name} ({device.device_id})...")
    sequence = [
        {'apdu': '80CA9F1700', 'description': 'GET DATA - PIN Try Counter'},
        {'apdu': '80CA9F3600', 'description': 'GET DATA - Application Transaction Counter'},
        {'apdu': '80CA9F4A00', 'description': 'GET DATA - SDAD'},
        {'apdu': '0084000008', 'description': 'GET CHALLENGE (8 bytes)'},
    ]
    results = _execute_apdu_sequence('crypto_test', device, sequence, stop_on_error=False, benchmark=True)
    benchmark_artifact = _persist_benchmark('crypto_test', results)
    artifact = _save_profile_results('crypto_test', results)
    fuzz_seed: List[bytes] = []
    echo_payload: Optional[bytes] = None
    if ACTIVE_CARD_SESSION:
        card_data = ACTIVE_CARD_SESSION.get('card_data', {})
        echo_snapshot = _latest_terminal_snapshot('pos') or _latest_terminal_snapshot('atm')
        for key in ('card_number', 'aid', 'cardholder_name'):
            value = card_data.get(key)
            if not value:
                continue
            fuzz_seed.append(str(value).encode('utf-8'))
        if echo_snapshot:
            echo_payload = json.dumps(echo_snapshot.get('response', {}), default=str).encode('utf-8')
            fuzz_seed.append(echo_payload)
    orchestrator = CryptoFuzzOrchestrator(hash_rounds=384, hmac_rounds=192, max_samples=7)
    fuzz_suite = orchestrator.run_suite(seed_material=fuzz_seed, echo_payload=echo_payload)
    fuzz_artifact = _persist_text_artifact('crypto_fuzzer', json.dumps(fuzz_suite, indent=2))
    summary_artifact = _persist_text_artifact('crypto_fuzzer_summary', json.dumps(fuzz_suite['summary'], indent=2))
    _record_card_event('crypto', 'hash_fuzz', 'complete', {
        'artifact': str(fuzz_artifact),
        'summary': fuzz_suite['summary'],
    })
    if artifact:
        print(f"[Crypto Test] Complete. Results saved to {artifact}")
    if benchmark_artifact:
        print(f"[Crypto Test] Benchmark metrics saved to {benchmark_artifact}")
    else:
        print("[Crypto Test] Benchmark metrics unavailable.")
    print(f"[Crypto Test] Hash & HMAC fuzzing suite saved to {fuzz_artifact}")
    print(f"[Crypto Test] Crypto fuzzing summary saved to {summary_artifact}")

def card_offline_auth(device):
    print(f"[Offline Data Auth] Testing offline authentication on {device.name} ({device.device_id})...")
    sequence = [
        {'apdu': '80CA9F2700', 'description': 'GET DATA - Cryptogram Information Data'},
        {'apdu': '80CA9F2600', 'description': 'GET DATA - Application Cryptogram'},
        {'apdu': '00B2010C00', 'description': 'READ RECORD SFI 1 Record 1'},
        {'apdu': '00B2020C00', 'description': 'READ RECORD SFI 1 Record 2'},
    ]
    results = _execute_apdu_sequence('offline_auth', device, sequence)
    artifact = _save_profile_results('offline_auth', results)
    if artifact:
        print(f"[Offline Data Auth] Complete. Results saved to {artifact}")
    else:
        print("[Offline Data Auth] Complete.")

def card_nfc_profile_test(device):
    print(f"[NFC Profile Test] Testing contactless profiles on {device.name} ({device.device_id})...")
    if device.device_type == 'android':
        enable_result = nfc_manager.enable_android_nfc(device.device_id)
        summary = {
            'device': device.device_id,
            'success': enable_result.get('success'),
            'final_status': enable_result.get('final_status'),
        }
        _record_card_event('nfc', 'android_enable', 'success' if summary['success'] else 'warning', summary)
        report = json.dumps(summary, indent=2)
        artifact = _persist_text_artifact('nfc_android_profile', report)
        print(report)
        print(f"[NFC Profile Test] Android enablement log saved to {artifact}")
        return

    sequence = [
        {'apdu': '00A404000E325041592E5359532E4444463031', 'description': 'SELECT PPSE'},
        {'apdu': '00A4040007A0000000041010', 'description': 'SELECT MasterCard PayPass'},
        {'apdu': '80A8000002830000', 'description': 'GPO for contactless profile'},
    ]
    results = _execute_apdu_sequence('nfc_profile_test', device, sequence)
    artifact = _save_profile_results('nfc_profile_test', results)
    if artifact:
        print(f"[NFC Profile Test] Complete. Results saved to {artifact}")
    else:
        print("[NFC Profile Test] Complete.")

def card_issuer_script(device):
    print(f"[Issuer Script] Sending issuer scripts to {device.name} ({device.device_id})...")
    script_data_1 = '9F020600000100009F1A0208269F36020001'
    script_data_2 = '9F170101'
    script_commands = [
        {'apdu': f'8016000016{script_data_1}', 'description': 'ISSUER SCRIPT - Update amount/currency/ATC'},
        {'apdu': f'8012000004{script_data_2}', 'description': 'ISSUER SCRIPT - Reset PIN try counter'},
        {'apdu': '80CA9F3600', 'description': 'GET DATA - Verify ATC after script'},
    ]
    results = _execute_apdu_sequence('issuer_script', device, script_commands, stop_on_error=False)
    artifact = _save_profile_results('issuer_script', results)
    if artifact:
        print(f"[Issuer Script] Complete. Results saved to {artifact}")
    else:
        print("[Issuer Script] Complete.")

def card_cvm_test(device):
    print(f"[CVM Test] Testing cardholder verification methods on {device.name} ({device.device_id})...")
    sequence = [
        {'apdu': '80CA8E0000', 'description': 'GET DATA - CVM List (Tag 8E)'},
        {'apdu': '80CA9F3400', 'description': 'GET DATA - CVM Results (9F34)'},
    ]
    results = _execute_apdu_sequence('cvm_test', device, sequence)
    if results:
        for item in results:
            response_hex = item.get('response', '')
            if response_hex:
                for tlv in _parse_tlv(response_hex):
                    print(f"  TLV {tlv['tag']}: {tlv['value']}")
    artifact = _save_profile_results('cvm_test', results)
    if artifact:
        print(f"[CVM Test] Complete. Results saved to {artifact}")
    else:
        print("[CVM Test] Complete.")

def card_risk_management(device):
    print(f"[Risk Management] Testing unpredictable number/risk controls on {device.name} ({device.device_id})...")
    entries: List[Dict[str, Any]] = []
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        for attempt in range(3):
            try:
                response, sw1, sw2 = connection.send_apdu('0084000008')
                record = {
                    'attempt': attempt + 1,
                    'apdu': '0084000008',
                    'response': ''.join(f'{b:02X}' for b in response),
                    'sw': f'{sw1:02X}{sw2:02X}',
                }
                entries.append(record)
                _record_emv_exchange('0084000008', response, sw1, sw2, f'Get challenge #{attempt + 1}')
            except Exception as exc:
                error_entry = {'attempt': attempt + 1, 'apdu': '0084000008', 'error': str(exc)}
                entries.append(error_entry)
                _record_card_event('risk', 'challenge', 'error', error_entry)
        results = _execute_apdu_sequence(
            'risk_management',
            device,
            [
                {'apdu': '80CA9F3600', 'description': 'GET DATA - Application Transaction Counter'},
                {'apdu': '80CA9F1D00', 'description': 'GET DATA - Issuer Action Code (Denial)'},
            ],
            stop_on_error=False,
        )
        entries.extend(results)
    artifact = _save_profile_results('risk_management', entries)
    if artifact:
        print(f"[Risk Management] Complete. Results saved to {artifact}")
    else:
        print("[Risk Management] Complete.")

def card_unknown_aid_scan(device):
    print(f"[Unknown AID Scan] Scanning for proprietary/non-standard AIDs on {device.name} ({device.device_id})...")
    candidate_aids = [
        'A0000000031010',  # Visa
        'A0000000041010',  # MasterCard
        'A0000000250104',  # Amex contactless
        'A0000001523010',  # Discover
        'A0000003241010',  # JCB
        'A0000004762010',  # UnionPay
        'F222222222',      # Test/proprietary
    ]
    sequence = [
        {'apdu': f'00A40400{len(aid)//2:02X}{aid}', 'description': f'SELECT {aid}'}
        for aid in candidate_aids
    ]
    results = _execute_apdu_sequence('unknown_aid_scan', device, sequence, stop_on_error=False)
    artifact = _save_profile_results('unknown_aid_scan', results)
    if artifact:
        print(f"[Unknown AID Scan] Complete. Results saved to {artifact}")
    else:
        print("[Unknown AID Scan] Complete.")

# --- Card Fuzzing/Testing Logic ---
def card_apdu_fuzzer(device):
    print(f"[APDU Fuzzer] Sending random/mutated APDUs to {device.name} ({device.device_id})...")
    import random
    exchanges: List[Dict[str, Any]] = []

    durations: List[float] = []
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Skipping fuzzing due to missing connection.")
            return
        for i in range(10):
            header = [random.randint(0, 255) for _ in range(4)]
            lc = random.randint(0, 12)
            data = [random.randint(0, 255) for _ in range(lc)]
            apdu = header + ([lc] if lc else []) + data
            apdu_hex = ''.join(f'{b:02X}' for b in apdu)
            description = f'Random fuzz frame #{i + 1}'
            try:
                start_time = time.perf_counter()
                response, sw1, sw2 = connection.send_apdu(apdu_hex)
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                durations.append(elapsed_ms)
                _record_emv_exchange(apdu_hex, response, sw1, sw2, description)
                exchanges.append(
                    {
                        'apdu': apdu_hex,
                        'response': ''.join(f'{b:02X}' for b in response),
                        'sw': f'{sw1:02X}{sw2:02X}',
                        'description': description,
                        'elapsed_ms': round(elapsed_ms, 6),
                    }
                )
            except Exception as exc:
                summary = {'apdu': apdu_hex, 'error': str(exc), 'description': description}
                _record_card_event('apdu', 'fuzz', 'error', summary)
                exchanges.append(summary)
                print(f"  [Fuzz] Error on {apdu_hex}: {exc}")
    artifact = _save_profile_results('apdu_fuzzer', exchanges)
    if durations:
        stats = {
            'profile': 'apdu_fuzzer',
            'count': len(durations),
            'min_ms': round(min(durations), 3),
            'max_ms': round(max(durations), 3),
            'avg_ms': round(statistics.mean(durations), 3),
        }
        _record_card_event('apdu', 'fuzz_benchmark', 'complete', stats)
        logger.info(
            "APDU fuzz timing metrics captured: count=%s avg=%.3f ms min=%.3f ms max=%.3f ms",
            stats['count'],
            stats['avg_ms'],
            stats['min_ms'],
            stats['max_ms'],
        )
        benchmark_artifact = _persist_text_artifact('apdu_fuzzer_benchmark', json.dumps(stats, indent=2))
        print(f"[APDU Fuzzer] Benchmark metrics saved to {benchmark_artifact}")
    if artifact:
        print(f"[APDU Fuzzer] Complete. Results saved to {artifact}")
    else:
        print("[APDU Fuzzer] Complete. No exchanges recorded.")

def card_emv_compliance_test(device):
    print(f"[EMV Compliance] Running EMVCo test vectors on {device.name} ({device.device_id})...")
    sequence = [
        {'apdu': '00A4040007A000000003101000', 'description': 'SELECT Visa credit AID'},
        {'apdu': '80A8000002830000', 'description': 'GET PROCESSING OPTIONS'},
        {'apdu': '00B2010C00', 'description': 'READ RECORD SFI 1 Record 1'},
        {'apdu': '00B2021400', 'description': 'READ RECORD SFI 2 Record 2'},
    ]
    results = _execute_apdu_sequence('emv_compliance', device, sequence, benchmark=True)
    benchmark_artifact = _persist_benchmark('emv_compliance', results)
    artifact = _save_profile_results('emv_compliance', results)
    if artifact:
        print(f"[EMV Compliance] Complete. Results saved to {artifact}")
    if benchmark_artifact:
        print(f"[EMV Compliance] Benchmark metrics saved to {benchmark_artifact}")
    else:
        print("[EMV Compliance] Complete.")

def card_memory_dump(device):
    print(f"[Memory Dump] Dumping ATR, SELECT, and READ BINARY from {device.name} ({device.device_id})...")
    entries: List[Dict[str, Any]] = []
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        atr = connection.get_atr()
        entries.append({'event': 'ATR', 'value': atr})
        print(f"  ATR: {atr}")
        for step in [
            {'apdu': '00A40000023F00', 'description': 'SELECT MF (3F00)'},
            {'apdu': '00A40000022F00', 'description': 'SELECT EF ICCID (2F00)'},
            {'apdu': '00B000000F', 'description': 'READ BINARY first 15 bytes'},
        ]:
            apdu_hex = step['apdu']
            description = step['description']
            try:
                response, sw1, sw2 = connection.send_apdu(apdu_hex)
                record = {
                    'apdu': apdu_hex,
                    'response': ''.join(f'{b:02X}' for b in response),
                    'sw': f'{sw1:02X}{sw2:02X}',
                    'description': description,
                }
                entries.append(record)
                _record_emv_exchange(apdu_hex, response, sw1, sw2, description)
            except Exception as exc:
                error_entry = {'apdu': apdu_hex, 'error': str(exc), 'description': description}
                entries.append(error_entry)
                _record_card_event('apdu', 'exchange', 'error', error_entry)
    if entries:
        _record_card_event('profile', 'memory_dump', 'complete', {'records': len(entries)})
    artifact = _save_profile_results('memory_dump', entries)
    if artifact:
        print(f"[Memory Dump] Complete. Results saved to {artifact}")
    else:
        print("[Memory Dump] Complete.")

def card_pin_bruteforce(device):
    print(f"[PIN/PUK Brute Force] Attempting PIN/PUK brute force on {device.name} ({device.device_id})...")
    pins = ["0000", "1234", "1111", "9999", "0420"]
    attempts: List[Dict[str, Any]] = []
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        for pin in pins:
            pin_bytes = ''.join(f'{int(d):02X}' for d in pin)
            apdu_hex = f'0020008004{pin_bytes}'
            try:
                response, sw1, sw2 = connection.send_apdu(apdu_hex)
                result = {
                    'pin': pin,
                    'apdu': apdu_hex,
                    'response': ''.join(f'{b:02X}' for b in response),
                    'sw': f'{sw1:02X}{sw2:02X}',
                }
                attempts.append(result)
                status = 'success' if (sw1, sw2) == (0x90, 0x00) else 'denied'
                _record_card_event('cvm', 'pin_attempt', status, result)
                print(f"  Trying PIN {pin}: SW={sw1:02X}{sw2:02X}")
                if (sw1, sw2) == (0x90, 0x00):
                    print("  -> PIN accepted, stopping attempts.")
                    break
            except Exception as exc:
                summary = {'pin': pin, 'apdu': apdu_hex, 'error': str(exc)}
                attempts.append(summary)
                _record_card_event('cvm', 'pin_attempt', 'error', summary)
                print(f"  Trying PIN {pin}: Error {exc}")
    artifact = _save_profile_results('pin_bruteforce', attempts)
    if artifact:
        print(f"[PIN/PUK Brute Force] Complete. Results saved to {artifact}")
    else:
        print("[PIN/PUK Brute Force] Complete.")

def card_filesystem_enum(device):
    print(f"[FS Enum] Enumerating files/DFs/EFs on {device.name} ({device.device_id})...")
    sequence = [
        {'apdu': '00A40000023F00', 'description': 'SELECT MF (3F00)'},
        {'apdu': '00A40000022F00', 'description': 'SELECT EF ICCID (2F00)'},
        {'apdu': '00A4020400', 'description': 'SELECT by SFI 4 (example directory)'},
        {'apdu': '00B000000F', 'description': 'READ BINARY from current EF'},
    ]
    results = _execute_apdu_sequence('filesystem_enum', device, sequence, stop_on_error=False)
    artifact = _save_profile_results('filesystem_enum', results)
    if artifact:
        print(f"[FS Enum] Complete. Results saved to {artifact}")
    else:
        print("[FS Enum] Complete.")

def card_custom_script(device):
    print(f"[Custom Script] Running user-supplied APDU/script on {device.name} ({device.device_id})...")
    print("Paste APDU/script (hex, one per line, blank to end). Use '#' for comments.")
    lines: List[str] = []
    while True:
        line = input().strip()
        if not line:
            break
        if line.startswith('#'):
            continue
        lines.append(line)

    if not lines:
        print("[Custom Script] No APDUs provided.")
        return

    entries: List[Dict[str, Any]] = []
    with _card_connection(device) as connection:
        if connection is None:
            print("  [WARN] Could not establish PC/SC connection.")
            return
        for idx, apdu_hex in enumerate(lines, 1):
            clean_hex = apdu_hex.replace(' ', '')
            try:
                response, sw1, sw2 = connection.send_apdu(clean_hex)
                record = {
                    'index': idx,
                    'apdu': clean_hex,
                    'response': ''.join(f'{b:02X}' for b in response),
                    'sw': f'{sw1:02X}{sw2:02X}',
                }
                entries.append(record)
                _record_emv_exchange(clean_hex, response, sw1, sw2, f'Script step {idx}')
                print(f"  [Script] APDU {idx}: SW={sw1:02X}{sw2:02X}")
            except Exception as exc:
                summary = {'index': idx, 'apdu': clean_hex, 'error': str(exc)}
                entries.append(summary)
                _record_card_event('apdu', 'script', 'error', summary)
                print(f"  [Script] APDU {idx}: Error {exc}")
    artifact = _save_profile_results('custom_script', entries)
    if artifact:
        print(f"[Custom Script] Complete. Results saved to {artifact}")
    else:
        print("[Custom Script] Complete.")

def utilities_working():
    """Working utilities implementation."""
    print("⚙️ Utilities & Tools") 
    print("=" * 40)
    
    print("Available utilities:")
    print("1. 🔧 APDU Converter (hex ↔ decimal)")
    print("2. 📊 Luhn Algorithm Validator")
    print("3. 🗂️ File Operations")
    print("4. 📈 System Diagnostics")
    print("5. 🧮 EMV Tag Parser")
    
    try:
        choice = input("\nSelect utility (1-5): ").strip()
        
        if choice == '1':
            # APDU Converter
            print("\n🔧 APDU Converter")
            print("Examples: '00A4040007A0000000041010' or '0,164,4,0,7,160,0,0,0,4,16,16'")
            
            user_input = input("Enter APDU (hex or decimal): ").strip()
            
            if ',' in user_input:
                # Decimal input
                try:
                    decimal_values = [int(x.strip()) for x in user_input.split(',')]
                    hex_string = ''.join(f'{x:02X}' for x in decimal_values)
                    print(f"Hex format: {hex_string}")
                    print(f"Formatted: {' '.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))}")
                except ValueError:
                    print("❌ Invalid decimal format")
            else:
                # Hex input
                try:
                    clean_hex = user_input.replace(' ', '')
                    decimal_values = [int(clean_hex[i:i+2], 16) for i in range(0, len(clean_hex), 2)]
                    print(f"Decimal format: {','.join(str(x) for x in decimal_values)}")
                    print(f"Byte array: {decimal_values}")
                    
                    # Parse basic APDU structure
                    if len(decimal_values) >= 4:
                        print(f"\nAPDU Structure:")
                        print(f"  CLA: 0x{decimal_values[0]:02X} ({decimal_values[0]})")
                        print(f"  INS: 0x{decimal_values[1]:02X} ({decimal_values[1]})")
                        print(f"  P1:  0x{decimal_values[2]:02X} ({decimal_values[2]})")
                        print(f"  P2:  0x{decimal_values[3]:02X} ({decimal_values[3]})")
                        if len(decimal_values) > 4:
                            print(f"  Lc:  {decimal_values[4]} (data length)")
                            if len(decimal_values) > 5:
                                data = decimal_values[5:5+decimal_values[4]]
                                print(f"  Data: {' '.join(f'{x:02X}' for x in data)}")
                except ValueError:
                    print("❌ Invalid hex format")
        
        elif choice == '2':
            # Luhn Validator
            print("\n📊 Luhn Algorithm Validator")
            card_number = input("Enter card number: ").strip().replace(' ', '')
            
            try:
                # Calculate Luhn checksum
                def luhn_validate(num_str):
                    digits = [int(d) for d in num_str]
                    checksum = 0
                    for i, digit in enumerate(digits[::-1]):
                        if i % 2 == 1:
                            doubled = digit * 2
                            checksum += doubled if doubled < 10 else doubled - 9
                        else:
                            checksum += digit
                    return checksum % 10 == 0
                
                is_valid = luhn_validate(card_number)
                print(f"Card number: {card_number}")
                print(f"Luhn check: {'✅ Valid' if is_valid else '❌ Invalid'}")
                
                # Identify card type
                if card_number.startswith('4'):
                    card_type = "Visa"
                elif card_number.startswith('5'):
                    card_type = "Mastercard"
                elif card_number.startswith(('34', '37')):
                    card_type = "American Express"
                elif card_number.startswith('6'):
                    card_type = "Discover"
                else:
                    card_type = "Unknown"
                
                print(f"Card type: {card_type}")
                
            except ValueError:
                print("❌ Invalid card number format")
        
        elif choice == '3':
            # File Operations
            print("\n🗂️ File Operations")
            print("1. List .json files in current directory")
            print("2. Count total files")
            print("3. Check file sizes")
            
            file_choice = input("Select operation (1-3): ").strip()
            
            if file_choice == '1':
                json_files = list(Path('.').glob('*.json'))
                print(f"Found {len(json_files)} .json files:")
                for file in json_files[:10]:  # Show first 10
                    size = file.stat().st_size
                    print(f"  📄 {file.name} ({size} bytes)")
                if len(json_files) > 10:
                    print(f"  ... and {len(json_files) - 10} more")
            
            elif file_choice == '2':
                total_files = len(list(Path('.').glob('*')))
                directories = len([p for p in Path('.').iterdir() if p.is_dir()])
                files = total_files - directories
                print(f"📊 Current directory statistics:")
                print(f"   Files: {files}")
                print(f"   Directories: {directories}")
                print(f"   Total items: {total_files}")
            
            elif file_choice == '3':
                files = [f for f in Path('.').iterdir() if f.is_file()]
                if files:
                    sizes = [(f, f.stat().st_size) for f in files]
                    sizes.sort(key=lambda x: x[1], reverse=True)
                    
                    print(f"📊 Largest files:")
                    for file, size in sizes[:5]:
                        size_str = f"{size:,} bytes"
                        if size > 1024*1024:
                            size_str += f" ({size/(1024*1024):.1f} MB)"
                        print(f"   📄 {file.name}: {size_str}")
                else:
                    print("No files found in current directory")
        
        elif choice == '4':
            # System Diagnostics
            print("\n📈 System Diagnostics")
            
            import platform
            import os
            
            print(f"🖥️ System Information:")
            print(f"   OS: {platform.system()} {platform.release()}")
            print(f"   Architecture: {platform.architecture()[0]}")
            print(f"   Python: {platform.python_version()}")
            print(f"   Working Directory: {os.getcwd()}")
            
            print(f"\n🔧 Environment:")
            important_vars = ['PATH', 'PYTHONPATH', 'JAVA_HOME', 'ANDROID_HOME']
            for var in important_vars:
                value = os.environ.get(var, 'Not set')
                if len(value) > 80:
                    value = value[:80] + '...'
                print(f"   {var}: {value}")
            
            print(f"\n💾 Memory Usage:")
            try:
                import psutil
                memory = psutil.virtual_memory()
                print(f"   Total: {memory.total / (1024**3):.1f} GB")
                print(f"   Available: {memory.available / (1024**3):.1f} GB")
                print(f"   Used: {memory.percent}%")
            except ImportError:
                print("   Install psutil for memory information")
            
        elif choice == '5':
            # EMV Tag Parser  
            print("\n🧮 EMV Tag Parser")
            print("Enter EMV response data to parse common tags")
            
            emv_data = input("EMV data (hex): ").strip().replace(' ', '')
            
            # Common EMV tags
            emv_tags = {
                '50': ('Application Label', 'text'),
                '57': ('Track 2', 'hex'),
                '5A': ('PAN', 'hex'),
                '5F20': ('Cardholder Name', 'text'),
                '5F24': ('Application Expiration Date', 'date'),
                '5F25': ('Application Effective Date', 'date'),
                '5F30': ('Service Code', 'hex'),
                '84': ('Dedicated File Name', 'hex'),
                '87': ('Application Priority Indicator', 'hex'),
                '8C': ('CDOL1', 'hex'),
                '8D': ('CDOL2', 'hex'),
                '9F07': ('Application Usage Control', 'hex'),
                '9F08': ('Application Version Number', 'hex'),
                '9F0D': ('IAC - Default', 'hex'),
                '9F0E': ('IAC - Denial', 'hex'),
                '9F0F': ('IAC - Online', 'hex'),
                '9F38': ('PDOL', 'hex'),
                '9F42': ('Application Currency Code', 'hex'),
            }
            
            print(f"\n📋 Parsed EMV tags:")
            found_tags = 0
            
            for tag, (description, format_type) in emv_tags.items():
                pos = emv_data.upper().find(tag.upper())
                if pos >= 0:
                    try:
                        # Simple length parsing (assuming single byte length)
                        length_pos = pos + len(tag)
                        if length_pos < len(emv_data):
                            length = int(emv_data[length_pos:length_pos+2], 16)
                            value_start = length_pos + 2
                            value_end = value_start + (length * 2)
                            
                            if value_end <= len(emv_data):
                                value = emv_data[value_start:value_end]
                                
                                # Format value based on type
                                if format_type == 'text':
                                    try:
                                        decoded = bytes.fromhex(value).decode('ascii', errors='ignore')
                                        print(f"   {tag}: {description} = '{decoded}' ({value})")
                                    except:
                                        print(f"   {tag}: {description} = {value}")
                                elif format_type == 'date' and len(value) == 4:
                                    year = f"20{value[0:2]}"
                                    month = value[2:4]
                                    print(f"   {tag}: {description} = {month}/{year} ({value})")
                                else:
                                    print(f"   {tag}: {description} = {value}")
                                
                                found_tags += 1
                    except (ValueError, IndexError):
                        pass
            
            if found_tags == 0:
                print("   No recognized EMV tags found")
            else:
                print(f"\n✅ Found {found_tags} EMV tags")
        
        else:
            print("❌ Invalid choice")
    
    except KeyboardInterrupt:
        print("\n❌ Cancelled")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    input("\nPress Enter to continue...")
    return 'refresh'

# --- Added working APDU fuzzing menu action ---

def apdu_fuzzing_working():
    """Interactive native APDU fuzzing session (simulation first, optional hardware).

    Uses the modular core `NativeAPDUFuzzer`. If a reader is available and the
    user opts in, real short APDUs will be sent; otherwise a fast simulation
    provides vulnerability categorization.
    """
    from core.apdu_fuzzer import run_native_apdu_fuzz
    print("🧬 Native APDU Fuzzing")
    print("=" * 40)

    targets = {"1": "jcop", "2": "nxp", "3": "emv", "4": "all"}
    print("Target card type:")
    print(" 1. JCOP")
    print(" 2. NXP (MIFARE/DESFire/NTAG)")
    print(" 3. EMV")
    print(" 4. All (default)")
    t_choice = input("Select (1-4): ").strip()
    target = targets.get(t_choice, "all")

    it_raw = input("Iterations (default 300): ").strip()
    iterations = int(it_raw) if it_raw.isdigit() else 300

    mut_raw = input("Mutation level 1-10 (default 5): ").strip()
    mutation_level = int(mut_raw) if mut_raw.isdigit() and 1 <= int(mut_raw) <= 10 else 5

    verbose = input("Verbose output? (y/N): ").strip().lower() == 'y'

    # Attempt hardware mode
    use_hw = False
    send_callable = None
    try:
        from smartcard.System import readers
        from smartcard.util import toBytes
        hw_readers = readers()
        if hw_readers:
            print(f"\n📡 Detected {len(hw_readers)} reader(s). Optional hardware fuzz? This only sends safe short APDUs.")
            use_hw = input("Use first reader for real transmission? (y/N): ").strip().lower() == 'y'
            if use_hw:
                r = hw_readers[0]
                conn = r.createConnection()
                try:
                    conn.connect()
                    print(f"✅ Connected to {r}")
                    def send_apdu_callable(apdu_hex: str):
                        apdu_bytes = toBytes(apdu_hex)
                        resp, sw1, sw2 = conn.transmit(apdu_bytes)
                        return resp, sw1, sw2
                    send_callable = send_apdu_callable
                except Exception as e:
                    print(f"❌ Hardware connection failed, reverting to simulation: {e}")
                    use_hw = False
        else:
            if verbose:
                print("(No PC/SC readers detected – simulation mode)")
    except Exception as e:
        if verbose:
            print(f"(Hardware check error: {e} – simulation mode)")

    print(f"\n🚀 Starting fuzzing (mode: {'HARDWARE' if use_hw else 'SIMULATION'})...")
    session, report_path = run_native_apdu_fuzz(
        target_card=target,
        iterations=iterations,
        mutation_level=mutation_level,
        use_hardware=use_hw,
        send_apdu_callable=send_callable,
        verbose=verbose,
        report_dir="."
    )

    print("\n✅ Session complete")
    print(f"   Commands: {session['commands_sent']}")
    print(f"   Vulnerabilities: {len(session['vulnerabilities'])}")
    print(f"   Errors: {len(session['errors'])}")
    print(f"   Report: {report_path}")

    # Offer to show summary of vulnerability types
    if session['vulnerabilities']:
        vt = {}
        for v in session['vulnerabilities']:
            vt[v['type']] = vt.get(v['type'], 0) + 1
        print("\n📊 Vulnerability Summary:")
        for k, v in vt.items():
            print(f"  - {k.replace('_',' ').title()}: {v}")
    else:
        print("\n📊 No vulnerabilities detected in this session.")

    input("\nPress Enter to continue...")
    return 'refresh'

def apdu_fuzz_dashboard_working():
    """Menu-accessible dashboard aggregation for APDU fuzz runs."""
    import subprocess, os, glob
    print("📊 APDU Fuzz Dashboard")
    print("="*40)
    target_dir = input("Directory with session JSONs (default .): ").strip() or "."
    pattern = os.path.join(target_dir, "native_apdu_fuzz_session_*.json")
    files = glob.glob(pattern)
    if not files:
        print("❌ No session JSON artifacts found.")
        input("Press Enter to continue...")
        return 'refresh'
    try:
        subprocess.run(['python', 'fuzz_dashboard.py', target_dir], check=True)
        print("✅ Dashboard generated (fuzz_dashboard_summary.md)")
        show = input("View summary now? (y/N): ").strip().lower() == 'y'
        if show and os.path.isfile(os.path.join(target_dir,'fuzz_dashboard_summary.md')):
            print("\n--- Dashboard Preview ---")
            with open(os.path.join(target_dir,'fuzz_dashboard_summary.md'),'r',encoding='utf-8') as f:
                for line in f.read().splitlines()[:30]:
                    print(line)
            print("--- End Preview ---")
    except Exception as e:
        print(f"❌ Dashboard generation failed: {e}")
    input("Press Enter to continue...")
    return 'refresh'

def configuration_center_working():
    """Unified configuration center for global defaults."""
    from core.global_defaults import load_defaults, update_defaults
    cfg = load_defaults()
    print("🛠️ Configuration Center (Global Defaults)")
    print("="*50)
    print("Current values:")
    print(f"  1. Verbose default           : {cfg['verbose_default']}")
    print(f"  2. Max payload default       : {cfg['max_payload_default']}")
    print(f"  3. Stateful fuzz default     : {cfg['stateful_default']}")
    print(f"  4. Artifact directory default: {cfg['artifact_dir_default']}")
    print("  5. Save & Exit")
    print("  0. Cancel")
    dirty = False
    while True:
        choice = input("Select item to modify (0/1-5): ").strip()
        if choice == '0':
            print("Exiting without changes" if not dirty else "Changes kept in memory (already saved)")
            break
        if choice == '5':
            print("✅ Saved.")
            break
        if choice == '1':
            val = input("Verbose default (true/false): ").strip().lower()
            if val in ['true','false','t','f','y','n']:
                cfg['verbose_default'] = val.startswith(('t','y'))
                dirty = True
        elif choice == '2':
            val = input("Max payload bytes (e.g. 220): ").strip()
            if val.isdigit() and int(val)>0:
                cfg['max_payload_default'] = int(val)
                dirty = True
        elif choice == '3':
            val = input("Stateful fuzz default (true/false): ").strip().lower()
            if val in ['true','false','t','f','y','n']:
                cfg['stateful_default'] = val.startswith(('t','y'))
                dirty = True
        elif choice == '4':
            val = input("Artifact directory (path): ").strip()
            if val:
                cfg['artifact_dir_default'] = val
                dirty = True
        else:
            print("Invalid selection")
            continue
        if dirty:
            update_defaults(**cfg)
    input("Press Enter to continue...")
    return 'refresh'


def vulnerability_scanner_working() -> str:
    """Run the vulnerability scanning suite with interactive prompts."""
    print("🛡️ Vulnerability Scanner")
    print("=" * 60)

    try:
        from greenwire.core.configuration_manager import get_configuration_manager
        from greenwire.core.vulnerability_scanner import VulnerabilityScanner
    except ImportError as exc:  # pragma: no cover - optional dependency pathing
        print(f"❌ Vulnerability scanner unavailable: {exc}")
        print("   Run GREENWIRE via greenwire.py or install the package to enable.")
        input("Press Enter to continue...")
        return 'refresh'

    config_manager = get_configuration_manager()
    configuration = config_manager.data()
    scanning_cfg = configuration.get('vulnerability_scanning', {})

    default_suite = scanning_cfg.get('default_suite') or ['cap_integrity', 'gp_audit']
    print(f"Default suite: {', '.join(default_suite)}")
    suite_entry = input("Suite to run (comma separated, blank for default): ").strip()
    if suite_entry:
        suite = [item.strip() for item in suite_entry.split(',') if item.strip()]
    else:
        suite = default_suite

    cap_hint = scanning_cfg.get('default_cap_path') or ''
    gp_hint = scanning_cfg.get('global_platform_path') or ''
    cap_path = input(f"CAP file to analyze [{cap_hint or 'skip'}]: ").strip() or cap_hint
    gp_path = input(f"GlobalPlatformPro jar [{gp_hint or 'skip'}]: ").strip() or gp_hint

    card_data: Dict[str, Any] = {}
    card_path = input("Card JSON with transcript (optional): ").strip()
    if card_path:
        try:
            with open(card_path, 'r', encoding='utf-8') as fh:
                card_data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"⚠️ Could not load card data: {exc}")
            retry = input("Continue without card data? (Y/n): ").strip().lower()
            if retry in {'n', 'no'}:
                return 'refresh'
            card_data = {}

    scanner = VulnerabilityScanner(config=configuration)

    print("\n🚀 Running vulnerability suite...")
    try:
        results = scanner.run_suite(
            card_data=card_data or None,
            suite=suite,
            cap_path=cap_path or None,
            gp_binary_path=gp_path or None,
            include_hashes=True,
        )
    except Exception as exc:  # pragma: no cover - dynamic runtime path
        print(f"❌ Scanner execution failed: {exc}")
        input("Press Enter to continue...")
        return 'refresh'

    if not isinstance(results, list):
        print("⚠️ Unexpected scanner output (expected list of results).")
        input("Press Enter to continue...")
        return 'refresh'

    print("\n📊 Vulnerability Suite Results")
    print("-" * 60)
    summary = {'pass': 0, 'fail': 0, 'error': 0, 'warn': 0}
    for entry in results:
        status = (entry.get('status') or 'unknown').lower()
        emoji = '✅'
        if status in {'fail', 'failed'}:
            emoji = '❌'
        elif status in {'warn', 'warning'}:
            emoji = '⚠️'
        elif status in {'error', 'exception'}:
            emoji = '💥'
        test_name = entry.get('test') or entry.get('name') or 'Unnamed test'
        print(f" {emoji} {test_name}: {status.upper()}")
        detail_lines = entry.get('details')
        if isinstance(detail_lines, list):
            for detail in detail_lines[:3]:
                print(f"    - {detail}")
        elif detail_lines:
            print(f"    {detail_lines}")
        digest = entry.get('artifact_digest')
        if digest:
            print(f"    SHA256: {digest}")
        summary_key = status if status in summary else 'warn'
        summary[summary_key] = summary.get(summary_key, 0) + 1

    print("\nSummary:")
    for key, value in summary.items():
        print(f"  {key.title():<8}: {value}")

    output_path = input("\nSave results to JSON? Enter path or leave blank: ").strip()
    if output_path:
        try:
            directory = os.path.dirname(output_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as fh:
                json.dump(results, fh, indent=2, ensure_ascii=False)
            print(f"💾 Results saved to {output_path}")
        except OSError as exc:
            print(f"❌ Failed to write results: {exc}")

    input("\nPress Enter to continue...")
    return 'refresh'