#!/usr/bin/env python3
"""
GREENWIRE Protocol Logger - Comprehensive logging for NFC and ATR operations
Provides operator-readable verbose logging with protocol-level details
"""

import datetime, json, logging, os, time  # noqa: F401
from typing import Any, Dict, List, Optional, Union  # noqa: F401
from pathlib import Path

class ProtocolLogger:
    """Comprehensive protocol logger for NFC and card operations."""
    
    def __init__(self, log_dir: str = None, enable_console: bool = True):
        """Initialize protocol logger.
        
        Args:
            log_dir: Directory for log files (default: ./logs)
            enable_console: Enable console output
        """
        self.log_dir = Path(log_dir or "logs")
        self.log_dir.mkdir(exist_ok=True)
        self.enable_console = enable_console
        
        # Create structured log files
        self.session_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.setup_loggers()
        
    def setup_loggers(self):
        """Setup specialized loggers for different protocol types."""
        # Main protocol logger
        self.protocol_logger = logging.getLogger(f"greenwire_protocol_{self.session_id}")
        self.protocol_logger.setLevel(logging.DEBUG)
        
        # File handlers
        protocol_file = self.log_dir / f"protocol_{self.session_id}.log"
        nfc_file = self.log_dir / f"nfc_{self.session_id}.log"
        atr_file = self.log_dir / f"atr_{self.session_id}.log"
        apdu_file = self.log_dir / f"apdu_{self.session_id}.log"
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Protocol file handler
        protocol_handler = logging.FileHandler(protocol_file)
        protocol_handler.setFormatter(detailed_formatter)
        self.protocol_logger.addHandler(protocol_handler)
        
        # Specialized loggers
        self.nfc_logger = self._create_specialized_logger("nfc", nfc_file, detailed_formatter)
        self.atr_logger = self._create_specialized_logger("atr", atr_file, detailed_formatter)
        self.apdu_logger = self._create_specialized_logger("apdu", apdu_file, detailed_formatter)
        
        # Console handler if enabled
        if self.enable_console:
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter('%(levelname)s: %(message)s')
            console_handler.setFormatter(console_formatter)
            self.protocol_logger.addHandler(console_handler)
            
    def _create_specialized_logger(self, name: str, file_path: Path, formatter) -> logging.Logger:
        """Create a specialized logger for specific protocol types."""
        logger = logging.getLogger(f"greenwire_{name}_{self.session_id}")
        logger.setLevel(logging.DEBUG)
        
        handler = logging.FileHandler(file_path)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
        
    def log_atr_analysis(self, atr_bytes: bytes, device_info: Dict = None):
        """Log detailed ATR analysis with operator-readable output."""
        timestamp = datetime.datetime.now().isoformat()
        
        # Basic ATR information
        atr_hex = atr_bytes.hex().upper()
        atr_length = len(atr_bytes)
        
        analysis = {
            'timestamp': timestamp,
            'atr_hex': atr_hex,
            'atr_length': atr_length,
            'device_info': device_info or {},
            'analysis': {}
        }
        
        # Parse ATR structure
        if atr_length > 0:
            ts = atr_bytes[0]  # Initial character
            analysis['analysis']['ts'] = {
                'value': f'0x{ts:02X}',
                'meaning': self._decode_ts(ts)
            }
            
        if atr_length > 1:
            t0 = atr_bytes[1]  # Format character
            analysis['analysis']['t0'] = {
                'value': f'0x{t0:02X}',
                'historical_length': t0 & 0x0F,
                'ta1_present': bool(t0 & 0x10),
                'tb1_present': bool(t0 & 0x20),
                'tc1_present': bool(t0 & 0x40),
                'td1_present': bool(t0 & 0x80)
            }
            
        # Parse interface characters
        pos = 2
        ta_tb_tc_td = []
        
        for i in range(1, 5):  # Support up to TD4
            if pos >= atr_length:
                break
                
            td_prev = atr_bytes[pos - 1] if pos > 1 else t0
            
            if td_prev & (0x10 << (i-1)):  # TA present
                if pos < atr_length:
                    ta_tb_tc_td.append(('TA', i, atr_bytes[pos]))
                    pos += 1
                    
            if td_prev & (0x20 << (i-1)):  # TB present
                if pos < atr_length:
                    ta_tb_tc_td.append(('TB', i, atr_bytes[pos]))
                    pos += 1
                    
            if td_prev & (0x40 << (i-1)):  # TC present
                if pos < atr_length:
                    ta_tb_tc_td.append(('TC', i, atr_bytes[pos]))
                    pos += 1
                    
            if td_prev & (0x80 << (i-1)):  # TD present
                if pos < atr_length:
                    ta_tb_tc_td.append(('TD', i, atr_bytes[pos]))
                    pos += 1
                else:
                    break
            else:
                break
                
        analysis['analysis']['interface_chars'] = [
            {'type': t, 'index': i, 'value': f'0x{v:02X}', 'decoded': self._decode_interface_char(t, i, v)}
            for t, i, v in ta_tb_tc_td
        ]
        
        # Historical bytes
        hist_length = t0 & 0x0F if atr_length > 1 else 0
        if hist_length > 0 and pos + hist_length <= atr_length:
            hist_bytes = atr_bytes[pos:pos + hist_length]
            analysis['analysis']['historical_bytes'] = {
                'hex': hist_bytes.hex().upper(),
                'length': hist_length,
                'ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in hist_bytes)
            }
            pos += hist_length
            
        # Check character (TCK)
        if pos < atr_length:
            tck = atr_bytes[pos]
            analysis['analysis']['tck'] = {
                'value': f'0x{tck:02X}',
                'present': True
            }
            
        # Log to files and console
        self.atr_logger.info(f"ATR Analysis: {json.dumps(analysis, indent=2)}")
        
        if self.enable_console:
            self._display_atr_analysis(analysis)
            
        return analysis
        
    def _decode_ts(self, ts: int) -> str:
        """Decode TS (Initial Character)."""
        if ts == 0x3B:
            return "Direct convention"
        elif ts == 0x3F:
            return "Inverse convention"
        else:
            return f"Invalid TS (expected 0x3B or 0x3F)"
            
    def _decode_interface_char(self, char_type: str, index: int, value: int) -> str:
        """Decode interface characters."""
        if char_type == 'TA':
            if index == 1:
                fi = (value >> 4) & 0x0F
                di = value & 0x0F
                return f"FI={fi}, DI={di} (Clock rate conversion factor and baud rate adjustment)"
            elif index == 2:
                return f"Specific mode byte: 0x{value:02X}"
        elif char_type == 'TB':
            if index == 1:
                ii = (value >> 5) & 0x03
                pi1 = value & 0x1F
                return f"II={ii}, PI1={pi1} (Programming current and voltage)"
        elif char_type == 'TC':
            if index == 1:
                return f"Extra guard time: {value} ETU"
        elif char_type == 'TD':
            protocol = value & 0x0F
            return f"Protocol T={protocol}, interface chars follow: {bool(value & 0x80)}"
            
        return f"Value: 0x{value:02X}"
        
    def _display_atr_analysis(self, analysis: Dict):
        """Display human-readable ATR analysis to console."""
        print("\n" + "="*70)
        print("🔍 ATR (Answer To Reset) Analysis")
        print("="*70)
        print(f"⏰ Timestamp: {analysis['timestamp']}")
        print(f"📏 Length: {analysis['atr_length']} bytes")
        print(f"🔢 Raw ATR: {analysis['atr_hex']}")
        print()
        
        if 'ts' in analysis['analysis']:
            ts = analysis['analysis']['ts']
            print(f"📍 TS (Initial Character): {ts['value']} - {ts['meaning']}")
            
        if 't0' in analysis['analysis']:
            t0 = analysis['analysis']['t0']
            print(f"📍 T0 (Format Character): {t0['value']}")
            print(f"   Historical bytes length: {t0['historical_length']}")
            print(f"   Interface characters present: TA1={t0['ta1_present']}, TB1={t0['tb1_present']}, TC1={t0['tc1_present']}, TD1={t0['td1_present']}")
            
        if analysis['analysis'].get('interface_chars'):
            print(f"\n📡 Interface Characters:")
            for char in analysis['analysis']['interface_chars']:
                print(f"   {char['type']}{char['index']}: {char['value']} - {char['decoded']}")
                
        if analysis['analysis'].get('historical_bytes'):
            hist = analysis['analysis']['historical_bytes']
            print(f"\n📚 Historical Bytes ({hist['length']} bytes):")
            print(f"   HEX: {hist['hex']}")
            print(f"   ASCII: '{hist['ascii']}'")
            
        if analysis['analysis'].get('tck'):
            tck = analysis['analysis']['tck']
            print(f"\n✅ TCK (Check Character): {tck['value']}")
            
        print("="*70)
        
    def log_nfc_transaction(self, transaction_type: str, data: Dict):
        """Log NFC transaction with detailed protocol information."""
        timestamp = datetime.datetime.now().isoformat()
        
        log_entry = {
            'timestamp': timestamp,
            'transaction_type': transaction_type,
            'data': data,
            'session_id': self.session_id
        }
        
        self.nfc_logger.info(f"NFC Transaction: {json.dumps(log_entry, indent=2)}")
        
        if self.enable_console:
            print(f"\n📡 NFC {transaction_type.upper()}")
            print(f"⏰ {timestamp}")
            if isinstance(data, dict):
                for key, value in data.items():
                    print(f"   {key}: {value}")
            else:
                print(f"   Data: {data}")
                
    def log_apdu_exchange(self, command: bytes, response: bytes, timing: float = None, description: str = None):
        """Log APDU command/response exchange with detailed analysis."""
        timestamp = datetime.datetime.now().isoformat()
        
        # Analyze command APDU
        cmd_analysis = self._analyze_apdu_command(command)
        
        # Analyze response APDU
        resp_analysis = self._analyze_apdu_response(response)
        
        log_entry = {
            'timestamp': timestamp,
            'command': {
                'hex': command.hex().upper(),
                'length': len(command),
                'analysis': cmd_analysis
            },
            'response': {
                'hex': response.hex().upper(),
                'length': len(response),
                'analysis': resp_analysis
            },
            'timing_ms': timing * 1000 if timing else None,
            'description': description,
            'session_id': self.session_id
        }
        
        self.apdu_logger.info(f"APDU Exchange: {json.dumps(log_entry, indent=2)}")
        
        if self.enable_console:
            self._display_apdu_exchange(log_entry)
            
    def _analyze_apdu_command(self, apdu: bytes) -> Dict:
        """Analyze APDU command structure."""
        if len(apdu) < 4:
            return {'error': 'APDU too short'}
            
        cla, ins, p1, p2 = apdu[0:4]
        
        analysis = {
            'cla': f'0x{cla:02X}',
            'ins': f'0x{ins:02X}',
            'p1': f'0x{p1:02X}',
            'p2': f'0x{p2:02X}',
            'ins_name': self._get_ins_name(ins),
            'cla_analysis': self._analyze_cla(cla)
        }
        
        # Determine case and parse Lc/Le
        if len(apdu) == 4:
            analysis['case'] = 'Case 1 (no data, no response)'
        elif len(apdu) == 5:
            analysis['case'] = 'Case 2s (no data, short response)'
            analysis['le'] = apdu[4]
        elif len(apdu) > 5:
            lc = apdu[4]
            if len(apdu) == 5 + lc:
                analysis['case'] = 'Case 3s (short data, no response)'
                analysis['lc'] = lc
                analysis['data'] = apdu[5:5+lc].hex().upper()
            elif len(apdu) == 5 + lc + 1:
                analysis['case'] = 'Case 4s (short data, short response)'
                analysis['lc'] = lc
                analysis['data'] = apdu[5:5+lc].hex().upper()
                analysis['le'] = apdu[5+lc]
            else:
                analysis['case'] = 'Extended APDU or malformed'
                
        return analysis
        
    def _analyze_apdu_response(self, response: bytes) -> Dict:
        """Analyze APDU response structure."""
        if len(response) < 2:
            return {'error': 'Response too short'}
            
        data = response[:-2] if len(response) > 2 else b''
        sw1, sw2 = response[-2], response[-1]
        
        analysis = {
            'sw1': f'0x{sw1:02X}',
            'sw2': f'0x{sw2:02X}',
            'sw': f'0x{sw1:02X}{sw2:02X}',
            'status': self._get_sw_meaning(sw1, sw2),
            'data_length': len(data)
        }
        
        if data:
            analysis['data'] = data.hex().upper()
            
        return analysis
        
    def _get_ins_name(self, ins: int) -> str:
        """Get instruction name from INS byte."""
        ins_map = {
            0x00: 'NOP',
            0x04: 'DEACTIVATE FILE',
            0x0C: 'ERASE RECORD',
            0x0E: 'ERASE BINARY',
            0x10: 'PERFORM SCQL OPERATION',
            0x12: 'PERFORM TRANSACTION OPERATION',
            0x14: 'PERFORM USER OPERATION',
            0x20: 'VERIFY',
            0x22: 'MANAGE SECURITY ENVIRONMENT',
            0x24: 'CHANGE REFERENCE DATA',
            0x26: 'DISABLE VERIFICATION REQUIREMENT',
            0x28: 'ENABLE VERIFICATION REQUIREMENT',
            0x2A: 'PERFORM SECURITY OPERATION',
            0x2C: 'RESET RETRY COUNTER',
            0x44: 'ACTIVATE FILE',
            0x46: 'GENERATE ASYMMETRIC KEY PAIR',
            0x70: 'MANAGE CHANNEL',
            0x82: 'EXTERNAL AUTHENTICATE',
            0x84: 'GET CHALLENGE',
            0x88: 'INTERNAL AUTHENTICATE',
            0xA4: 'SELECT FILE',
            0xB0: 'READ BINARY',
            0xB2: 'READ RECORD',
            0xC0: 'GET RESPONSE',
            0xC2: 'ENVELOPE',
            0xCA: 'GET DATA',
            0xD0: 'WRITE BINARY',
            0xD2: 'WRITE RECORD',
            0xD6: 'UPDATE BINARY',
            0xDA: 'PUT DATA',
            0xDC: 'UPDATE RECORD',
            0xE0: 'CREATE FILE',
            0xE2: 'APPEND RECORD',
            0xE4: 'DELETE FILE',
            0xE6: 'TERMINATE DF',
            0xE8: 'TERMINATE EF'
        }
        
        return ins_map.get(ins, f'UNKNOWN (0x{ins:02X})')
        
    def _analyze_cla(self, cla: int) -> Dict:
        """Analyze CLA byte structure."""
        return {
            'interindustry': bool(cla & 0x80) == 0,
            'secure_messaging': (cla & 0x0C) >> 2,
            'logical_channel': cla & 0x03,
            'chain': bool(cla & 0x10)
        }
        
    def _get_sw_meaning(self, sw1: int, sw2: int) -> str:
        """Get status word meaning."""
        sw = (sw1 << 8) | sw2
        
        if sw == 0x9000:
            return "SUCCESS - Normal processing"
        elif sw1 == 0x61:
            return f"SUCCESS - {sw2} bytes available with GET RESPONSE"
        elif sw1 == 0x6C:
            return f"WRONG Le - Correct Le is {sw2}"
        elif sw == 0x6300:
            return "WARNING - Authentication failed"
        elif sw == 0x6400:
            return "ERROR - Execution error"
        elif sw == 0x6500:
            return "ERROR - Memory failure"
        elif sw == 0x6700:
            return "ERROR - Wrong length"
        elif sw == 0x6800:
            return "ERROR - Functions in CLA not supported"
        elif sw == 0x6900:
            return "ERROR - Command not allowed"
        elif sw == 0x6A00:
            return "ERROR - Wrong parameters P1-P2"
        elif sw == 0x6B00:
            return "ERROR - Wrong parameters P1-P2"
        elif sw == 0x6D00:
            return "ERROR - Unknown instruction code"
        elif sw == 0x6E00:
            return "ERROR - Wrong instruction class"
        elif sw == 0x6F00:
            return "ERROR - Technical problem, no precise diagnosis"
        else:
            return f"Unknown status (0x{sw:04X})"
            
    def _display_apdu_exchange(self, log_entry: Dict):
        """Display APDU exchange to console."""
        print("\n" + "="*80)
        print("📡 APDU Exchange")
        print("="*80)
        print(f"⏰ {log_entry['timestamp']}")
        
        if log_entry.get('description'):
            print(f"📝 {log_entry['description']}")
            
        # Command
        cmd = log_entry['command']
        print(f"\n📤 COMMAND ({cmd['length']} bytes): {cmd['hex']}")
        if 'analysis' in cmd and 'error' not in cmd['analysis']:
            analysis = cmd['analysis']
            print(f"   CLA: {analysis['cla']} | INS: {analysis['ins']} ({analysis['ins_name']}) | P1: {analysis['p1']} | P2: {analysis['p2']}")
            print(f"   Case: {analysis.get('case', 'Unknown')}")
            if 'data' in analysis:
                print(f"   Data: {analysis['data']}")
                
        # Response
        resp = log_entry['response']
        print(f"\n📥 RESPONSE ({resp['length']} bytes): {resp['hex']}")
        if 'analysis' in resp and 'error' not in resp['analysis']:
            analysis = resp['analysis']
            print(f"   SW: {analysis['sw']} - {analysis['status']}")
            if analysis['data_length'] > 0:
                print(f"   Data: {analysis['data']}")
                
        if log_entry.get('timing_ms'):
            print(f"\n⏱️  Timing: {log_entry['timing_ms']:.2f} ms")
            
        print("="*80)
        
    def create_session_summary(self) -> Dict:
        """Create a summary of the current session."""
        summary = {
            'session_id': self.session_id,
            'start_time': datetime.datetime.now().isoformat(),
            'log_directory': str(self.log_dir),
            'files_created': [
                f"protocol_{self.session_id}.log",
                f"nfc_{self.session_id}.log", 
                f"atr_{self.session_id}.log",
                f"apdu_{self.session_id}.log"
            ]
        }
        
        # Save summary
        summary_file = self.log_dir / f"session_summary_{self.session_id}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
        return summary