#!/usr/bin/env python3
"""
Operation Greenwire — Consolidated CLI for EMV and smartcard security testing

Combines features from greenwire-brute.py, improved variant, and fuzzer.py into
one efficient, Windows-friendly tool.

Usage:
  greenwtest1.py [options] --mode <mode> [--type <type>] [--count N]

Modes:
  standard      Basic EMV protocol testing
  simulate      Transaction simulation with fuzzing
  fuzz          Dedicated fuzzing mode
  readfuzz      Focus on READ RECORD fuzzing
  extractkeys   Extract and analyze keys

Options:
  --mode MODE       Testing mode (required)
  --type TYPE       Card type (visa,mc,amex,etc)
  --count N         Number of iterations
  --auth AUTH       Authentication (pin,signature)
  --fuzz STRAT      Fuzzing strategy (random,param,crypto,entropy)
  --timing          Enable timing analysis
  --power           Enable power analysis
  --glitch          Enable glitch detection
  --combined        Test combined attack vectors
  --advanced        Run predefined attack scenarios
  --verbose         Enable detailed logging
  --silent          Suppress non-error output
  --export FILE     Export results to JSON
  --max-threads N   Maximum threads to use (default:4)
"""
import sys
import os
import json
import time
import argparse
import logging
import sqlite3
import threading
import random
import hashlib
import struct
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from math import log2
from dataclasses import dataclass

# Try imports for real card access; fallback to mocks on Windows
try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    from smartcard.CardConnection import CardConnection
    from greenwire.core.fuzzer import SmartcardFuzzer
except ImportError:
    logging.warning("Smartcard libs not found; entering simulation mode.")
    class CardConnection:
        def __init__(self, reader=None): self.reader = reader
        def transmit(self, apdu): return [], 0x90, 0x00
    class SmartcardFuzzer:
        def analyze_timing_attack(self, cmd, iterations): return {'vulnerabilities': []}
        def test_power_analysis(self, cmd, samples): return {'vulnerabilities': []}
        def detect_clock_glitch(self, cmd, iterations): return {'vulnerabilities': []}

# Version and thresholds
DB_VERSION = 1
ANALYSIS_THRESHOLDS = {
    'MIN_ENTROPY': 3.5,
    'RESPONSE_TIME_THRESHOLD': 1.0,
    'POWER_TRACE_SAMPLES': 1000,
    'GLITCH_WIDTH_MIN': 10,
    'GLITCH_WIDTH_MAX': 100,
    'MIN_KEY_STRENGTH': 112
}

# EMV and card commands (merged, unique)
CARD_OS_COMMANDS = {
    'JAVACARD': {...},  # truncated for brevity, use merged definitions
    'MULTOS':  {...},  
    'EMV':     {...}
}
EMV_COMMANDS = {...}     # merged command lists
EMV_AIDS = {...}         # combined AIDs map
EMV_TAGS = {...}         # combined tag definitions

# Attack scenarios from fuzzer.py
ATTACK_SCENARIOS = {
    'SDA_DOWNGRADE': {...},
    'PIN_BYPASS':     {...},
    'PRE_PLAY':       {...},
    'EXPRESSPAY_REPLAY': {...}
}

@dataclass
class TLVObject:
    tag: bytes
    length: int
    value: bytes
    @property
    def tag_str(self): return self.tag.hex().upper()
    @property
    def name(self): return EMV_TAGS.get(self.tag_str, 'Unknown')
    def __str__(self): return f"{self.tag_str} ({self.name}): {self.value.hex().upper()}"

class TLVParser:
    @staticmethod
    def parse(data: bytes):
        objs, offset = [], 0
        while offset < len(data):
            tag, offset = TLVParser._parse_tag(data, offset)
            if tag is None: break
            length, offset = TLVParser._parse_length(data, offset)
            if length is None: break
            value = data[offset:offset+length]; offset += length
            objs.append(TLVObject(tag, length, value))
        return objs
    @staticmethod
    def _parse_tag(data, offset):
        if offset>=len(data): return None, offset
        start=offset; first=data[offset]; offset+=1
        if first&0x1F==0x1F:
            while offset<len(data) and data[offset]&0x80: offset+=1
            offset+=1
        return data[start:offset], offset
    @staticmethod
    def _parse_length(data, offset):
        if offset>=len(data): return None, offset
        lb=data[offset]; offset+=1
        if lb&0x80:
            num=lb&0x7F; val=0
            for i in range(num): val=(val<<8)|data[offset+i]
            offset+=num; return val, offset
        return lb, offset

class VulnerabilityDetector:
    def __init__(self, db_conn):
        self.db = db_conn
        self.timing_hist = {}
        self.patterns = {}
        self.suspicious_sw = {
            0x6283: "Selected file invalidated",
            0x6700: "Wrong length",
            0x6982: "Security status not satisfied",
        }
    def analyze_command(self, typ, apdu, resp, sw1, sw2, exec_time):
        findings=[]
        # timing
        hist=self.timing_hist.setdefault(typ,[]); hist.append(exec_time)
        if len(hist)>10:
            mean=sum(hist)/len(hist)
            sd=(sum((x-mean)**2 for x in hist)/len(hist))**0.5
            if abs(exec_time-mean)>2*sd:
                findings.append({'type':'TIMING_ANOMALY','description':f"Unusual timing for {typ}"})
        # status words
        sw=(sw1<<8)|sw2
        if sw in self.suspicious_sw:
            findings.append({'type':'SUSPICIOUS_STATUS','description':self.suspicious_sw[sw]})
        # log to DB
        for f in findings:
            self.db.execute(
                "INSERT INTO vulnerabilities(session_id, vulnerability_type, description, apdu, response) VALUES(?,?,?,?,?)",
                (None, f['type'], f['description'], apdu.hex(), resp.hex())
            )
        self.db.commit()
        return findings

def init_database():
    db_path = Path('greenwire.db')
    conn = sqlite3.connect(str(db_path))
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS db_version(version INTEGER PRIMARY KEY, timestamp DATETIME);
        CREATE TABLE IF NOT EXISTS vulnerabilities(
            id INTEGER PRIMARY KEY, session_id INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            vulnerability_type TEXT, description TEXT, apdu TEXT, response TEXT);
    ''')
    conn.execute('INSERT OR REPLACE INTO db_version(version) VALUES(?)', (DB_VERSION,))
    conn.commit()
    return conn

def setup_logging(verbose=False, silent=False):
    fmt='%(asctime)s - %(levelname)s - %(message)s'
    lvl=logging.DEBUG if verbose else logging.INFO
    handlers=[]
    fh=logging.FileHandler('greenwire.log'); fh.setFormatter(logging.Formatter(fmt)); handlers.append(fh)
    if not silent:
        ch=logging.StreamHandler(sys.stdout); ch.setFormatter(logging.Formatter(fmt)); handlers.append(ch)
    logging.basicConfig(level=lvl, handlers=handlers)

def parse_args():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', required=True, choices=['standard','simulate','fuzz','readfuzz','extractkeys'])
    p.add_argument('--type', default='auto')
    p.add_argument('--count', type=int, default=1)
    p.add_argument('--auth', choices=['pin','signature'])
    p.add_argument('--fuzz')
    p.add_argument('--timing', action='store_true')
    p.add_argument('--power', action='store_true')
    p.add_argument('--glitch', action='store_true')
    p.add_argument('--combined', action='store_true')
    p.add_argument('--advanced', action='store_true')
    p.add_argument('--verbose', action='store_true')
    p.add_argument('--silent', action='store_true')
    p.add_argument('--export')
    p.add_argument('--max-threads', type=int, default=4)
    args=p.parse_args()
    if args.silent and args.verbose: p.error("--silent and --verbose are mutually exclusive")
    if args.mode in ['fuzz','simulate'] and not args.fuzz: p.error("--fuzz required for fuzz/simulate")
    if args.mode!='standard' and not args.auth: p.error("--auth required for non-standard modes")
    return args

# Mode implementations (simplified)
def run_standard(conn, args, fuzzer, detector):
    logging.info("Running standard EMV tests...")
    # Example select + read
    readers_list = readers() if 'readers' in globals() else []
    for rdr in readers_list:
        conn_card = CardConnection(rdr)
        apdu = bytes(EMV_COMMANDS['SELECT']) + toBytes('A0000000031010')
        resp,sw1,sw2 = conn_card.transmit(list(apdu))
        detector.analyze_command('SELECT', apdu, bytes(resp), sw1, sw2, 0.0)

def run_simulate(conn, args, fuzzer, detector):
    logging.info("Simulating transaction with fuzzing...")
    # integrate fuzzer and detector here...

def run_fuzz(conn, args, fuzzer, detector):
    """Run generic fuzzing using SmartcardFuzzer."""
    logging.info("Running fuzz mode...")
    result = fuzzer.simulate_attack_scenario("SDA_DOWNGRADE")
    logging.info("Scenario result: %s", result)


def run_readfuzz(conn, args, fuzzer, detector):
    """Fuzz READ RECORD commands via contactless interface."""
    logging.info("Running READ RECORD fuzzing...")
    aids = EMV_AIDS.get(args.type, EMV_AIDS.get('visa', []))
    for res in fuzzer.fuzz_contactless(aids, iterations=args.count):
        detector.analyze_command(
            "READ_RECORD",
            b"",
            res.get("gpo", b""),
            0x90,
            0x00,
            0.0,
        )


def run_extractkeys(conn, args, fuzzer, detector):
    """Extract cryptographic key material using the fuzzer."""
    logging.info("Extracting keys from card...")
    fuzzer.fuzz_key_detection()
    if args.export:
        Path(args.export).write_text(json.dumps(fuzzer.detected_keys, indent=2))


def run_advanced(conn, args, fuzzer, detector):
    logging.info("Running advanced attack scenarios...")
    for name, scenario in ATTACK_SCENARIOS.items():
        logging.info(f"Executing scenario: {name}")
        result = getattr(fuzzer, scenario['method'])(scenario['command'], args.count)
        # process vulnerabilities if present

def main():
    args = parse_args()
    setup_logging(args.verbose, args.silent)
    conn = init_database()
    detector = VulnerabilityDetector(conn)
    fuzzer = SmartcardFuzzer()
    if args.advanced:
        run_advanced(conn, args, fuzzer, detector)
    else:
        if args.mode=='standard':    run_standard(conn, args, fuzzer, detector)
        elif args.mode=='simulate':  run_simulate(conn, args, fuzzer, detector)
        elif args.mode=='fuzz':      run_fuzz(conn, args, fuzzer, detector)
        elif args.mode=='readfuzz':  run_readfuzz(conn, args, fuzzer, detector)
        elif args.mode=='extractkeys': run_extractkeys(conn, args, fuzzer, detector)
    conn.close()

if __name__=='__main__':
    main()
