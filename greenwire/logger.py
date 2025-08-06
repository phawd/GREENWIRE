"""
Logger and log utilities for .cap file APDU/command exchanges.

This logger is used to track all APDU (command) exchanges with smart cards,
especially for .cap file operations. It provides replay, suspicious activity
detection, and log sealing for audit and debugging.

Layman summary:
- Every command sent to the card and its response is logged.
- Suspicious or fingerprinting commands are detected and flagged.
- You can replay sessions, randomize responses, and seal logs for security.
- All logs are saved as JSON files next to your .cap file.
"""

import os
import json
import time
import hashlib


class CapFileLogger:
    """Logger for .cap file APDU/command exchanges."""

    # APDU command prefixes that are often used for fingerprinting or probing
    # the card
    FINGERPRINTING_APDUS = [
        '80CA',  # GET DATA
        '80CB',  # GET DATA (proprietary)
        '80E2',  # Some proprietary commands
        # Add more as needed
    ]
    # Known AIDs for ghost (test/dummy) applets
    GHOST_APPLET_AIDS = [
        'A00000006203010C99',
        'A00000006203010C98',
        # Add more as needed
    ]

    def __init__(self, cap_file):
        """
        Create a logger for a given .cap file.
        Loads previous logs if they exist.
        """
        self.cap_file = cap_file
        self.log_file = f"{cap_file}.log.json"
        self.entries = []
        self.positive_mode = False
        if os.path.exists(self.log_file):
            with open(self.log_file, "r", encoding="utf-8") as f:
                try:
                    self.entries = json.load(f)
                except Exception:
                    self.entries = []

    def log(self, direction, apdu, response):
        """
        Log a command (APDU) and its response.
        If the command is a fingerprinting APDU, mask the response as a generic success.
        """
        if self.is_fingerprinting_apdu(apdu):
            self.log_suspicious(
                apdu, "Fingerprinting APDU detected, masking response"
            )
            response = '9000'  # Always positive, generic
        self.entries.append({
            "direction": direction,  # 'sent' or 'received'
            "apdu": apdu,
            "response": response,
            "timestamp": time.time()
        })
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, indent=2)
        self.persist_logs_in_cap()

    def persist_logs_in_cap(self):
        """
        Store logs inside the .cap file (if supported by your workflow).
        """
        from greenwire.utils import store_logs_in_cap
        store_logs_in_cap(self.cap_file, self.entries)

    def dump(self):
        """
        Return all log entries as a list.
        """
        return self.entries

    def set_positive_mode(self, enable=True):
        """
        Enable 'positive mode' (all responses are positive for testing).
        """
        self.positive_mode = enable
        # Optionally persist this flag in the log file
        if self.entries and isinstance(self.entries, list):
            self.entries.append({
                "positive_mode": enable,
                "timestamp": time.time()
            })
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(self.entries, f, indent=2)

    def record_apdu_pair(self, apdu, response):
        """
        Record a command/response pair for replay.
        """
        if not hasattr(self, 'replay_pairs'):
            self.replay_pairs = {}
        self.replay_pairs[apdu] = response
        # Optionally persist replay pairs
        with open(f"{self.cap_file}.replay.json", "w", encoding="utf-8") as f:
            json.dump(self.replay_pairs, f, indent=2)

    def get_replay_response(self, apdu):
        """
        Get a replayed response for a given APDU, if available.
        """
        if hasattr(self, 'replay_pairs') and apdu in self.replay_pairs:
            return self.replay_pairs[apdu]
        return None

    def import_replay_log(self, path):
        """
        Load a replay log from a file.
        """
        with open(path, "r", encoding="utf-8") as f:
            self.replay_pairs = json.load(f)

    def export_replay_log(self, path):
        """
        Save the current replay log to a file.
        """
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.replay_pairs, f, indent=2)

    def log_suspicious(self, apdu, reason):
        """
        Log a suspicious APDU event (for audit and debugging).
        """
        if not hasattr(self, 'suspicious_events'):
            self.suspicious_events = []
        self.suspicious_events.append({
            "apdu": apdu,
            "reason": reason,
            "timestamp": time.time()
        })
        with open(f"{self.cap_file}.suspicious.json", "w", encoding="utf-8") as f:
            json.dump(self.suspicious_events, f, indent=2)

    def dump_suspicious(self):
        """
        Return all suspicious events.
        """
        if hasattr(self, 'suspicious_events'):
            return self.suspicious_events
        return []

    def learn_from_session(self):
        """
        After a positive session, update replay and suspicious logs.
        """
        if hasattr(self, 'entries'):
            for entry in self.entries:
                if entry.get('response') == '9000':
                    self.record_apdu_pair(entry['apdu'], entry['response'])
        # Optionally, clear suspicious events if session was positive
        if hasattr(self, 'suspicious_events'):
            self.suspicious_events = [
                e for e in self.suspicious_events if e.get('response') != '9000']
            with open(f"{self.cap_file}.suspicious.json", "w", encoding="utf-8") as f:
                json.dump(self.suspicious_events, f, indent=2)

    def is_fingerprinting_apdu(self, apdu):
        """
        Check if an APDU is a known fingerprinting command.
        """
        return any(apdu.startswith(prefix) for prefix in self.FINGERPRINTING_APDUS)

    def randomize_response_fields(self, apdu):
        """
        For certain APDUs, return a random response (e.g., GET CHALLENGE).
        """
        import secrets
        if apdu.startswith('00840000'):  # GET CHALLENGE
            rand_bytes = secrets.token_hex(4)
            self.log('randomized', apdu, rand_bytes)
            return rand_bytes + '9000'
        # Add more randomization logic as needed
        return None

    def log_timing(self, apdu, last_time):
        """
        Log timing between APDUs to detect anomalies (e.g., automation or attacks).
        """
        now = time.time()
        delta = now - last_time if last_time else None
        if delta is not None and (delta < 0.05 or delta > 2.0):
            self.log_suspicious(
                apdu, f"Timing anomaly: {delta:.3f}s since last APDU"
            )
        return now

    def is_ghost_applet(self, aid):
        """
        Check if an AID is a known ghost (test) applet.
        """
        return aid in self.GHOST_APPLET_AIDS

    def log_ghost_applet(self, aid, apdu):
        """
        Log an interaction with a ghost applet.
        """
        self.log('ghost_applet', apdu, f"Ghost applet {aid} interaction")

    def seal_logs(self):
        """
        Seal the logs by writing a hash of the log area for audit.
        """
        marker = "#LOGS_START\n"
        with open(self.cap_file, "r", encoding="utf-8") as f:
            content = f.read()
        if marker in content:
            logs = content.split(marker)[1]
            log_hash = hashlib.sha256(logs.encode("utf-8")).hexdigest()
            with open(f"{self.cap_file}.loghash.txt", "w", encoding="utf-8") as f:
                f.write(log_hash)
            self.log('seal', 'LOGS', f"Log area sealed with hash {log_hash}")
            self.log('seal', 'LOGS', f"Log area sealed with hash {log_hash}")
            with open(self.log_file, "r", encoding="utf-8") as f:
                try:
                    self.entries = json.load(f)
                except Exception:
                    self.entries = []
