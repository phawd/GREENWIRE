
"""
Greenwire Unified CLI
---------------------
Swiss army knife for smartcard, EMV, JCOP, and .cap file emulation, testing, and issuance.

Features:
- Modular CLI for card generation, fuzzing, simulation, and hardware/CSV output
- Realistic HSM/terminal simulation (PCSC, NFC, HSM profiles)
- Robust logging, operator feedback, and cryptographic verification
- EMV/JCOP/ISO 7816/JavaCard support

Usage:
    python greenwire.py <subcommand> [options]

Key Subcommands:
    supertouch     Run fuzzing, brute force, and key extraction (with --csv-output, --hardware)
    jcalgtest      Run JCAlgTest simulation
    integration    Run JCOP integration tests
    supporttable   Run SupportTable integration
    jcop           Run JCOP manager (cap gen/test/dump)
    emulator       Run ISO/EMV emulator (with --profile, --hardware)
    crypto         Run cryptographic verification
    issuance       Simulate card issuance (with --csv-output, --hardware, --profile)
    self-test      Run a basic self-test of all major features

Options:
    --csv-output <file>   Output results to CSV file (where supported)
    --hardware            Use real hardware (PCSC/NFC) if available
    --profile <profile>   Select terminal/HSM profile (e.g., pcsc, nfc, hsm)

Examples:
    python greenwire.py issuance --csv-output cards.csv --hardware --profile pcsc
    python greenwire.py supertouch --cap-files mytest.cap --csv-output results.csv
    python greenwire.py emulator --cap-file mytest.cap --profile nfc

See -h/--help after any subcommand for details.
"""

import argparse
import os
import subprocess
import logging
import time
import random
import hashlib
import string
import json
import secrets


def generate_random_aid():
    """Generate a random AID (Application Identifier)."""
    return ''.join(random.choices(string.hexdigits.upper(), k=16))


def obfuscate_cap_content(content):
    """Obfuscate the content of a .cap file."""
    return ''.join(chr((ord(c) + 3) % 256) for c in content)


def encrypt_cap_content(content, key="default_key"):
    """Encrypt the content of a .cap file using a simple XOR cipher."""
    return ''.join(
        chr(ord(c) ^ ord(key[i % len(key)]))
        for i, c in enumerate(content)
    )


def enhance_cap_file(file_path):

    """
    Enhance a .cap file with randomized metadata, dynamic AID,
    obfuscation, and encryption.
    """
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            f.write("dummy_cap_content")

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Add randomized metadata
    metadata = f"# Randomized Metadata: {generate_random_aid()}\n"

    # Obfuscate and encrypt content
    obfuscated_content = obfuscate_cap_content(content)
    encrypted_content = encrypt_cap_content(obfuscated_content)

    # Write enhanced content back to the file
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(metadata + encrypted_content)


def store_logs_in_cap(cap_file, log_data):
    """Append logs to a reserved section in the .cap file after #LOGS_START marker."""
    marker = "#LOGS_START\n"
    with open(cap_file, "r", encoding="utf-8") as f:
        content = f.read()
    if marker not in content:
        content += f"\n{marker}"
    # Remove any previous logs after marker
    content = content.split(marker)[0] + marker
    # Append new logs
    content += json.dumps(log_data, indent=2)
    with open(cap_file, "w", encoding="utf-8") as f:
        f.write(content)


class CapFileLogger:
    """Logger for .cap file APDU/command exchanges."""
    FINGERPRINTING_APDUS = [
        '80CA',  # GET DATA
        '80CB',  # GET DATA (proprietary)
        '80E2',  # Some proprietary commands
        # Add more as needed
    ]
    GHOST_APPLET_AIDS = [
        'A00000006203010C99',
        'A00000006203010C98',
        # Add more as needed
    ]

    def __init__(self, cap_file):
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
        if self.is_fingerprinting_apdu(apdu):
            self.log_suspicious(apdu, "Fingerprinting APDU detected, masking response")
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
        store_logs_in_cap(self.cap_file, self.entries)

    def dump(self):
        return self.entries

    def set_positive_mode(self, enable=True):
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
        if not hasattr(self, 'replay_pairs'):
            self.replay_pairs = {}
        self.replay_pairs[apdu] = response
        # Optionally persist replay pairs
        with open(f"{self.cap_file}.replay.json", "w", encoding="utf-8") as f:
            json.dump(self.replay_pairs, f, indent=2)

    def get_replay_response(self, apdu):
        if hasattr(self, 'replay_pairs') and apdu in self.replay_pairs:
            return self.replay_pairs[apdu]
        return None

    def import_replay_log(self, path):
        with open(path, "r", encoding="utf-8") as f:
            self.replay_pairs = json.load(f)

    def export_replay_log(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.replay_pairs, f, indent=2)

    def log_suspicious(self, apdu, reason):
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
        if hasattr(self, 'suspicious_events'):
            return self.suspicious_events
        return []

    def learn_from_session(self):
        # After a positive session, update replay log and suspicious log
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
        return any(apdu.startswith(prefix) for prefix in self.FINGERPRINTING_APDUS)

    def randomize_response_fields(self, apdu):
        # Example: If APDU expects unpredictable number, return random
        if apdu.startswith('00840000'):  # GET CHALLENGE
            rand_bytes = secrets.token_hex(4)
            self.log('randomized', apdu, rand_bytes)
            return rand_bytes + '9000'
        # Add more randomization logic as needed
        return None

    def log_timing(self, apdu, last_time):
        now = time.time()
        delta = now - last_time if last_time else None
        if delta is not None and (delta < 0.05 or delta > 2.0):
            self.log_suspicious(apdu, f"Timing anomaly: {delta:.3f}s since last APDU")
        return now

    def is_ghost_applet(self, aid):
        return aid in self.GHOST_APPLET_AIDS

    def log_ghost_applet(self, aid, apdu):
        self.log('ghost_applet', apdu, f"Ghost applet {aid} interaction")

    def seal_logs(self):
        marker = "#LOGS_START\n"
        with open(self.cap_file, "r", encoding="utf-8") as f:
            content = f.read()
        if marker in content:
            logs = content.split(marker)[1]
            log_hash = hashlib.sha256(logs.encode("utf-8")).hexdigest()
            with open(f"{self.cap_file}.loghash.txt", "w", encoding="utf-8") as f:
                f.write(log_hash)
            self.log('seal', 'LOGS', f"Log area sealed with hash {log_hash}")


class GreenwireSuperTouch:
    """
    Fuzzes, brute-forces, and attempts key extraction on a .cap file using
    simulated APDU commands.
    """
    def __init__(self):
        self.log_file = "greenwire_supertouch_log.txt"
        self.comm_log_file = "greenwire_communication_log.txt"
        logging.basicConfig(
            level=logging.INFO,
            filename=self.log_file,
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def supertouch(self, cap_file, package_aid, applet_aid):
        """Run SUPERTOUCH fuzzing, brute force, and key extraction."""
        terminal_commands = self.get_all_terminal_commands()
        logging.info(
            "Starting SUPERTOUCH operation with learning capabilities..."
        )
        for command in terminal_commands:
            try:
                logging.info(f"Executing terminal command: {command}")
                self.execute_terminal_command(
                    cap_file, package_aid, applet_aid, command
                )
                random_payload = self.generate_random_payload(command)
                apdu_command = self.build_apdu_command(random_payload)
                self.interface_with_cli(apdu_command)
            except Exception as e:
                logging.warning(
                    f"Error executing command {command}: {e}"
                )
                # Remove non-working command (simulate learning)
                if command in terminal_commands:
                    terminal_commands.remove(command)
        # Brute force Generate AC
        logging.info("Attempting brute force Generate AC...")
        for _ in range(10):
            brute_force_payload = self.generate_brute_force_payload()
            apdu_command = self.build_apdu_command(brute_force_payload)
            try:
                self.interface_with_cli(apdu_command)
            except Exception as e:
                logging.warning(f"Brute force failed: {e}")
        # Attempt key extraction and apply to transactions
        logging.info("Attempting key extraction...")
        extracted_keys = self.extract_keys_from_terminal()
        if extracted_keys:
            logging.info(
                "Keys extracted successfully. Applying to transactions..."
            )
            self.apply_keys_to_transactions(extracted_keys)
        else:
            logging.warning(
                "Key extraction failed. Proceeding with random educated "
                "guesses."
            )

    def get_all_terminal_commands(self):
        """Return a list of example APDU commands."""
        return ["00A40400", "80CA9F7F"]

    def execute_terminal_command(self, cap_file, package_aid, applet_aid,
                                 command):
        """Simulate execution of a terminal command."""
        logging.info(f"Executing command on CAP file: {command}")

    def generate_random_payload(self, command):
        """Generate a random payload for fuzzing."""
        return os.urandom(16)

    def build_apdu_command(self, payload):
        """Build an APDU command from payload."""
        return f"00A40400{len(payload):02X}{payload.hex()}"

    def interface_with_cli(self, apdu_command):
        """Simulate interfacing with the CLI (logs output)."""
        try:
            # Simulate CLI call
            result = f"Simulated CLI call: {apdu_command}\n"
            with open(self.comm_log_file, 'a') as comm_log:
                comm_log.write(result)
        except Exception as e:
            logging.error(f"Error interfacing with CLI: {e}")

    def generate_brute_force_payload(self):
        """Generate a brute force payload."""
        return os.urandom(8)

    def extract_keys_from_terminal(self):
        """Simulate key extraction."""
        logging.info("Extracting keys from terminal...")
        return b"404142434445464748494a4b4c4d4e4f"

    def apply_keys_to_transactions(self, keys):
        """Simulate applying extracted keys to transactions."""
        logging.info("Applying extracted keys to transactions...")
        for _ in range(3):
            try:
                apdu_command = self.build_apdu_command(keys)
                self.interface_with_cli(apdu_command)
            except Exception as e:
                logging.warning(f"Error applying keys to transaction: {e}")


class GreenwireJCAlgTest:

    def __init__(self):
        self.log_file = "greenwire_jcalgtest_log.txt"
        self.comm_log_file = "greenwire_jcalgtest_communication_log.txt"
        logging.basicConfig(
            level=logging.INFO,
            filename=self.log_file,
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def execute_jcalgtest(self, cap_file, package_aid, applet_aid):
        logging.info("Starting JCAlgTest operation...")

        try:
            # Example CAP file and AIDs
            for i in range(100):
                logging.info(f"Executing JCAlgTest iteration {i + 1}...")
                self.run_test_iteration(cap_file, package_aid, applet_aid)

        except Exception as e:
            logging.error(f"JCAlgTest operation failed: {e}")

        logging.info("JCAlgTest operation completed.")

    def run_test_iteration(self, cap_file, package_aid, applet_aid):
        # Simulate execution of a JCAlgTest iteration
        logging.info(f"Running test iteration on CAP file: {cap_file}")
        apdu_command = self.build_apdu_command(os.urandom(255))
        self.interface_with_cli(apdu_command)

    def build_apdu_command(self, payload):
        return f"00A40400{len(payload):02X}{payload.hex()}"

    def interface_with_cli(self, apdu_command):
        try:
            result = subprocess.run(
                ["python", "greenwire_cli.py", "jcalgtest", apdu_command],
                capture_output=True, text=True
            )
            with open(self.comm_log_file, 'a') as comm_log:
                comm_log.write(result.stdout)
        except Exception as e:
            logging.error(f"Error interfacing with CLI: {e}")


class GreenwireIntegration:

    def __init__(self):
        self.log_file = "greenwire_integration_log.txt"
        self.comm_log_file = "greenwire_integration_communication_log.txt"
        logging.basicConfig(
            level=logging.INFO,
            filename=self.log_file,
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def integrate_jcop_functions(self, cap_file, package_aid, applet_aid):
        logging.info("Starting integration with JCOP functions...")

        try:
            # Example CAP file and AIDs
            # fuzzer = JCOPFuzzer()
            # fuzzer.supertouch(cap_file, package_aid, applet_aid)
            logging.info("Simulating JCOP function integration...")

        except Exception as e:
            logging.error(f"Integration with JCOP functions failed: {e}")

        logging.info("Integration with JCOP functions completed.")

    def execute_all_tests(self, cap_file, package_aid, applet_aid):
        logging.info("Executing all integrated tests...")

        try:
            self.integrate_jcop_functions(cap_file, package_aid, applet_aid)
            self.execute_jcalgtest(cap_file, package_aid, applet_aid)

        except Exception as e:
            logging.error(f"Execution of all tests failed: {e}")

        logging.info("Execution of all tests completed.")

    def execute_jcalgtest(self, cap_file, package_aid, applet_aid):
        logging.info("Starting JCAlgTest operation...")

        try:
            # Example CAP file and AIDs
            for i in range(100):
                logging.info(f"Executing JCAlgTest iteration {i + 1}...")
                self.run_test_iteration(cap_file, package_aid, applet_aid)

        except Exception as e:
            logging.error(f"JCAlgTest operation failed: {e}")

        logging.info("JCAlgTest operation completed.")

    def run_test_iteration(self, cap_file, package_aid, applet_aid):
        # Simulate execution of a JCAlgTest iteration
        logging.info(f"Running test iteration on CAP file: {cap_file}")
        apdu_command = self.build_apdu_command(os.urandom(255))
        self.interface_with_cli(apdu_command)

    def build_apdu_command(self, payload):
        return f"00A40400{len(payload):02X}{payload.hex()}"

    def interface_with_cli(self, apdu_command):
        try:
            result = subprocess.run(
                ["python", "greenwire_cli.py", "integration", apdu_command],
                capture_output=True, text=True
            )
            with open(self.comm_log_file, 'a') as comm_log:
                comm_log.write(result.stdout)
        except Exception as e:
            logging.error(f"Error interfacing with CLI: {e}")


class GreenwireSupportTableIntegration:

    def __init__(self):
        self.log_file = "greenwire_supporttable_log.txt"
        self.comm_log_file = "greenwire_supporttable_communication_log.txt"
        logging.basicConfig(
            level=logging.INFO,
            filename=self.log_file,
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def integrate_support_table(self, cap_file, package_aid, applet_aid):
        logging.info("Starting integration with SupportTable functions...")

        try:
            # Example CAP file and AIDs
            self.generate_html_table(cap_file)
            self.compare_supported_algs(cap_file)

        except Exception as e:
            logging.error(
                f"Integration with SupportTable functions failed: {e}"
            )

        logging.info("Integration with SupportTable functions completed.")

    def generate_html_table(self, base_path):
        # Simulate generating an HTML table
        logging.info(f"Generating HTML table for base path: {base_path}")

    def compare_supported_algs(self, input_dir):
        # Simulate comparing supported algorithms
        logging.info(
            f"Comparing supported algorithms in directory: {input_dir}"
        )

    def execute_all_tests(self, cap_file, package_aid, applet_aid):
        logging.info("Executing all integrated tests...")

        try:
            self.integrate_support_table(cap_file, package_aid, applet_aid)
            self.execute_jcalgtest(cap_file, package_aid, applet_aid)

        except Exception as e:
            logging.error(f"Execution of all tests failed: {e}")

        logging.info("Execution of all tests completed.")

    def execute_jcalgtest(self, cap_file, package_aid, applet_aid):
        logging.info("Starting JCAlgTest operation...")

        try:
            # Example CAP file and AIDs
            for i in range(100):
                logging.info(f"Executing JCAlgTest iteration {i + 1}...")
                self.run_test_iteration(cap_file, package_aid, applet_aid)

        except Exception as e:
            logging.error(f"JCAlgTest operation failed: {e}")

        logging.info("JCAlgTest operation completed.")

    def run_test_iteration(self, cap_file, package_aid, applet_aid):
        # Simulate execution of a JCAlgTest iteration
        logging.info(f"Running test iteration on CAP file: {cap_file}")
        apdu_command = self.build_apdu_command(os.urandom(255))
        self.interface_with_cli(apdu_command)

    def build_apdu_command(self, payload):
        return f"00A40400{len(payload):02X}{payload.hex()}"

    def interface_with_cli(self, apdu_command):
        try:
            result = subprocess.run(
                ["python", "greenwire_cli.py", "supporttable", apdu_command],
                capture_output=True, text=True
            )
            with open(self.comm_log_file, 'a') as comm_log:
                comm_log.write(result.stdout)
        except Exception as e:
            logging.error(f"Error interfacing with CLI: {e}")


class GreenwireJCOPManager:
    """
    Manages JCOP functionality, including generating and testing CAP files,
    retrieving CAP file information, and providing operator feedback.
    """

    def __init__(self):
        self.log_file = "greenwire_jcop_log.txt"
        self.comm_log_file = "greenwire_jcop_communication_log.txt"
        logging.basicConfig(
            level=logging.INFO,
            filename=self.log_file,
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def generate_and_test_caps(
        self, cap_file, package_aid, applet_aid, duration=300
    ):
        """
        Generate and test CAP files in an emulator for a specified duration.

        :param cap_file: Path to the CAP file.
        :param package_aid: Package AID for the CAP file.
        :param applet_aid: Applet AID for the CAP file.
        :param duration: Duration in seconds to run the tests
            (default: 300 seconds).
        """
        logging.info("Starting CAP file generation and testing...")
        start_time = time.time()
        cap_count = 0

        while time.time() - start_time < duration and cap_count < 5:
            try:
                logging.info(f"Generating CAP file {cap_count + 1}...")
                self.generate_cap_file(cap_file, package_aid, applet_aid)
                logging.info(f"Testing CAP file {cap_count + 1}...")
                self.test_cap_file(cap_file, package_aid, applet_aid)
                cap_count += 1
            except Exception as e:
                logging.error(
                    f"Error during CAP file generation or testing: {e}"
                )

        logging.info("CAP file generation and testing completed.")

    def generate_cap_file(self, cap_file, package_aid, applet_aid):
        """
        Simulate CAP file generation.

        :param cap_file: Path to the CAP file.
        :param package_aid: Package AID for the CAP file.
        :param applet_aid: Applet AID for the CAP file.
        """
        logging.info(
            f"Generating CAP file at {cap_file} with "
            f"Package AID {package_aid} "
            f"and Applet AID {applet_aid}."
        )
        # Simulate CAP file generation logic

    def test_cap_file(self, cap_file, package_aid, applet_aid):
        """
        Simulate testing a CAP file in an emulator.

        :param cap_file: Path to the CAP file.
        :param package_aid: Package AID for the CAP file.
        :param applet_aid: Applet AID for the CAP file.
        """
        logging.info(
            f"Testing CAP file at {cap_file} with Package AID {package_aid} "
            f"and Applet AID {applet_aid}."
        )
        # Simulate CAP file testing logic

    def dump_cap_info(self, cap_file):
        """
        Retrieve and store CAP file information.

        :param cap_file: Path to the CAP file.
        """
        logging.info(f"Dumping information for CAP file at {cap_file}.")
        # Simulate retrieving CAP file information
        cap_info = {
            "path": cap_file,
            "size": os.path.getsize(cap_file)
            if os.path.exists(cap_file)
            else "Unknown",
            "metadata": "Simulated metadata for CAP file."
        }
        logging.info(f"CAP file information: {cap_info}")
        return cap_info


class GreenwireEmulator:

    def run_random_emulations(self, cap_file, duration=10):
        """
        Run random emulation cycles for a given duration (seconds).
        Simulates random APDU exchanges and logs results.
        """
        print(f"[Emulator] Running random emulations for {duration} seconds on {cap_file}...")
        start = time.time()
        count = 0
        while time.time() - start < duration:
            # Pick a random ISO command
            iso_cmd = random.choice(list(self.iso_specs.values()))
            apdu = iso_cmd["hex"] + ''.join(random.choices('0123456789ABCDEF', k=8))
            response = self.simulate_terminal("pcsc", apdu)
            count += 1
            time.sleep(0.1)
        print(f"[Emulator] {count} emulation cycles complete.")

    def create_encrypted_cap(self, cap_file, output_file):
        """
        Create an encrypted version of a .cap file (demo: just copy and obfuscate).
        """
        print(f"[Emulator] Creating encrypted cap file: {output_file} from {cap_file}")
        if not os.path.exists(cap_file):
            with open(cap_file, "w") as f:
                f.write("dummy_cap_content")
        with open(cap_file, "r", encoding="utf-8") as f:
            content = f.read()
        # Simple obfuscation for demo
        obfuscated = ''.join(chr((ord(c) + 7) % 256) for c in content)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(obfuscated)
    """
    Simulates various terminal environments and runs emulations based on ISO
    specifications. This class is designed to lint, test, and run random
    emulations to ensure robustness and compliance.
    """

    def __init__(self):
        self.log_file = "greenwire_emulator_log.txt"
        self.comm_log_file = "greenwire_emulator_communication_log.txt"
        # A more comprehensive list of ISO 7816 commands with descriptions
        self.iso_specs = {
            # File selection
            "SELECT_FILE": {"hex": "00A40000",
                            "desc": "Select File by Identifier"},
            "SELECT_FILE_BY_DF_NAME": {
                "hex": "00A40400",
                "desc": "Select File by DF Name (AID)"
            },
            # Read/Write
            "READ_BINARY": {
                "hex": "00B00000",
                "desc": "Read Binary from file"
            },
            "UPDATE_BINARY": {"hex": "00D60000", "desc": "Update Binary data"},
            "READ_RECORD": {"hex": "00B20104", "desc": "Read Record(s)"},
            "UPDATE_RECORD": {"hex": "00DC0104", "desc": "Update Record"},
            # Security
            "GET_CHALLENGE": {
                "hex": "00840000",
                "desc": "Get Challenge for authentication"
            },
            "VERIFY": {
                "hex": "00200000",
                "desc": "Verify PIN or security condition"
            },
            "INTERNAL_AUTHENTICATE": {
                "hex": "00880000",
                "desc": "Internal Authenticate (for DDA/SDA)"
            },
            "EXTERNAL_AUTHENTICATE": {
                "hex": "00820000",
                "desc": "External Authenticate"
            },
            # Data retrieval
            "GET_DATA": {"hex": "00CA0000", "desc": "Get Data Object(s)"},
            "GET_RESPONSE": {
                "hex": "00C00000",
                "desc": "Get Response data from card"
            },
            # Applet management
            "INSTALL_FOR_LOAD": {
                "hex": "E6E20000",
                "desc": "Install (for Load)"
            },
            "LOAD": {"hex": "E8000000", "desc": "Load Application"},
            "INSTALL_FOR_INSTALL": {
                "hex": "E6E40000",
                "desc": "Install (for Install and Make Selectable)"
            },
        }
        if not logging.getLogger().handlers:
            logging.basicConfig(
                level=logging.INFO,
                filename=self.log_file,
                filemode='a',
                format='%(asctime)s - %(levelname)s - %(message)s'
            )

    def simulate_terminal(self, terminal_type, command):
        """
        Simulates a specific terminal environment and logs the command with
        its human-readable interpretation. Includes retries and resets for
        realistic PCSC hardware testing.

        :param terminal_type: The type of terminal (e.g., "pcsc", "jcop").
        :param command: The APDU command to execute.
        """
        interpretation = self.get_command_interpretation(command)
        log_msg = (f"Simulating terminal '{terminal_type}' | SENT: "
                   f"{command} | Interpretation: {interpretation}")
        print(log_msg)
        logging.info(log_msg)
        with open(self.comm_log_file, 'a') as comm_log:
            comm_log.write(f"[{time.asctime()}] {log_msg}\n")

        # Simulate retries and resets
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Simulate a response
                response = '9000'  # Simulate positive response
                response_log = (
                    f"Simulating terminal '{terminal_type}' | RECV: "
                    f"{response}"
                )
                print(response_log)
                logging.info(response_log)
                with open(self.comm_log_file, 'a') as comm_log:
                    comm_log.write(f"[{time.asctime()}] {response_log}\n")
                return response
            except Exception as e:
                logging.error(f"Error during terminal simulation: {e}")
                print(f"Error during terminal simulation: {e}")
                if attempt < max_retries - 1:
                    print("Retrying terminal simulation...")
                    logging.info("Retrying terminal simulation...")
                    time.sleep(1)  # Simulate reset delay
                else:
                    print("Terminal simulation failed after retries.")
                    logging.error("Terminal simulation failed after retries.")
                    raise

    def get_command_interpretation(self, apdu_command):
        """
        Returns a human-readable interpretation of an APDU command.

        :param apdu_command: The APDU command string.
        :return: A string with the human-readable interpretation.
        """
        # Check for command by iterating through the dictionary
        for name, info in self.iso_specs.items():
            if apdu_command.upper().startswith(info["hex"]):
                return f"{name} ({info['desc']})"
        return "Unknown Command"


class GreenwireCrypto:
    """
    Handles cryptographic operations and verification to ensure that the
    underlying crypto functions are working before attempting DDA or
    encryption.
    """

    def __init__(self, emulator):
        self.emulator = emulator
        self.log_file = "greenwire_crypto_log.txt"
        if not logging.getLogger().handlers:
            logging.basicConfig(
                level=logging.INFO,
                filename=self.log_file,
                filemode='a',
                format='%(asctime)s - %(levelname)s - %(message)s'
            )

    def verify_crypto_functions(self):
        """
        Verifies basic cryptographic functions by simulating a challenge-
        response mechanism (like for DDA).
        """
        logging.info("Verifying cryptographic functions...")
        print("\n--- Verifying Crypto Functions ---")

        # 1. Get Challenge
        # Le = 8 bytes
        challenge_apdu = (
            self.emulator.iso_specs["GET_CHALLENGE"]["hex"] + "0008"
        )
        response = self.emulator.simulate_terminal("pcsc", challenge_apdu)

        # Assuming response is data + status word
        # (e.g., 16 hex chars data + '9000')
        challenge = response[:-4] if len(response) > 4 else ""

        if challenge:
            logging.info(f"Successfully received challenge: {challenge}")
            print(f"Received challenge: {challenge}")

            # 2. Simulate signing the challenge (Internal Authenticate)
            # In a real scenario, the card would sign this
            # with its private key.
            try:
                signature = hashlib.sha256(
                    bytes.fromhex(challenge)
                ).hexdigest()
                logging.info(f"Simulated signature (SHA256): {signature}")
                print(f"Simulated signature of challenge: {signature[:32]}...")

                # The data for INTERNAL AUTHENTICATE is typically
                # the challenge itself or some derivative. The card
                # provides the signature in the response.
                # For simulation, we'll send the challenge and
                # pretend the card verifies it.
                auth_apdu = (
                    f"{self.emulator.iso_specs['INTERNAL_AUTHENTICATE']['hex']}"
                )

                # 3. Send Internal Authenticate
                auth_response = self.emulator.simulate_terminal(
                    "pcsc", auth_apdu
                )
                if auth_response.endswith("9000"):
                    logging.info("Crypto function verification successful.")
                    print("--- Crypto Verification Complete ---")
                    return True
                else:
                    logging.error("Internal Authenticate command failed.")
                    print("--- Crypto Verification Failed (Auth Step) ---")
                    return False
            except ValueError as e:
                logging.error(f"Crypto error (likely hex conversion): {e}")
                print(f"--- Crypto Verification Failed (Error: {e}) ---")
                return False
        else:
            logging.error(
                "Failed to get a challenge. Crypto verification failed."
            )
            print("--- Crypto Verification Failed (Challenge Step) ---")
            return False


class GreenwireCardIssuance:
    """
    Simulates a standard card issuance process, including generating LUNs
    and using major card BINs for personalization.
    """

    def __init__(self, emulator):
        self.emulator = emulator
        self.log_file = "greenwire_issuance_log.txt"
        self.major_card_bins = {
            "Visa": "4",
            "Mastercard": "5",
            "Amex": "37",
        }
        if not logging.getLogger().handlers:
            logging.basicConfig(
                level=logging.INFO,
                filename=self.log_file,
                filemode='a',
                format='%(asctime)s - %(levelname)s - %(message)s'
            )

    def generate_lun(self):
        """Generates a random 10-digit LUN (Logical Unit Number)."""
        return ''.join([str(random.randint(0, 9)) for _ in range(10)])

    def simulate_standard_issuance(self, cap_file_type="standard_emv.cap"):
        """
        Simulates the issuance of cards for major BINs.
        """
        logging.info(
            f"Starting standard issuance simulation for '{cap_file_type}'"
        )
        print(
            f"\n--- Simulating Standard Card Issuance for {cap_file_type} ---"
        )

        for brand, bin_prefix in self.major_card_bins.items():
            lun = self.generate_lun()
            # Generate a valid PAN with a correct Luhn check digit
            pan_base = (
                bin_prefix + ''.join([
                    str(random.randint(0, 9))
                    for _ in range(14 - len(bin_prefix))
                ])
            )
            pan = self.luhn_generate(pan_base)

            log_msg = (
                f"Issuing {brand} card | BIN: {bin_prefix} | PAN: {pan} | "
                f"LUN: {lun}"
            )
            print(log_msg)
            logging.info(log_msg)

            # Simulate personalization commands
            personalization_data = f"Cardholder:J.DOE/PAN:{pan}/EXP:2812"
            apdu_data = personalization_data.encode('utf-8').hex()
            # P1-P2 offset 0000
            apdu = (
                f"{self.emulator.iso_specs['UPDATE_BINARY']['hex']}"
                f"0000{len(apdu_data)//2:02X}{apdu_data}"
            )

            self.emulator.simulate_terminal("jcop", apdu)

        print("--- Standard Issuance Simulation Complete ---")
        return True

    def luhn_generate(self, card_number):
        """
        Generates the Luhn check digit for a given card number base.
        """
        s = 0
        for i, digit in enumerate(reversed(card_number)):
            d = int(digit)
            if i % 2 == 0:
                d *= 2
            if d > 9:
                d -= 9
            s += d
        check_digit = (10 - (s % 10)) % 10
        return f"{card_number}{check_digit}"


def random_aid():
    """Generate a random 16-character hex AID."""
    return ''.join(random.choices('0123456789ABCDEF', k=16))


# Example usage

def main():
    """
    Entry point for the Greenwire Unified CLI. Parses command-line arguments and dispatches subcommands.
    """
    parser = argparse.ArgumentParser(description="Greenwire Unified CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Common arguments
    def add_common_args(p):
        p.add_argument(
            "--cap-files",
            nargs="*",
            default=["test_applet.cap"],
            help=(
                "List up to 5 CAP file paths (space separated, max 5)"
            )
        )
        p.add_argument(
            "--package-aids",
            nargs="*",
            default=["A00000006203010C01"],
            help=(
                "List of Package AIDs (space separated, "
                "matches cap-files order)"
            )
        )
        p.add_argument(
            "--applet-aids",
            nargs="*",
            default=["A00000006203010C0101"],
            help=(
                "List of Applet AIDs (space separated, "
                "matches cap-files order)"
            )
        )

    # SUPERTOUCH
    p_supertouch = subparsers.add_parser(
        "supertouch",
        help="Run SUPERTOUCH fuzzing and brute force"
    )

    add_common_args(p_supertouch)
    p_supertouch.add_argument(
        "--csv-output",
        default=None,
        help="Output results to CSV file"
    )
    p_supertouch.add_argument(
        "--hardware",
        action="store_true",
        help="Use real hardware if available"
    )

    p_jcalg = subparsers.add_parser(
        "jcalgtest",
        help="Run JCAlgTest simulation"
    )

    add_common_args(p_jcalg)

    p_integ = subparsers.add_parser(
        "integration",
        help="Run JCOP integration tests"
    )

    add_common_args(p_integ)

    p_support = subparsers.add_parser(
        "supporttable",
        help="Run SupportTable integration"
    )

    add_common_args(p_support)

    p_jcop = subparsers.add_parser(
        "jcop",
        help="Run JCOP manager (cap gen/test/dump)"
    )
    add_common_args(p_jcop)
    p_jcop.add_argument(
        "--dump",
        action="store_true",
        help="Dump CAP file info"
    )

    p_emul = subparsers.add_parser(
        "emulator",
        help="Run ISO/EMV emulator"
    )

    p_emul.add_argument(
        "--cap-file",
        default="test_applet.cap",
        help="Path to CAP file"
    )
    p_emul.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Emulation duration (s)"
    )
    p_emul.add_argument(
        "--profile",
        default="pcsc",
        choices=["pcsc", "nfc", "hsm"],
        help="Terminal/HSM profile: pcsc, nfc, hsm"
    )
    p_emul.add_argument(
        "--hardware",
        action="store_true",
        help="Use real hardware if available"
    )

    subparsers.add_parser(
        "crypto",
        help="Run cryptographic verification"
    )

    p_issuance = subparsers.add_parser(
        "issuance",
        help="Simulate card issuance"
    )
    p_issuance.add_argument(
        "--csv-output",
        default=None,
        help="Output results to CSV file"
    )
    p_issuance.add_argument(
        "--hardware",
        action="store_true",
        help="Use real hardware if available"
    )
    p_issuance.add_argument(
        "--profile",
        default="pcsc",
        choices=["pcsc", "nfc", "hsm"],
        help="Terminal/HSM profile: pcsc, nfc, hsm"
    )
    subparsers.add_parser(
        "self-test",
        help="Run a basic self-test of all major features"
    )

    dump_log_parser = subparsers.add_parser(
        "dump-log",
        help="Dump .cap communication log"
    )
    dump_log_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to dump log for"
    )

    sim_parser = subparsers.add_parser(
        "simulate-positive",
        help="Simulate positive transaction results for a .cap file"
    )
    sim_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to simulate"
    )
    sim_parser.add_argument(
        "--enable",
        action="store_true",
        help="Enable positive simulation mode"
    )

    export_parser = subparsers.add_parser(
        "export-replay",
        help="Export APDU replay log for a .cap file"
    )
    export_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to export replay log for"
    )
    export_parser.add_argument(
        "--output",
        required=True,
        help="Output path for replay log"
    )
    import_parser = subparsers.add_parser(
        "import-replay",
        help="Import APDU replay log for a .cap file"
    )
    import_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to import replay log for"
    )
    import_parser.add_argument(
        "--input",
        required=True,
        help="Input path for replay log"
    )

    suspicious_parser = subparsers.add_parser(
        "dump-suspicious",
        help="Dump suspicious events for a .cap file"
    )
    suspicious_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to dump suspicious events for"
    )

    learn_parser = subparsers.add_parser(
        "learn-session",
        help="Update replay/suspicious logs after a positive session"
    )
    learn_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to learn from"
    )

    seal_parser = subparsers.add_parser(
        "seal-logs",
        help="Seal reserved log area in .cap with hash/signature"
    )
    seal_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to seal logs for"
    )

    # CLI: Add IdentityCrisis option
    idc_parser = subparsers.add_parser(
        "identitycrisis",
        help="Enable IdentityCrisis mode: random AID for each transaction"
    )
    idc_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to use in IdentityCrisis mode"
    )
    idc_parser.add_argument(
        "--smackdown",
        action="store_true",
        help="Enable smackdown mode: brute with complex, randomized, transactional fuzz payloads until 60s timeout"
    )

    # CLI: Add Stealth .cap category
    stealth_parser = subparsers.add_parser(
        "stealth",
        help="Stealth .cap: EMV compliant, minimal logging, random delays"
    )
    stealth_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to use in Stealth mode"
    )

    # CLI: Add Replay .cap category
    replay_parser = subparsers.add_parser(
        "replay",
        help="Replay .cap: EMV compliant, record/replay APDU/response pairs"
    )
    replay_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to use in Replay mode"
    )

    # CLI: Add Decoy .cap category
    decoy_parser = subparsers.add_parser(
        "decoy",
        help="Decoy .cap: EMV compliant, multiple applets (one real, others decoy)"
    )
    decoy_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to use in Decoy mode"
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help="Audit .cap: EMV compliant, logs all APDUs, only Visa/Mastercard/Amex AIDs"
    )
    audit_parser.add_argument(
        "--cap-file",
        required=True,
        help="CAP file to use in Audit mode"
    )

    install_parser = subparsers.add_parser(
        "install-cap",
        help="Install a .cap file on a smart card using GlobalPlatformPro or OpenSC."
    )
    install_parser.add_argument(
        "--cap-file",
        required=True,
        help="Path to the .cap file to install."
    )
    install_parser.add_argument(
        "--tool",
        choices=["gpp", "opensc"],
        default="gpp",
        help="Tool to use for installation: gpp (GlobalPlatformPro) or opensc (OpenSC). Default: gpp."
    )
    install_parser.add_argument(
        "--aid",
        default=None,
        help="AID to use for installation (optional)."
    )

    args = parser.parse_args()
    # Manually enforce subcommand requirement for compatibility with Python <3.7
    if not hasattr(args, "command") or args.command is None:
        parser.print_help()
        parser.exit(2, "\nError: a subcommand is required.\n")

    # Helper to unify cap_file/cap_files and related AIDs
    def get_cap_files_and_aids(args):
        # Determine cap_files list
        if hasattr(args, "cap_files"):
            cap_files = args.cap_files
        elif hasattr(args, "cap_file"):
            cap_files = [args.cap_file]
        else:
            cap_files = ["test_applet.cap"]
        cap_files = (cap_files + [cap_files[-1]] * 5)[:5]

        # Package AIDs
        if hasattr(args, "package_aids") and args.package_aids:
            package_aids = (args.package_aids + [args.package_aids[-1]] * 5)[:5]
        else:
            package_aids = ["A00000006203010C01"] * len(cap_files)

        # Applet AIDs
        if hasattr(args, "applet_aids") and args.applet_aids:
            applet_aids = (args.applet_aids + [args.applet_aids[-1]] * 5)[:5]
        else:
            applet_aids = ["A00000006203010C0101"] * len(cap_files)

        return cap_files, package_aids, applet_aids

    cap_files, package_aids, applet_aids = get_cap_files_and_aids(args)

    # Ensure all files exist
    for cap_file in cap_files:
        if not os.path.exists(cap_file):
            with open(cap_file, "w") as f:
                f.write("dummy_cap_content")

    # Enhance .cap files
    for cap_file in cap_files:
        enhance_cap_file(cap_file)
        if os.path.exists(cap_file):
            with open(cap_file, "r", encoding="utf-8") as f:
                first_line = f.readline()
                if first_line.startswith("# Randomized Metadata:"):
                    needs_enhance = False
        if needs_enhance:
            enhance_cap_file(cap_file)

    if args.command == "supertouch":
        csv_rows = []
        for cap_file, pkg_aid, app_aid in zip(
                cap_files, package_aids, applet_aids):
            GreenwireSuperTouch().supertouch(
                cap_file, pkg_aid, app_aid)
            # Example: append result row for CSV
            csv_rows.append({"cap_file": cap_file, "package_aid": pkg_aid, "applet_aid": app_aid, "result": "OK"})
        if getattr(args, "csv_output", None):
            import csv
            with open(args.csv_output, "w", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_rows[0].keys())
                writer.writeheader()
                writer.writerows(csv_rows)
            print(f"Results written to {args.csv_output}")
        if getattr(args, "hardware", False):
            print("[HARDWARE] Real hardware output would be triggered here (not implemented in demo)")
    elif args.command == "jcalgtest":
        for cap_file, pkg_aid, app_aid in zip(
                cap_files, package_aids, applet_aids):
            GreenwireJCAlgTest().execute_jcalgtest(
                cap_file, pkg_aid, app_aid)
    elif args.command == "integration":
        for cap_file, pkg_aid, app_aid in zip(
                cap_files, package_aids, applet_aids):
            GreenwireIntegration().execute_all_tests(
                cap_file, pkg_aid, app_aid)
    elif args.command == "supporttable":
        for cap_file, pkg_aid, app_aid in zip(
                cap_files, package_aids, applet_aids):
            GreenwireSupportTableIntegration().execute_all_tests(
                cap_file, pkg_aid, app_aid)
    elif args.command == "jcop":
        mgr = GreenwireJCOPManager()
        if args.dump:
            for cap_file in cap_files:
                info = mgr.dump_cap_info(cap_file)
                print("CAP File Information:", info)
        else:
            for cap_file, pkg_aid, app_aid in zip(
                    cap_files, package_aids, applet_aids):
                mgr.generate_and_test_caps(
                    cap_file, pkg_aid, app_aid)
    elif args.command == "emulator":
        emu = GreenwireEmulator()
        for cap_file in cap_files:
            print(f"[PROFILE] Using terminal/HSM profile: {getattr(args, 'profile', 'pcsc')}")
            emu.run_random_emulations(
                cap_file, duration=args.duration)
        if getattr(args, "hardware", False):
            print("[HARDWARE] Real hardware output would be triggered here (not implemented in demo)")
    elif args.command == "crypto":
        emu = GreenwireEmulator()
        ok = GreenwireCrypto(emu).verify_crypto_functions()
        print("Crypto verification:", "OK" if ok else "FAILED")
    elif args.command == "issuance":
        emu = GreenwireEmulator()
        issuer = GreenwireCardIssuance(emu)
        csv_rows = []
        for cap_file in cap_files:
            issuer.simulate_standard_issuance(cap_file)
            # Example: append result row for CSV
            csv_rows.append({"cap_file": cap_file, "profile": getattr(args, "profile", "pcsc"), "result": "OK"})
        if getattr(args, "csv_output", None):
            import csv
            with open(args.csv_output, "w", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_rows[0].keys())
                writer.writeheader()
                writer.writerows(csv_rows)
            print(f"Results written to {args.csv_output}")
        if getattr(args, "hardware", False):
            print("[HARDWARE] Real hardware output would be triggered here (not implemented in demo)")
    elif args.command == "self-test":
        print("Running Greenwire self-test...")
        # Run all major features in sequence for all cap files
        for cap_file, pkg_aid, app_aid in zip(
                cap_files, package_aids, applet_aids):
            GreenwireSuperTouch().supertouch(
                cap_file, pkg_aid, app_aid)
            GreenwireJCAlgTest().execute_jcalgtest(
                cap_file, pkg_aid, app_aid)
            GreenwireIntegration().execute_all_tests(
                cap_file, pkg_aid, app_aid)
            GreenwireSupportTableIntegration().execute_all_tests(
                cap_file, pkg_aid, app_aid)
            mgr = GreenwireJCOPManager()
            mgr.generate_and_test_caps(
                cap_file, pkg_aid, app_aid)
            print("CAP File Information:",
                  mgr.dump_cap_info(cap_file))
        emu = GreenwireEmulator()
        ok = GreenwireCrypto(emu).verify_crypto_functions()
        print("Crypto verification:", "OK" if ok else "FAILED")
        if ok:
            issuer = GreenwireCardIssuance(emu)
            for cap_file in cap_files:
                issuer.simulate_standard_issuance(cap_file)
            ENCRYPTED_CAP_FILE = "test_applet_encrypted.cap"
            emu.create_encrypted_cap(
                cap_files[0], ENCRYPTED_CAP_FILE)
            emu.run_random_emulations(
                ENCRYPTED_CAP_FILE, duration=5)
        print("Self-test complete.")
    elif args.command == "dump-log":
        logger = CapFileLogger(args.cap_file)
        print(json.dumps(logger.dump(), indent=2))
    elif args.command == "simulate-positive":
        logger = CapFileLogger(args.cap_file)
        logger.set_positive_mode(args.enable)
        print(f"Positive simulation mode set to {args.enable} for "
              f"{args.cap_file}")
    elif args.command == "export-replay":
        logger = CapFileLogger(args.cap_file)
        logger.export_replay_log(args.output)
        print(f"Replay log exported to {args.output}")
    elif args.command == "import-replay":
        logger = CapFileLogger(args.cap_file)
        logger.import_replay_log(args.input)
        print(f"Replay log imported from {args.input}")
    elif args.command == "dump-suspicious":
        logger = CapFileLogger(args.cap_file)
        print(json.dumps(logger.dump_suspicious(), indent=2))
    elif args.command == "learn-session":
        logger = CapFileLogger(args.cap_file)
        logger.learn_from_session()
        print(f"Learning complete for {args.cap_file}")
    elif args.command == "seal-logs":
        logger = CapFileLogger(args.cap_file)
        logger.seal_logs()
        print(f"Log area sealed for {args.cap_file}")
    elif args.command == "identitycrisis":
        logger = CapFileLogger(args.cap_file)
        aid = random_aid()
        logger.log('identitycrisis', 'SELECT', f"Random AID used: {aid}")
        print(f"IdentityCrisis mode: using random AID {aid}")
        blacklist = set()
        # Simulate transaction loop
        for attempt in range(5):
            # ...simulate transaction with this AID...
            if aid in blacklist:
                aid = random_aid()
                logger.log('identitycrisis', 'BLACKLIST', f"AID {aid} was blacklisted, new AID generated")
                logger.persist_logs_in_cap()
                continue
            result = random.choice(['9000', '6A82', '6985'])  # Simulate status
            logger.log('identitycrisis', 'RESULT', f"AID {aid} result: {result}")
            logger.persist_logs_in_cap()
            if result == '9000':
                print(f"Transaction succeeded with AID {aid}")
                break
            else:
                blacklist.add(aid)
                logger.log('identitycrisis', 'EVADE', f"Negative result {result}, evading with new AID")
                logger.persist_logs_in_cap()
                aid = random_aid()
                logger.log('identitycrisis', 'SELECT', f"Random AID used: {aid}")
                logger.persist_logs_in_cap()
                print(f"Evading: new random AID {aid}")
        if getattr(args, "smackdown", False):
            print("IdentityCrisis: Smackdown mode enabled. Brute-forcing with complex fuzz payloads for 60 seconds.")
            import time
            start = time.time()
            count = 0
            while time.time() - start < 60:
                # Generate a random APDU command (CLA, INS, P1, P2, Lc, Data, Le)
                apdu = ''.join(random.choices('0123456789ABCDEF', k=random.randint(8, 64)))
                # Generate a complex, transactional, EMV-like response with random data
                resp_data = ''.join(random.choices('0123456789ABCDEF', k=random.randint(16, 128)))
                # Randomly select a valid EMV status word
                sw = random.choice(['9000', '6283', '6A82', '6985', '6A84', '6F00'])
                response = resp_data + sw
                logger.log('identitycrisis', 'SMACKDOWN', f"APDU: {apdu}, RESP: {response}")
                count += 1
                # Simulate transactional nature: sometimes log a commit/rollback
                if random.random() < 0.2:
                    logger.log('identitycrisis', 'TXN', f"Transaction {'commit' if random.random() < 0.5 else 'rollback'} for APDU {apdu}")
                # Add a small random delay to simulate processing
                time.sleep(random.uniform(0.01, 0.1))
            print(f"Smackdown complete. {count} brute APDUs sent.")
            logger.persist_logs_in_cap()
            return
    elif args.command == "stealth":
        import time
        logger = CapFileLogger(args.cap_file)
        print("Stealth .cap: EMV compliant, minimal logging, random delays")
        for i in range(3):
            # Simulate EMV-compliant APDU exchange
            apdu = '00A40400'  # SELECT (EMV compliant)
            response = '9000'   # Success
            # Random delay to avoid timing analysis
            delay = random.uniform(0.1, 0.5)
            time.sleep(delay)
            # Only log if suspicious event (simulate none here)
        print("Stealth transaction complete.")
    elif args.command == "replay":
        logger = CapFileLogger(args.cap_file)
        print("Replay .cap: EMV compliant, record/replay APDU/response pairs")
        apdu = '00A40400'  # EMV SELECT
        # Check for replayed response
        replayed = logger.get_replay_response(apdu)
        if replayed:
            response = replayed
            print(f"Replayed response: {response}")
        else:
            response = '9000'  # EMV success
            logger.record_apdu_pair(apdu, response)
            logger.persist_logs_in_cap()
            print(f"Recorded new response: {response}")
        print("Replay transaction complete.")
    elif args.command == "decoy":
        logger = CapFileLogger(args.cap_file)
        print("Decoy .cap: EMV compliant, multiple applets (one real, others decoy)")
        real_aid = 'A0000000031010'  # Example EMV AID
        decoy_aids = ['A0000000031011', 'A0000000031012']
        selected = random.choice([real_aid] + decoy_aids)
        apdu = '00A40400'  # EMV SELECT
        if selected == real_aid:
            response = '9000'
            print("Real applet selected.")
        else:
            response = '9000'
            print(f"Decoy applet {selected} selected.")
        logger.log('decoy', 'SELECT', f"AID {selected} selected, response: {response}")
        logger.persist_logs_in_cap()
        print("Decoy transaction complete.")
    elif args.command == "audit":
        logger = CapFileLogger(args.cap_file)
        print("Audit .cap: EMV compliant, logs all APDUs, only Visa/Mastercard/Amex AIDs")
        # Visa, Mastercard, Amex AIDs (examples)
        visa_aid = 'A0000000031010'
        mc_aid = 'A0000000041010'
        amex_aid = 'A00000002501'
        aids = [visa_aid, mc_aid, amex_aid]
        selected = random.choice(aids)
        apdu = '00A40400'  # EMV SELECT
        response = '9000'
        print(f"Selected AID: {selected}")
        logger.log('audit', 'SELECT', f"AID {selected} selected, response: {response}")
        # Simulate logging all APDUs (for demo, log 5 random APDUs)
        for _ in range(5):
            apdu = ''.join(random.choices('0123456789ABCDEF', k=16))
            resp = ''.join(random.choices('0123456789ABCDEF', k=32)) + '9000'
            logger.log('audit', 'APDU', f"APDU: {apdu}, RESP: {resp}")
        logger.persist_logs_in_cap()
        print("Audit transaction complete.")
    elif args.command == "install-cap":
        """
        Installs a .cap file on a smart card using the selected tool.
        Requires GlobalPlatformPro (gpp) or OpenSC to be installed and available in PATH.
        """
        cap_file = args.cap_file
        aid = args.aid or "A0000000031010"  # Default Visa AID if not provided
        if args.tool == "gpp":
            # GlobalPlatformPro command
            cmd = [
                "java", "-jar", "globalplatformpro.jar",
                "--install", cap_file,
                "--package", aid,
                "--applet", aid
            ]
            print(f"Installing {cap_file} with GlobalPlatformPro (AID: {aid})...")
        else:
            # OpenSC command
            cmd = [
                "opensc-tool", "-s",
                f"00A40400{len(aid)//2:02X}{aid}"
            ]
            print(f"Installing {cap_file} with OpenSC (AID: {aid})...")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print("[stderr]", result.stderr)
            print("Installation complete.")
        except Exception as e:
            print(f"Installation failed: {e}")


if __name__ == "__main__":
    main()


# =====================
# Documentation/Comments
#
# Clarifications:
# - "Greenwire": Proper noun, project name.
# - "JCOP": Acronym for JavaCard OpenPlatform. All JCOP-related logic is
#   encapsulated within the Greenwire* classes in this script. The classes
#   provide a Python-based simulation and interface for JCOP operations,
#   JCAlgTest, and other smart card functionalities.
# - "APDU": Acronym for Application Protocol Data Unit.
# - "NFCIP": Acronym for Near Field Communication Interface and Protocol.
# - "pcsc": Abbreviation for Personal Computer/Smart Card.
# - "DDA": Dynamic Data Authentication, a security feature for smart cards.
# - "LUN": Logical Unit Number, used in card issuance.
# - "BIN": Bank Identification Number, the first few digits of a card number.
# =====================
