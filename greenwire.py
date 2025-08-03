

# Greenwire Unified CLI
# ---------------------
# Swiss army knife for smartcard, EMV, JCOP, and .cap file emulation,
# testing, and issuance.
#
# Usage:
#   python greenwire.py <subcommand> [options]
#
# Subcommands:
#   supertouch   Run SUPERTOUCH operation (fuzzing, brute force,
#                key extraction)
#   jcalgtest    Run JCAlgTest simulation
#   integration  Run JCOP integration tests
#   supporttable Run SupportTable integration
#   jcop         Run JCOP manager (cap gen/test/dump)
#   emulator     Run ISO/EMV emulator
#   crypto       Run cryptographic verification
#   issuance     Simulate card issuance
#   self-test    Run a basic self-test of all major features
#
# Use -h/--help after any subcommand for details.

import argparse
import os
import subprocess
import logging
import time
import random
import hashlib


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
            f"Generating CAP file at {cap_file} with Package AID {package_aid} "
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

    def simulate_terminal(self, terminal_type, command):
        """
        Simulates a specific terminal environment and logs the command with
        its human-readable interpretation.

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
        # Simulate a response
        response_sw = "9000"  # Simulate success
        response_data = os.urandom(random.randint(8, 32)).hex()
        response_log = (
            f"Simulating terminal '{terminal_type}' | RECV: "
            f"{response_data}{response_sw}"
        )
        print(response_log)
        logging.info(response_log)
        with open(self.comm_log_file, 'a') as comm_log:
            comm_log.write(f"[{time.asctime()}] {response_log}\n")
        return f"{response_data}{response_sw}"

    def create_encrypted_cap(self, base_cap_file, encrypted_cap_file):
        """
        Simulates the creation of a CAP file with strong encryption (DDA).
        In a real scenario, this would involve cryptographic operations.
        """
        log_msg = (
            f"Simulating DDA and strong encryption for '{base_cap_file}'"
            f" -> '{encrypted_cap_file}'"
        )
        print(log_msg)
        logging.info(log_msg)
        # Simulate by copying the file and appending a pseudo-signature
        if os.path.exists(base_cap_file):
            with open(base_cap_file, 'rb') as f_in, \
                 open(encrypted_cap_file, 'wb') as f_out:
                f_out.write(f_in.read())
                f_out.write(b'\n#--ENCRYPTED_DDA_SIGNATURE--#\n')
                f_out.write(os.urandom(128))
            logging.info(f"Created encrypted CAP file: {encrypted_cap_file}")
        else:
            logging.error(f"Base CAP file not found: {base_cap_file}")

    def run_random_emulations(self, cap_file, duration=60):
        """
        Runs random emulations using various ISO commands for a duration.

        :param cap_file: Path to the CAP file being tested.
        :param duration: Duration in seconds to run the emulations.
        """
        log_msg = (
            f"Starting random emulations on '{cap_file}' for {duration}s."
        )
        print(log_msg)
        logging.info(log_msg)
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                command_name = random.choice(list(self.iso_specs.keys()))
                command_hex = self.iso_specs[command_name]["hex"]
                lc = random.randint(0, 255)
                payload = os.urandom(lc)
                le = random.randint(0, 256)
                le_hex = f"{le:02X}" if le < 256 else "00"

                apdu = f"{command_hex}{lc:02X}{payload.hex()}{le_hex}"
                terminal = random.choice(["pcsc", "jcop", "custom_serial"])

                self.simulate_terminal(terminal, apdu)
                time.sleep(random.uniform(0.05, 0.2))
            except Exception as e:
                logging.error(f"Error during random emulation: {e}")
        logging.info("Random emulations completed.")


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
        
    # Assuming response is data + status word (e.g., 16 hex chars data + '9000')
        challenge = response[:-4] if len(response) > 4 else ""

        if challenge:
            logging.info(f"Successfully received challenge: {challenge}")
            print(f"Received challenge: {challenge}")

            # 2. Simulate signing the challenge (Internal Authenticate)
            # In a real scenario, the card would sign this with its private key.
            # Here we just hash the challenge as a simulation.
            try:
                signature = hashlib.sha256(bytes.fromhex(challenge)).hexdigest()
                logging.info(f"Simulated signature (SHA256): {signature}")
                print(f"Simulated signature of challenge: {signature[:32]}...")

                # The data for INTERNAL AUTHENTICATE is typically the challenge itself
                # or some derivative. The card provides the signature in the response.
                # For simulation, we'll send the challenge and pretend the card verifies it.
                auth_apdu_data = challenge
                auth_apdu = (
                    f"{self.emulator.iso_specs['INTERNAL_AUTHENTICATE']['hex']}"
                    f"{len(auth_apdu_data)//2:02X}{auth_apdu_data}"
                )

                # 3. Send Internal Authenticate
                auth_response = self.emulator.simulate_terminal("pcsc", auth_apdu)
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
                f"{bin_prefix}{''.join([str(random.randint(0, 9)) for _ in range(14 - len(bin_prefix))])}"
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


# Example usage

def main():
    parser = argparse.ArgumentParser(description="Greenwire Unified CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

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

    subparsers.add_parser(
        "crypto",
        help="Run cryptographic verification"
    )
    subparsers.add_parser(
        "issuance",
        help="Simulate card issuance"
    )
    subparsers.add_parser(
        "self-test",
        help="Run a basic self-test of all major features"
    )

    args = parser.parse_args()

    # Ensure dummy cap file exists
    # Cap file argument validation and limiting
    cap_files = args.cap_files[:5]
    package_aids = (args.package_aids + [args.package_aids[-1]] * 5)[:5]
    applet_aids = (args.applet_aids + [args.applet_aids[-1]] * 5)[:5]
    # Ensure all files exist
    for cap_file in cap_files:
        if not os.path.exists(cap_file):
            with open(cap_file, "w") as f:
                f.write("dummy_cap_content")

    if args.command == "supertouch":
        for cap_file, pkg_aid, app_aid in zip(
                cap_files, package_aids, applet_aids):
            GreenwireSuperTouch().supertouch(
                cap_file, pkg_aid, app_aid)
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
            emu.run_random_emulations(
                cap_file, duration=args.duration)
    elif args.command == "crypto":
        emu = GreenwireEmulator()
        ok = GreenwireCrypto(emu).verify_crypto_functions()
        print("Crypto verification:", "OK" if ok else "FAILED")
    elif args.command == "issuance":
        emu = GreenwireEmulator()
        issuer = GreenwireCardIssuance(emu)
        for cap_file in cap_files:
            issuer.simulate_standard_issuance(cap_file)
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
