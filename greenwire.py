# spell-checker:ignore Greenwire JCOP APDU NFCIP pcsc smartcards jcop apdu

#!/usr/bin/env python3

import argparse
import os
import subprocess
import logging
import time
import random
import hashlib


class GreenwireSuperTouch:

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

                # Generate random payloads based on results
                random_payload = self.generate_random_payload(command)
                apdu_command = self.build_apdu_command(random_payload)

                # Interface with the Python CLI system
                self.interface_with_cli(apdu_command)

            except Exception as e:
                logging.warning(
                    f"Error executing command {command}: {e}"
                )
                terminal_commands.remove(command)  # Remove non-working command

        # Brute force Generate AC
        logging.info("Attempting brute force Generate AC...")
        for _ in range(1000):
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
        return ["00A40400", "80CA9F7F"]  # Example APDU commands

    def execute_terminal_command(
        self, cap_file, package_aid, applet_aid, command
    ):
        # Simulate execution of a terminal command
        logging.info(
            f"Executing command on CAP file: {command}"
        )

    def generate_random_payload(self, command):
        return os.urandom(255)  # Generate random payload

    def build_apdu_command(self, payload):
        return f"00A40400{len(payload):02X}{payload.hex()}"

    def interface_with_cli(self, apdu_command):
        try:
            result = subprocess.run(
                ["python", "greenwire_cli.py", "supertouch", apdu_command],
                capture_output=True, text=True
            )
            with open(self.comm_log_file, 'a') as comm_log:
                comm_log.write(result.stdout)
        except Exception as e:
            logging.error(f"Error interfacing with CLI: {e}")

    def generate_brute_force_payload(self):
        return os.urandom(255)  # Generate brute force payload

    def extract_keys_from_terminal(self):
        logging.info("Extracting keys from terminal...")
        return b"404142434445464748494a4b4c4d4e4f"  # Example keys

    def apply_keys_to_transactions(self, keys):
        logging.info("Applying extracted keys to transactions...")
        for _ in range(10):
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
            "SELECT_FILE": {"hex": "00A40000", "desc": "Select File by Identifier"},
            "SELECT_FILE_BY_DF_NAME": {"hex": "00A40400", "desc": "Select File by DF Name (AID)"},
            # Read/Write
            "READ_BINARY": {"hex": "00B00000", "desc": "Read Binary from file"},
            "UPDATE_BINARY": {"hex": "00D60000", "desc": "Update Binary data"},
            "READ_RECORD": {"hex": "00B20104", "desc": "Read Record(s)"},
            "UPDATE_RECORD": {"hex": "00DC0104", "desc": "Update Record"},
            # Security
            "GET_CHALLENGE": {"hex": "00840000", "desc": "Get Challenge for authentication"},
            "VERIFY": {"hex": "00200000", "desc": "Verify PIN or security condition"},
            "INTERNAL_AUTHENTICATE": {"hex": "00880000", "desc": "Internal Authenticate (for DDA/SDA)"},
            "EXTERNAL_AUTHENTICATE": {"hex": "00820000", "desc": "External Authenticate"},
            # Data retrieval
            "GET_DATA": {"hex": "00CA0000", "desc": "Get Data Object(s)"},
            "GET_RESPONSE": {"hex": "00C00000", "desc": "Get Response data from card"},
            # Applet management
            "INSTALL_FOR_LOAD": {"hex": "E6E20000", "desc": "Install (for Load)"},
            "LOAD": {"hex": "E8000000", "desc": "Load Application"},
            "INSTALL_FOR_INSTALL": {"hex": "E6E40000", "desc": "Install (for Install and Make Selectable)"},
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
        response_log = f"Simulating terminal '{terminal_type}' | RECV: {response_data}{response_sw}"
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
        log_msg = (f"Simulating DDA and strong encryption for '{base_cap_file}'"
                   f" -> '{encrypted_cap_file}'")
        print(log_msg)
        logging.info(log_msg)
        # Simulate by copying the file and appending a pseudo-signature
        if os.path.exists(base_cap_file):
            with open(base_cap_file, 'rb') as f_in, open(encrypted_cap_file, 'wb') as f_out:
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
        log_msg = f"Starting random emulations on '{cap_file}' for {duration}s."
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
        challenge_apdu = self.emulator.iso_specs["GET_CHALLENGE"]["hex"] + "0008" # Le = 8 bytes
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
                auth_apdu = (f"{self.emulator.iso_specs['INTERNAL_AUTHENTICATE']['hex']}"
                             f"{len(auth_apdu_data)//2:02X}{auth_apdu_data}")

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
            logging.error("Failed to get a challenge. Crypto verification failed.")
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
        logging.info(f"Starting standard issuance simulation for '{cap_file_type}'")
        print(f"\n--- Simulating Standard Card Issuance for {cap_file_type} ---")

        for brand, bin_prefix in self.major_card_bins.items():
            lun = self.generate_lun()
            # Generate a valid PAN with a correct Luhn check digit
            pan_base = f"{bin_prefix}{''.join([str(random.randint(0, 9)) for _ in range(14 - len(bin_prefix))])}"
            pan = self.luhn_generate(pan_base)

            log_msg = f"Issuing {brand} card | BIN: {bin_prefix} | PAN: {pan} | LUN: {lun}"
            print(log_msg)
            logging.info(log_msg)

            # Simulate personalization commands
            personalization_data = f"Cardholder:J.DOE/PAN:{pan}/EXP:2812"
            apdu_data = personalization_data.encode('utf-8').hex()
            apdu = (f"{self.emulator.iso_specs['UPDATE_BINARY']['hex']}"
                    f"0000{len(apdu_data)//2:02X}{apdu_data}") # P1-P2 offset 0000

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
if __name__ == "__main__":
    # Define dummy file and AIDs for testing
    DUMMY_CAP_FILE = "test_applet.cap"
    DUMMY_PKG_AID = "A00000006203010C01"
    DUMMY_APP_AID = "A00000006203010C0101"

    # Create a dummy cap file for functions that check existence
    if not os.path.exists(DUMMY_CAP_FILE):
        with open(DUMMY_CAP_FILE, "w") as f:
            f.write("dummy_cap_content")

    supertouch_tool = GreenwireSuperTouch()
    supertouch_tool.supertouch(DUMMY_CAP_FILE, DUMMY_PKG_AID, DUMMY_APP_AID)

    jcalgtest_tool = GreenwireJCAlgTest()
    jcalgtest_tool.execute_jcalgtest(
        DUMMY_CAP_FILE, DUMMY_PKG_AID, DUMMY_APP_AID
    )

    integration_tool = GreenwireIntegration()
    integration_tool.execute_all_tests(
        DUMMY_CAP_FILE, DUMMY_PKG_AID, DUMMY_APP_AID
    )

    support_table_tool = GreenwireSupportTableIntegration()
    support_table_tool.execute_all_tests(
        DUMMY_CAP_FILE, DUMMY_PKG_AID, DUMMY_APP_AID
    )

    jcop_manager = GreenwireJCOPManager()
    jcop_manager.generate_and_test_caps(
        DUMMY_CAP_FILE, DUMMY_PKG_AID, DUMMY_APP_AID
    )
    cap_info = jcop_manager.dump_cap_info(DUMMY_CAP_FILE)
    print("CAP File Information:", cap_info)

    # Run the new emulator tests
    emulator = GreenwireEmulator()

    # Verify crypto functions before proceeding
    crypto_verifier = GreenwireCrypto(emulator)
    crypto_ok = crypto_verifier.verify_crypto_functions()

    if crypto_ok:
        # Simulate standard card issuance
        issuer = GreenwireCardIssuance(emulator)
        # Simulate for different CAP types
        cap_types = ["standard_emv.cap", "contactless.cap", "dual_interface.cap"]
        for cap_type in cap_types:
            # Create dummy files for simulation
            if not os.path.exists(cap_type):
                with open(cap_type, "w") as f:
                    f.write(f"dummy_content_for_{cap_type}")
            issuer.simulate_standard_issuance(cap_type)

        # Simulate creating an encrypted CAP file only if crypto is OK
        ENCRYPTED_CAP_FILE = "test_applet_encrypted.cap"
        emulator.create_encrypted_cap(DUMMY_CAP_FILE, ENCRYPTED_CAP_FILE)
        # Run emulations on the encrypted file
        emulator.run_random_emulations(ENCRYPTED_CAP_FILE, duration=10)
    else:
        print("\nSkipping issuance and encryption tests due to crypto verification failure.")


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
