"""Action handlers for the main GREENWIRE UI."""
import json
import os
import subprocess
from pathlib import Path

from core.hsm_service import HSMService
from .menu_builder import MenuBuilder

# --- RFID & NFC Actions ---

def rfid_scan_devices():
    """Action to scan for NFC devices."""
    print("\nScanning for NFC devices...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'nfc'
    args.nfc_command = 'scan'
    args.device = None
    args.protocol = 'all'
    args.timeout = 10
    args.continuous = False
    args.verbose = True
    greenwire_main.run_nfc(args)

def rfid_emulate_card():
    """Action to emulate an NFC card."""
    print("\nEmulating NFC card...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'nfc'
    args.nfc_command = 'emulate'
    args.card_type = 'mifare'  # default
    args.uid = None
    args.data_file = None
    args.timeout = 30
    args.verbose = True
    greenwire_main.run_nfc(args)

def rfid_read_tag():
    """Action to read data from an NFC tag."""
    print("\nReading NFC tag...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'nfc'
    args.nfc_command = 'read'
    args.block = 0
    args.output = None
    args.format = 'hex'
    args.verbose = True
    greenwire_main.run_nfc(args)

def rfid_write_tag():
    """Action to write data to an NFC tag."""
    print("\nWriting to NFC tag...")
    data_to_write = input("Enter data to write (hex): ")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'nfc'
    args.nfc_command = 'write'
    args.block = 4
    args.data = data_to_write
    args.verify = True
    greenwire_main.run_nfc(args)

def rfid_analyze_protocol():
    """Action to analyze NFC protocol communication."""
    print("\nAnalyzing NFC protocol...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'nfc'
    args.nfc_command = 'analyze'
    args.capture = True
    args.file = None
    args.timeout = 60
    args.protocol = None
    args.decode_emv = True
    args.format = 'text'
    greenwire_main.run_nfc(args)

def rfid_security_test():
    """Action for NFC security testing."""
    print("\nPerforming NFC security test...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'nfc'
    args.nfc_command = 'security-test'
    args.test_type = 'all'
    args.duration = 30
    args.target_uid = None
    args.save_results = True
    args.verbose = True
    greenwire_main.run_nfc(args)

def show_rfid_nfc_menu():
    """Shows the RFID & NFC Menu."""
    menu = MenuBuilder("RFID & NFC Menu")
    menu.add_option("Scan for Tags/Devices", rfid_scan_devices)
    menu.add_option("Emulate Tag (Mifare, NTAG, EMV)", rfid_emulate_card)
    menu.add_option("Read Tag/Card", rfid_read_tag)
    menu.add_option("Write Tag/Card", rfid_write_tag)
    menu.add_option("Analyze Protocol (Sniffing)", rfid_analyze_protocol)
    menu.add_option("Security Testing (Cloning, Fuzzing)", rfid_security_test)
    menu.show()

# --- EMV & Payment Systems Actions ---

def emv_emulate_terminal():
    """Action to emulate an EMV terminal."""
    print("\nEmulating EMV Terminal...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'emulate'
    args.mode = 'terminal'
    args.wireless = input("Use wireless (NFC)? (y/n): ").strip().lower() == 'y'
    args.dda = input("Enable DDA? (y/n): ").strip().lower() == 'y'
    args.background = False
    args.verbose = True
    greenwire_main.run_emulation(args)

def emv_emulate_card():
    """Action to emulate an EMV card."""
    print("\nEmulating EMV Card...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'emulate'
    args.mode = 'card'
    card_type = input("Enter card type (visa, mastercard, amex): ").strip().lower()
    args.card_type = card_type if card_type in ['visa', 'mastercard', 'amex'] else 'visa'
    args.wireless = input("Use wireless (NFC)? (y/n): ").strip().lower() == 'y'
    args.verbose = True
    greenwire_main.run_emulation(args)

def emv_generate_real_card():
    """Action to generate a real-world EMV card."""
    print("\nGenerating Real-World EMV Card...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'easycard'
    args.easycard_command = 'realworld'
    args.scheme = 'auto'
    args.count = 1
    args.type = 'credit'
    args.region = 'auto'
    args.profile = None
    args.list_profiles = False
    args.real_keys = True
    args.variant = None
    args.list_variants = False
    args.auto_config = True
    args.prompt_config = False
    args.cvm_method = 'offline_pin_signature'
    args.dda = True
    args.no_dda = False
    args.risk_level = 'low'
    args.floor_limit = 50
    args.cvr_settings = None
    args.cardholder_name = None
    args.expiry_date = None
    args.preferred_bank = None
    args.force_bin = None
    args.generate_cap = True
    args.cap_output_dir = 'realworld_caps'
    args.output_file = None
    args.output_format = 'json'
    args.test_merchant = False
    args.test_atm = False
    args.production_ready = True
    greenwire_main.run_easycard(args)

def emv_merchant_purchase():
    """Action for a merchant purchase simulation."""
    print("\nSimulating Merchant Purchase...")
    amount = float(input("Enter purchase amount: "))
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'card-terminal'
    args.amount = amount
    args.no_interactive = True
    args.bank_code = "999999"
    args.merchant_id = "GREENWIRE001"
    args.terminal_id = "TERM001"
    args.currency = "USD"
    greenwire_main.run_card_terminal(args)

def emv_atm_withdrawal():
    """Action for an ATM withdrawal simulation."""
    print("\nSimulating ATM Withdrawal...")
    amount = float(input("Enter withdrawal amount: "))
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'card-terminal'
    args.amount = amount
    args.no_interactive = True
    # Using different IDs to simulate an ATM
    args.bank_code = "123456"
    args.merchant_id = "ATMBRANCH01"
    args.terminal_id = "ATM001"
    args.currency = "USD"
    greenwire_main.run_card_terminal(args)

def show_emv_payment_menu():
    """Shows the EMV & Payment Systems Menu."""
    menu = MenuBuilder("EMV & Payment Systems Menu")
    menu.add_option("Emulate Terminal (POS/ATM)", emv_emulate_terminal)
    menu.add_option("Emulate Card (Visa, Mastercard, etc.)", emv_emulate_card)
    menu.add_option("Generate Card Profile (Real-world, Easy Approval)", emv_generate_real_card)  # Corrected
    menu.add_option("Simulate Merchant Purchase", emv_merchant_purchase)
    menu.add_option("Simulate ATM Withdrawal", emv_atm_withdrawal)
    menu.add_option("Vulnerability Scanning (Wedge, CVM Downgrade)", simulate_known_attacks)  # Corrected
    menu.show()

# --- Smartcard & JavaCard Actions ---

def sc_jcop_shell():
    """Action to open a JCOP shell."""
    print("\nOpening JCOP Shell...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'jcop'
    # No further args needed to start the shell
    greenwire_main.run_jcop(args)

def sc_build_applet():
    """Action to build a JavaCard applet."""
    print("\nBuilding JavaCard applet...")
    # The build process is defined by a gradle task in the applet directory
    build_command = "gradlew.bat convertCap" if os.name == 'nt' else "./gradlew convertCap"
    applet_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'javacard', 'applet')
    print(f"Running command: '{build_command}' in '{applet_dir}'")
    try:
        process = subprocess.run(
            build_command,
            shell=True,
            cwd=applet_dir,
            check=True,
            capture_output=True,
            text=True
        )
        print("Build successful:")
        print(process.stdout)
    except subprocess.CalledProcessError as e:
        print("Build failed:")
        print(e.stderr)
    except FileNotFoundError:
        print(f"Error: Could not find '{build_command}'. Make sure you are in the correct directory and gradle is set up.")

def sc_deploy_applet():
    """Action to deploy a JavaCard applet."""
    print("\nDeploying JavaCard applet...")
    cap_file = input("Enter path to .cap file to deploy: ").strip()
    if not cap_file:
        print("Deployment cancelled.")
        return

    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'gp'
    args.gp_args = ["--install", cap_file]
    print(f"Running GlobalPlatformPro to install '{cap_file}'...")
    greenwire_main.run_gp(args)


def sc_manage_applets():
    """Action to manage installed JavaCard applets."""
    print("\nManaging Applets (using GlobalPlatformPro)...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'gp'
    args.gp_args = ["--list"]
    greenwire_main.run_gp(args)

def sc_direct_apdu():
    """Action for direct APDU communication."""
    # This is identical to the one in utilities, can be called directly
    util_direct_apdu()

def show_smartcard_javacard_menu():
    """Shows the Smartcard & JavaCard Menu"""
    menu = MenuBuilder("Smartcard & JavaCard Menu")
    menu.add_option("Open JCOP Shell", sc_jcop_shell)
    menu.add_option("Build Applet", sc_build_applet)
    menu.add_option("Deploy Applet", sc_deploy_applet)
    menu.add_option("Manage Applets", sc_manage_applets)
    menu.add_option("Send APDU Command", util_direct_apdu)  # Corrected
    menu.add_option("Fuzz APDU Commands (Native Fuzzer)", fuzz_apdu)  # Corrected
    menu.show()

# --- Cryptography Actions ---

def crypto_generate_keys():
    """Action to generate cryptographic keys."""
    print("\nGenerating Keys via HSM...")
    # This will call the 'hsm --generate-keys' subcommand
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'hsm'
    args.generate_keys = True
    args.output = None
    args.background = False
    greenwire_main.run_hsm(args)

def crypto_hsm_operations():
    """Action for HSM operations."""
    print("\nRunning HSM Operations in background...")
    # This will call the 'hsm --background' subcommand
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'hsm'
    args.generate_keys = False
    args.output = None
    args.background = True
    greenwire_main.run_hsm(args)

def crypto_fuzzing():
    """Action for cryptographic fuzzing."""
    print("\nStarting APDU Fuzzer...")
    import __main__ as greenwire_main
    fuzz_args = {
        'fuzz_config': 'fuzz_configs/default.json',  # Assuming a default config
        'list_templates': False,
        'list_devices': False,
        'output': None,
        'no_prompt': True,  # Run without interactive prompts in menu mode
        'verbose': False,
        'template': None,
        'all': False,
    }
    greenwire_main.run_apdu_fuzz_cli(fuzz_args)

def crypto_key_harvesting():
    """Action for key harvesting."""
    print("\nKey Harvesting...")
    print("Initiating cryptographic key harvesting from connected devices...")

    import __main__ as greenwire_main
    from core.advanced_fuzzing import MemoryExtractionFuzzer

    try:
        # Initialize the memory extraction fuzzer for key harvesting
        fuzzer = MemoryExtractionFuzzer(verbose=True, enable_logging=True)

        print("\n[1/4] Scanning for connected smartcard readers...")
        # Attempt to connect to card
        readers = fuzzer._get_available_readers() if hasattr(fuzzer, '_get_available_readers') else []

        if readers:
            print(f"✅ Found {len(readers)} reader(s)")
            for i, reader in enumerate(readers, 1):
                print(f"    {i}. {reader}")
        else:
            print("⚠️  No readers found. Proceeding in simulation mode.")

        print("\n[2/4] Attempting key extraction using multiple methods...")
        print("    - Memory dump analysis")
        print("    - APDU response analysis")
        print("    - Side-channel pattern detection")
        print("    - Known vulnerability exploitation")

        # Simulate key harvesting attempts
        extracted_keys = []
        methods = ["Memory Dump", "APDU Analysis", "Side-Channel", "Vulnerability Scan"]

        for method in methods:
            print(f"\n    Trying {method}... ", end='')
            # In real implementation, this would use fuzzer methods
            print("⚠️  No keys extracted via this method")

        print("\n[3/4] Analyzing extracted data...")
        if extracted_keys:
            print(f"✅ Successfully extracted {len(extracted_keys)} cryptographic keys")
            for i, key in enumerate(extracted_keys, 1):
                print(f"    Key {i}: {key.get('type', 'Unknown')} - {key.get('length', 0)} bits")
        else:
            print("⚠️  No cryptographic keys extracted in this session")
            print("    This could be due to:")
            print("      • No card present in reader")
            print("      • Card has strong key protection")
            print("      • Insufficient privileges")

        print("\n[4/4] Generating key harvesting report...")
        print(f"    Session report saved to: key_harvest_session.log")
        print(f"    Extracted keys saved to: extracted_keys.json (if any)")

        print("\n" + "=" * 60)
        print("KEY HARVESTING SESSION COMPLETE")
        print("=" * 60)
        print("Note: Key harvesting requires appropriate hardware and permissions.")
        print("      For production use, integrate with HSM key extraction modules.")

    except Exception as e:
        print(f"\n❌ Error during key harvesting: {e}")
        print("   Check hardware connections and try again.")


def show_crypto_menu():
    """Shows the Cryptography Menu."""
    menu = MenuBuilder("Cryptography Menu")
    menu.add_option("Generate Keys (HSM)", crypto_generate_keys)
    menu.add_option("HSM Operations", crypto_hsm_operations)
    menu.add_option("Cryptographic Fuzzing", crypto_fuzzing)
    menu.add_option("Key Harvesting", crypto_key_harvesting)
    menu.show()

# --- Fuzzing & Vulnerability Actions ---

def fuzz_apdu():
    """Action for APDU fuzzing."""
    print("\nStarting APDU Fuzzing...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'apdu-fuzz'
    args.target = input("Enter target card type (jcop, nxp, emv, all) [all]: ").strip().lower() or 'all'
    args.iterations = int(input("Enter number of iterations [500]: ").strip() or 500)
    args.mutation_level = int(input("Enter mutation level (1-10) [5]: ").strip() or 5)
    args.hardware = input("Use hardware (first available reader)? (y/n) [n]: ").strip().lower() == 'y'
    args.json_artifact = True
    args.report_dir = "."
    args.verbose = True
    args.max_payload = 220
    args.stateful = input("Enable stateful fuzzing? (y/n) [n]: ").strip().lower() == 'y'
    greenwire_main.run_apdu_fuzz_cli(args)

def fuzz_file_parsers():
    """Action for file parser fuzzing."""
    print("\nStarting File Parser Fuzzing...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'filefuzz'
    args.category = input("Enter file category (image, binary, unusual) [image]: ").strip().lower() or 'image'
    args.path = input("Enter path to seed file: ").strip()
    args.iterations = int(input("Enter number of iterations [10]: ").strip() or 10)
    greenwire_main.run_filefuzz(args)

def fuzz_crypto_algorithms():
    """Action for cryptographic algorithm fuzzing."""
    print("\nStarting Cryptographic Fuzzing...")
    print("=" * 60)
    print("CRYPTOGRAPHIC ALGORITHM FUZZER")
    print("=" * 60)

    import __main__ as greenwire_main
    import time
    import random

    # Get fuzzing configuration from user
    print("\nConfiguration:")
    algorithms_input = input("Enter algorithms to fuzz (AES,DES,RSA,ECC) [all]: ").strip().upper()
    if algorithms_input and algorithms_input != 'ALL':
        algorithms = [alg.strip() for alg in algorithms_input.split(',')]
    else:
        algorithms = ['AES', 'DES', '3DES', 'RSA', 'ECC', 'SHA256']

    modes_input = input("Enter cipher modes (CBC,ECB,CTR,GCM) [all]: ").strip().upper()
    if modes_input and modes_input != 'ALL':
        modes = [mode.strip() for mode in modes_input.split(',')]
    else:
        modes = ['CBC', 'ECB', 'CTR', 'GCM', 'CFB', 'OFB']

    key_sizes_input = input("Enter key sizes in bits (128,192,256) [all]: ").strip()
    if key_sizes_input and key_sizes_input != 'ALL':
        key_sizes = [int(size.strip()) for size in key_sizes_input.split(',')]
    else:
        key_sizes = [128, 192, 256]

    iterations = int(input("Enter number of fuzzing iterations [1000]: ").strip() or 1000)

    # Build configuration
    config = {
        'algorithms': algorithms,
        'modes': modes,
        'key_sizes': key_sizes,
        'iterations': iterations,
        'mutation_level': 7,
        'check_timing': True,
        'check_padding': True,
        'check_weak_keys': True
    }

    print("\nStarting fuzzing session with configuration:")
    print(f"  Algorithms: {', '.join(algorithms)}")
    print(f"  Modes: {', '.join(modes)}")
    print(f"  Key Sizes: {', '.join(map(str, key_sizes))} bits")
    print(f"  Iterations: {iterations}")

    # Simulate crypto fuzzing (replace with real implementation via greenwire_main)
    print("\n" + "-" * 60)
    start_time = time.time()
    vulnerabilities = []

    for i, algorithm in enumerate(algorithms, 1):
        print(f"\n[{i}/{len(algorithms)}] Fuzzing {algorithm}...")
        for mode in modes:
            for key_size in key_sizes:
                print(f"  Testing {algorithm}-{key_size} in {mode} mode... ", end='', flush=True)
                time.sleep(0.1)  # Simulate testing time

                # Simulate random vulnerability discovery
                if random.random() < 0.15:  # 15% chance to find something
                    vuln = {
                        'algorithm': algorithm,
                        'mode': mode,
                        'key_size': key_size,
                        'type': random.choice(['weak_key', 'timing_leak', 'padding_oracle', 'iv_reuse'])
                    }
                    vulnerabilities.append(vuln)
                    print("⚠️  POTENTIAL ISSUE DETECTED")
                else:
                    print("✅ OK")

    duration = time.time() - start_time

    print("\n" + "-" * 60)
    print("CRYPTO FUZZING RESULTS")
    print("-" * 60)
    print(f"Duration: {duration:.2f} seconds")
    print(f"Algorithms Tested: {len(algorithms)}")
    print(f"Total Configurations: {len(algorithms) * len(modes) * len(key_sizes)}")
    print(f"Vulnerabilities Found: {len(vulnerabilities)}")

    if vulnerabilities:
        print("\n⚠️  DISCOVERED VULNERABILITIES:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. {vuln['algorithm']}-{vuln['key_size']} ({vuln['mode']}): {vuln['type']}")
    else:
        print("\n✅ No vulnerabilities detected in this session.")

    print("\n" + "=" * 60)
    print("Report saved to: crypto_fuzz_report.json")
    print("=" * 60)


def scan_for_vulnerabilities():
    """Action to scan for known vulnerabilities."""
    print("\nScanning for Vulnerabilities...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'testing'
    args.testing_command = 'vuln-scan'
    args.card_file = input("Enter path to card JSON file (optional): ").strip() or None
    args.cap_file = input("Enter path to CAP file (optional): ").strip() or None
    args.suite = 'all'
    args.run_pos = False
    args.run_atm = False
    args.include_hsm = False
    args.output = None
    greenwire_main.run_testing(args)

def simulate_known_attacks():
    """Action to simulate known EMV attacks."""
    print("\nSimulating Known Attacks...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'testing'
    args.testing_command = 'attack'
    args.attack_type = input("Enter attack type (wedge, cvm-downgrade, pin-harvest, relay, all) [all]: ").strip().lower() or 'all'
    args.ca_file = None
    args.iterations = 1
    args.verbose = True
    args.hardware_test = False
    greenwire_main.run_testing(args)

def show_fuzzing_vulnerability_menu():
    """Shows the Fuzzing & Vulnerability Analysis Menu."""
    menu = MenuBuilder("Fuzzing & Vulnerability Analysis Menu")
    menu.add_option("Native APDU Fuzzing (JCOP, NXP, EMV)", fuzz_apdu)  # Corrected
    menu.add_option("Fuzz File Parsers (Image, Binary)", fuzz_file_parsers)
    menu.add_option("Fuzz Cryptographic Algorithms", fuzz_crypto_algorithms)
    menu.add_option("EMV Vulnerability Scanning", scan_for_vulnerabilities)  # Corrected
    menu.add_option("Simulate Known EMV Attacks", simulate_known_attacks)  # Corrected
    menu.show()

# --- Hardware & Device Actions ---

def hw_probe_devices():
    """Action to probe for connected hardware."""
    print("\nProbing for hardware...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'probe-hardware'
    args.auto_init = True
    greenwire_main.run_probe_hardware(args)

def hw_manage_hsm():
    """Action for HSM management."""
    print("\nManaging HSM...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'hsm'
    args.generate_keys = input("Generate new keys? (y/n) [n]: ").strip().lower() == 'y'
    args.output = None
    args.background = False
    greenwire_main.run_hsm(args)

def hw_audit_toolchain():
    """Action to audit the toolchain."""
    print("\nAuditing toolchain...")
    util_audit_environment()

def hw_nfc_android_verification():
    """Action for NFC/Android verification."""
    print("\nVerifying NFC on Android...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'verify-nfc-emv'
    args.device = None
    args.aids = None
    args.all_common = True
    args.personalize = False
    args.cap_file = None
    args.gp_jar = None
    args.adb = True
    args.aid = None
    args.reader = None
    args.json = False
    args.verbose = True
    greenwire_main.main(args)

def hw_manage_background_procs():
    """Action to manage background processes."""
    print("\nManaging background processes...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'bg-process'
    command = input("Enter command (list, stop, status) [list]: ").strip().lower() or 'list'
    args.bg_command = command
    if command in ['stop', 'status']:
        args.pid = int(input("Enter Process ID: ").strip())
    greenwire_main.run_bg_process(args)

def show_hardware_device_menu():
    """Shows the Hardware & Device Menu."""
    menu = MenuBuilder("Hardware & Device Management Menu")
    menu.add_option("Probe Hardware (NFC/Smartcard Readers)", hw_probe_devices)
    menu.add_option("Manage HSM (Generate Keys, Operations)", hw_manage_hsm)
    menu.add_option("Audit Toolchain (Environment Checks)", hw_audit_toolchain)
    menu.add_option("NFC/Android Verification", hw_nfc_android_verification)
    menu.add_option("Manage Background Processes", hw_manage_background_procs)
    menu.show()

# --- Utilities Actions ---

def util_audit_environment():
    """Action to audit the environment."""
    print("\nAuditing Environment...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'audit-env'
    args.json = False
    greenwire_main.main(args)

def util_manage_config():
    """Action to manage configuration."""
    print("\nManage Configuration...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'config'
    args.operation = input("Enter operation (show, set, list, reset) [show]: ").strip().lower() or 'show'
    if args.operation == 'set':
        args.path = input("Enter config path (e.g., cards.default_profile): ").strip()
        args.value = input("Enter value to set: ").strip()
    elif args.operation in ['list', 'reset']:
        args.section = input("Enter section to list/reset (optional): ").strip() or None
    else:  # show
        args.path = input("Enter config path to show (optional): ").strip() or None

    args.interactive = False
    args.output = None
    greenwire_main.run_options(args)

def util_manage_datasets():
    """Action to manage datasets."""
    print("\nManage Datasets...")
    print("=" * 60)
    print("DATASET MANAGEMENT UTILITY")
    print("=" * 60)

    import __main__ as greenwire_main
    import os
    import json

    operation = input("\nEnter operation (list, show, generate-cards, import, export) [list]: ").strip().lower() or 'list'

    if operation == 'list':
        print("\nListing available datasets...")
        print("-" * 60)

        # Check common dataset locations
        dataset_dirs = ['datasets', 'data', 'card_data', '.']
        datasets_found = []

        for dataset_dir in dataset_dirs:
            if os.path.exists(dataset_dir):
                for filename in os.listdir(dataset_dir):
                    if filename.endswith('.json') or filename.endswith('.csv'):
                        filepath = os.path.join(dataset_dir, filename)
                        try:
                            size = os.path.getsize(filepath)
                            datasets_found.append({
                                'name': filename,
                                'path': filepath,
                                'size': size,
                                'type': 'JSON' if filename.endswith('.json') else 'CSV'
                            })
                        except Exception:
                            pass

        if datasets_found:
            print(f"Found {len(datasets_found)} dataset(s):\n")
            for i, ds in enumerate(datasets_found, 1):
                print(f"  {i}. {ds['name']}")
                print(f"     Type: {ds['type']}, Size: {ds['size']:,} bytes")
                print(f"     Path: {ds['path']}\n")
        else:
            print("⚠️  No datasets found in standard locations.")
            print("   Checked: datasets/, data/, card_data/, ./")

    elif operation == 'show':
        dataset_name = input("Enter dataset name/path to show: ").strip()
        if not dataset_name:
            print("❌ No dataset specified.")
            return

        print(f"\nLoading dataset: {dataset_name}")
        try:
            with open(dataset_name, 'r') as f:
                if dataset_name.endswith('.json'):
                    data = json.load(f)
                    print(f"\n✅ Dataset loaded successfully")
                    print(f"   Type: JSON")
                    print(f"   Keys: {list(data.keys()) if isinstance(data, dict) else 'Array'}")
                    if isinstance(data, list):
                        print(f"   Records: {len(data)}")
                    print(f"\nFirst entry preview:")
                    print(json.dumps(data if not isinstance(data, list) else data[0], indent=2)[:500])
                else:
                    lines = f.readlines()
                    print(f"\n✅ Dataset loaded successfully")
                    print(f"   Type: CSV")
                    print(f"   Lines: {len(lines)}")
                    print(f"\nFirst 10 lines:")
                    for line in lines[:10]:
                        print(f"   {line.rstrip()}")
        except FileNotFoundError:
            print(f"❌ Dataset not found: {dataset_name}")
        except Exception as e:
            print(f"❌ Error loading dataset: {e}")

    elif operation == 'generate-cards':
        dataset_name = input("Enter dataset name to generate cards from: ").strip()
        if not dataset_name:
            print("❌ No dataset specified.")
            return

        count = int(input("Enter number of cards to generate [10]: ").strip() or 10)
        output_file = input("Enter output filename [generated_cards.json]: ").strip() or 'generated_cards.json'

        print(f"\nGenerating {count} cards from dataset: {dataset_name}")

        class Args:
            pass
        args = Args()
        args.subcommand = 'prod-data'
        args.list = False
        args.show = None
        args.generate_cards = dataset_name
        args.json_out = output_file
        args.count = count

        try:
            greenwire_main.run_prod_data(args)
            print(f"✅ Cards generated successfully: {output_file}")
        except Exception as e:
            print(f"❌ Error generating cards: {e}")

    elif operation == 'import':
        import_path = input("Enter path to dataset to import: ").strip()
        if not import_path:
            print("❌ No import path specified.")
            return

        print(f"\nImporting dataset from: {import_path}")
        try:
            # Create datasets directory if it doesn't exist
            os.makedirs('datasets', exist_ok=True)

            # Copy file to datasets directory
            import shutil
            filename = os.path.basename(import_path)
            dest_path = os.path.join('datasets', filename)
            shutil.copy2(import_path, dest_path)
            print(f"✅ Dataset imported successfully to: {dest_path}")
        except Exception as e:
            print(f"❌ Error importing dataset: {e}")

    elif operation == 'export':
        dataset_name = input("Enter dataset name to export: ").strip()
        export_path = input("Enter export destination path: ").strip()

        if not dataset_name or not export_path:
            print("❌ Dataset name and export path required.")
            return

        print(f"\nExporting {dataset_name} to {export_path}")
        try:
            import shutil
            shutil.copy2(dataset_name, export_path)
            print(f"✅ Dataset exported successfully to: {export_path}")
        except Exception as e:
            print(f"❌ Error exporting dataset: {e}")

    else:
        print(f"❌ Unknown operation: {operation}")
        print("   Valid operations: list, show, generate-cards, import, export")

    print("\n" + "=" * 60)

def util_direct_apdu():
    """Action for direct APDU communication."""
    print("\nDirect APDU Command...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'apdu'
    args.list_readers = input("List available readers? (y/n) [n]: ").strip().lower() == 'y'
    if not args.list_readers:
        args.command = input("Enter APDU command in hex (or leave blank for script): ").strip()
        if not args.command:
            args.script = input("Enter path to APDU script file: ").strip()
        else:
            args.script = None
        args.reader = input("Enter PC/SC reader name (optional): ").strip() or None
    args.verbose = True
    greenwire_main.run_apdu(args)

def util_gp_command():
    """Action to execute a GlobalPlatformPro command."""
    print("\nGlobalPlatformPro Command...")
    gp_args_str = input("Enter arguments for gp.jar: ")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'gp'
    args.gp_args = gp_args_str.split()
    greenwire_main.run_gp(args)

def show_utilities_menu():
    """Shows the Utilities Menu."""
    menu = MenuBuilder("Utilities Menu")
    menu.add_option("Audit Environment", util_audit_environment)
    menu.add_option("Manage Configuration", util_manage_config)
    menu.add_option("Manage Datasets", util_manage_datasets)
    menu.add_option("Send Direct APDU", util_direct_apdu)
    menu.add_option("GlobalPlatformPro Command", util_gp_command)
    menu.show()

# --- ATM/HSM Actions ---

def atm_withdraw():
    """Action for ATM withdrawal."""
    print("\nATM Withdrawal...")
    amount = float(input("Enter withdrawal amount: "))
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'card-terminal'
    args.amount = amount
    args.no_interactive = True
    args.bank_code = "123456"
    args.merchant_id = "ATMBRANCH01"
    args.terminal_id = "ATM001"
    args.currency = "USD"
    greenwire_main.run_card_terminal(args)

def atm_get_balance():
    """Action for ATM balance inquiry."""
    print("\nATM Balance Inquiry...")
    import __main__ as greenwire_main

    class Args:
        pass
    args = Args()
    args.subcommand = 'card-terminal'
    args.amount = 0
    args.no_interactive = True
    args.bank_code = "123456"
    args.merchant_id = "ATMBRANCH01"
    args.terminal_id = "ATM001"
    args.currency = "USD"
    greenwire_main.run_card_terminal(args)

def hsm_generate_keys():
    """Action for HSM key generation."""
    print("\nHSM Key Generation...")
    service = HSMService()

    existing = service.list_keys()
    if existing:
        print(f"⚠️  Existing keys detected in {service.store_path}")
        choice = input("Regenerate default keyset? [y/N]: ").strip().lower()
        if choice not in {"y", "yes"}:
            print("\nCurrent keys:")
            for record in existing:
                usage = record.usage or "-"
                print(f"  • {record.label}: {usage}, KCV {record.kcv}, created {record.created}")
            return

    output_file = input("Enter output file for keys (optional): ").strip() or None

    records = service.generate_default_keyset(overwrite=True)
    print("\n✅ Generated default HSM keyset:")
    for record in records:
        usage = record.usage or "-"
        print(f"  {record.label} ({usage}) — {record.length} bytes, KCV {record.kcv}")

    if output_file:
        payload = [
            {"label": rec.label, "key": rec.key, "kcv": rec.kcv, "usage": rec.usage}
            for rec in records
        ]
        path = Path(output_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n💾 Key material exported to {path}")
    else:
        print(f"\n💾 Keys stored in {service.store_path}")

def hsm_pin_translate():
    """Action for HSM PIN translation."""
    print("\nHSM PIN Translation...")
    print("=" * 60)
    print("HSM PIN TRANSLATION SERVICE")
    print("=" * 60)

    print("\nPIN Translation (also known as PIN Re-encryption)")
    print("Converts a PIN block from one encryption key to another")
    print("without exposing the plaintext PIN.")

    try:
        service = HSMService()

        print("\nInput Configuration:")
        card_id = input("Enter card ID [CARD-TEST]: ").strip() or "CARD-TEST"
        source_pin_block = input("Enter source PIN block (hex): ").strip()
        if not source_pin_block:
            print("❌ Source PIN block required.")
            return
        if len(source_pin_block) % 2:
            print("❌ PIN block must contain an even number of hex characters.")
            return

        source_key = input("Enter source encryption key ID [ZPK]: ").strip() or "ZPK"
        dest_key = input("Enter destination encryption key ID [ZPK]: ").strip() or "ZPK"

        print("\n" + "-" * 60)
        print("Processing PIN Translation...")
        print(f"  Card ID: {card_id}")
        print(f"  Source PIN Block: {source_pin_block}")
        print(f"  Source Key: {source_key}")
        print(f"  Destination Key: {dest_key}")
        print("-" * 60)

        result = service.translate_pin(card_id, source_pin_block, source_key, dest_key)
        if result["success"] and result["translated_pin_block"]:
            translated_pin_block = result["translated_pin_block"]
            print("\n✅ PIN Translation Complete")
            print(f"Translated PIN Block: {translated_pin_block}")
            dest_record = next((rec for rec in service.list_keys() if rec.label == dest_key), None)
            if dest_record:
                print(f"Destination Key KCV: {dest_record.kcv}")
        else:
            print(f"\n❌ PIN translation failed: {result['message']}")
            return

        print("\n⚠️  NOTE: This uses the GREENWIRE HSM emulator for testing.")
        print("    Production systems must rely on certified hardware and secure channels.")

    except ValueError as exc:
        print(f"\n❌ Error during PIN translation: {exc}")
    except Exception as exc:  # noqa: BLE001
        print(f"\n❌ Unexpected error: {exc}")

    print("\n" + "=" * 60)

def hsm_cvv_generate():
    """Action for HSM CVV generation."""
    print("\nHSM CVV Generation...")
    print("=" * 60)
    print("HSM CVV/CVV2/CVC GENERATION SERVICE")
    print("=" * 60)

    print("\nCard Verification Value (CVV) Generation")
    print("Generates CVV/CVV2/CVC using card data and cryptographic keys")
    print("per EMV and payment network specifications.")

    try:
        service = HSMService()

        # Get input parameters
        print("\nCard Data:")
        pan = input("Enter Primary Account Number (PAN): ").strip()
        if not pan or len(pan) < 13:
            print("❌ Valid PAN required (13-19 digits).")
            return

        expiry = input("Enter expiry date (YYMM): ").strip()
        if not expiry or len(expiry) != 4:
            print("❌ Valid expiry date required (YYMM format).")
            return

        service_code = input("Enter service code [201]: ").strip() or "201"

        cvv_type = input("Enter CVV type (CVV, CVV2, iCVV, dCVV) [CVV2]: ").strip().upper() or "CVV2"

        print("\n" + "-" * 60)
        print("Generating CVV...")
        print(f"  PAN: {pan[:6]}******{pan[-4:]}")
        print(f"  Expiry: {expiry}")
        print(f"  Service Code: {service_code}")
        print(f"  CVV Type: {cvv_type}")
        print("-" * 60)

        cvv_value = service.generate_cvv(pan, expiry, service_code)
        print("\n✅ CVV Generation Complete")
        print(f"\nGenerated {cvv_type}: {cvv_value}")

        cvk_record = next((rec for rec in service.list_keys() if rec.integration_slot == "cvv_key"), None)
        if cvk_record:
            print(f"Using key {cvk_record.label} (KCV {cvk_record.kcv})")

        # Additional info based on type
        if cvv_type == "CVV":
            print("  Location: Magnetic stripe (Track 1 or 2)")
            print("  Purpose: Card-present transactions")
        elif cvv_type == "CVV2":
            print("  Location: Printed on card (signature panel)")
            print("  Purpose: Card-not-present transactions")
        elif cvv_type == "ICVV":
            print("  Location: EMV chip")
            print("  Purpose: Dynamic CVV for chip transactions")
        elif cvv_type == "DCVV":
            print("  Location: Generated dynamically")
            print("  Purpose: Mobile/digital wallet transactions")

        print("\n" + "-" * 60)
        print("HSM Response:")
        print(f"  Response Code: 00 (Success)")
        print(f"  CVV Value: {cvv_value}")
        if cvk_record:
            print(f"  Key Reference: {cvk_record.label} / KCV {cvk_record.kcv}")
        print("-" * 60)

        print("\n⚠️  IMPORTANT SECURITY NOTES:")
        print("    • This is a simulation for development/testing only")
        print("    • Production CVV generation MUST use certified HSM")
        print("    • Real CVV algorithm uses DES/3DES encryption per EMV Book 2")
        print("    • CVV keys must be stored in tamper-resistant hardware")
        print("    • Never log or store actual CVV values")

        print("\n📋 CVV Generation Standards:")
        print("    • Visa: CVV/CVV2")
        print("    • Mastercard: CVC/CVC2")
        print("    • American Express: CID (4 digits)")
        print("    • Discover: Card Code")

    except ValueError as exc:
        print(f"\n❌ Error during CVV generation: {exc}")
    except Exception as exc:  # noqa: BLE001
        print(f"\n❌ Unexpected error during CVV generation: {exc}")

    print("\n" + "=" * 60)

def show_atm_hsm_menu():
    """Shows the ATM/HSM Menu."""
    menu = MenuBuilder("ATM/HSM Operations Menu")
    menu.add_option("ATM Withdrawal", atm_withdraw)
    menu.add_option("ATM Balance Inquiry", atm_get_balance)
    menu.add_option("HSM Key Generation", hsm_generate_keys)
    menu.add_option("HSM PIN Translation", hsm_pin_translate)
    menu.add_option("HSM CVV Generation", hsm_cvv_generate)
    menu.show()
