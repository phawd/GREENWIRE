"""
GREENWIRE Argument Parser
Handles all CLI argument parsing and subcommand definitions.
"""

import argparse
from typing import Any
from core.logging_system import get_logger

def create_argument_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with all subcommands."""
    
    logger = get_logger()
    
    parser = argparse.ArgumentParser(
        description="GREENWIRE - EMV/NFC/JavaCard Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python greenwire.py testing fuzz --hardware
  python greenwire.py easycard generate random --count 5
  python greenwire.py emulator --profile nfc --hardware
  python greenwire.py install-cap myapplet.cap
        """
    )
    
    # Global arguments
    parser.add_argument("--version", action="version", version="GREENWIRE 2.0")
    parser.add_argument("--production", action="store_true", 
                       help="Run in production mode (reduced logging)")
    parser.add_argument("--menu", action="store_true", 
                       help="Launch interactive menu interface")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose output")
    parser.add_argument("--config", type=str, 
                       help="Path to configuration file")
    
    # Create subparsers
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Testing subcommand
    _add_testing_parser(subparsers)
    
    # EasyCard subcommand  
    _add_easycard_parser(subparsers)
    
    # Emulation subcommand
    _add_emulation_parser(subparsers)
    
    # NFC subcommand
    _add_nfc_parser(subparsers)
    
    # APDU subcommand
    _add_apdu_parser(subparsers)
    
    # FIDO subcommand
    _add_fido_parser(subparsers)
    
    # GlobalPlatform subcommand
    _add_gp_parser(subparsers)
    
    # CAP installation
    _add_install_cap_parser(subparsers)
    
    # Log analysis
    _add_log_analysis_parser(subparsers)
    
    # Crypto operations
    _add_crypto_parser(subparsers)
    
    # Probe hardware
    _add_probe_hardware_parser(subparsers)
    
    return parser

def _add_testing_parser(subparsers):
    """Add testing subcommand and its options."""
    testing = subparsers.add_parser("testing", help="Security testing operations")
    testing_sub = testing.add_subparsers(dest="testing_command", required=True)
    
    # Fuzzing
    fuzz = testing_sub.add_parser("fuzz", help="APDU fuzzing operations")
    fuzz.add_argument("--target", choices=["emv", "mifare", "desfire", "auto"], 
                     default="auto", help="Target card type")
    fuzz.add_argument("--iterations", type=int, default=1000, 
                     help="Number of fuzzing iterations")
    fuzz.add_argument("--mutation-level", type=int, choices=range(1, 11), default=5,
                     help="Mutation intensity (1-10)")
    fuzz.add_argument("--hardware", action="store_true", 
                     help="Use hardware reader instead of emulation")
    fuzz.add_argument("--reader", type=str, help="Specific PC/SC reader name")
    fuzz.add_argument("--output", type=str, help="Output file for results")
    fuzz.add_argument("--seed", type=int, help="Random seed for reproducibility")
    
    # Dump operations
    dump = testing_sub.add_parser("dump", help="Card data dumping")
    dump.add_argument("--format", choices=["json", "hex", "tlv"], default="json",
                     help="Output format")
    dump.add_argument("--hardware", action="store_true", help="Use hardware reader")
    dump.add_argument("--reader", type=str, help="Specific PC/SC reader name")
    dump.add_argument("--output", type=str, help="Output file")
    
    # Attack operations
    attack = testing_sub.add_parser("attack", help="Execute specific attacks")
    attack.add_argument("attack_type", choices=["replay", "mitm", "downgrade", "timing"],
                       help="Type of attack to execute")
    attack.add_argument("--target", type=str, help="Target card or reader")
    attack.add_argument("--payload", type=str, help="Attack payload file")
    attack.add_argument("--hardware", action="store_true", help="Use hardware reader")
    
    # Auto-detect
    auto_detect = testing_sub.add_parser("auto-detect", help="Auto-detect card type and capabilities")
    auto_detect.add_argument("--hardware", action="store_true", help="Use hardware reader")
    auto_detect.add_argument("--reader", type=str, help="Specific PC/SC reader name")
    auto_detect.add_argument("--verbose", action="store_true", help="Detailed detection output")
    
    # AI vulnerability testing
    ai_vuln = testing_sub.add_parser("ai-vuln", help="AI-powered vulnerability discovery")
    ai_vuln.add_argument("--model", choices=["standard", "advanced", "experimental"], 
                        default="standard", help="AI model to use")
    ai_vuln.add_argument("--iterations", type=int, default=500, help="Number of test iterations")
    ai_vuln.add_argument("--learning", action="store_true", help="Enable learning mode")
    ai_vuln.add_argument("--hardware", action="store_true", help="Use hardware reader")

def _add_easycard_parser(subparsers):
    """Add easycard subcommand and its options."""
    easycard = subparsers.add_parser("easycard", 
                                    help="Easy card operations - CA listing, card generation, and smart card installation")
    easycard_sub = easycard.add_subparsers(dest="easycard_command", required=True)

    # List CA types
    list_ca = easycard_sub.add_parser("list-ca", help="List available Certificate Authority types")

    # Card generation
    generate = easycard_sub.add_parser("generate", help="Generate card numbers or platform standard profiles")
    generate.add_argument("method", choices=["random", "certificate", "manual", "standard"], 
                          help="Generation method")
    generate.add_argument("--count", type=int, default=1, 
                         help="Number of cards to generate")
    generate.add_argument("--prefix", type=str, help="Card number prefix")
    generate.add_argument("--ca-file", type=str, help="CA key JSON file")
    generate.add_argument("--generate-cap", action="store_true", 
                         help="Generate .cap files for functional cards")
    generate.add_argument("--cap-output-dir", type=str, default="generated_caps",
                         help="Output directory for .cap files")
    generate.add_argument("--install-method", choices=["default", "globalplatform", "custom"], 
                         default="default", help="Installation method for applets")
    generate.add_argument("--test-terminal", action="store_true", 
                         help="Test generated cards with local card-terminal")
    generate.add_argument("--standard", type=str, 
                         help="Smartcard platform standard (jcop, desfire, piv, globalplatform)")
    generate.add_argument("--duplicate", type=int, default=1, 
                         help="Duplicate standard profile N times")
    generate.add_argument("--as-json", action="store_true", 
                         help="Emit JSON to stdout for integration")

    # Standards listing
    standards_cmd = easycard_sub.add_parser("standards", 
                                           help="List available smartcard standard profiles")

    # Merchant profile
    merchant_profile = easycard_sub.add_parser("merchant-profile", 
                                              help="Generate merchant processor profile template")
    merchant_profile.add_argument("--format", choices=["json", "text"], default="json")
    merchant_profile.add_argument("--scheme", choices=["visa","mastercard","amex","discover","generic"], 
                                 default="generic")
    merchant_profile.add_argument("--country", default="US")
    merchant_profile.add_argument("--currency", default="USD")

    # Real-world card generation
    realworld = easycard_sub.add_parser("realworld", 
                                       help="Generate real-world usable EMV-compliant cards")
    
    # Basic parameters
    realworld.add_argument("--scheme", choices=["visa", "mastercard", "amex", "auto"], 
                          default="auto", help="Card scheme")
    realworld.add_argument("--count", type=int, default=1, help="Number of cards")
    realworld.add_argument("--type", choices=["credit", "debit", "prepaid"], 
                          default="credit", help="Card type")
    realworld.add_argument("--region", choices=["us", "eu", "asia", "auto"], 
                          default="auto", help="Geographic region")

    # Authentication settings
    auth_group = realworld.add_argument_group("Authentication Settings")
    auth_group.add_argument("--cvm-method", 
                           choices=["offline_pin", "signature", "offline_pin_signature", 
                                   "online_pin", "no_cvm"], 
                           default="offline_pin_signature", help="Cardholder Verification Method")
    auth_group.add_argument("--dda", action="store_true", default=True, 
                           help="Enable Dynamic Data Authentication")
    auth_group.add_argument("--no-dda", action="store_false", dest="dda", 
                           help="Disable Dynamic Data Authentication")

    # Risk parameters
    risk_group = realworld.add_argument_group("Risk Parameters")
    risk_group.add_argument("--risk-level", choices=["very_low", "low", "medium", "high"], 
                           default="very_low", help="Card risk level")
    risk_group.add_argument("--floor-limit", type=int, default=50, 
                           help="Transaction amount floor limit")
    risk_group.add_argument("--cvr-settings", type=str, 
                           help="Custom Card Verification Results settings")

    # Easy approval cards
    easy_approval = easycard_sub.add_parser("easy-approval", 
                                           help="Generate cards designed for easy approval")
    easy_approval.add_argument("--scheme", choices=["visa", "mastercard", "amex"], 
                              default="visa", help="Card scheme")
    easy_approval.add_argument("--count", type=int, default=1, help="Number of cards")
    easy_approval.add_argument("--generate-cap", action="store_true", 
                              help="Generate .cap files")
    easy_approval.add_argument("--test-terminal", action="store_true", 
                              help="Test generated cards")

    # Install card
    install_card = easycard_sub.add_parser("install-card", 
                                          help="Install a card to a smart card using GlobalPlatform")
    install_card.add_argument("--cap-file", type=str, required=True, 
                             help="Path to .cap file to install")
    install_card.add_argument("--cardholder-name", type=str, default="GIFT HOLDER", 
                             help="Cardholder name")
    install_card.add_argument("--reader", type=str, help="PC/SC reader name")
    install_card.add_argument("--aid", type=str, help="Application Identifier (AID)")

def _add_emulation_parser(subparsers):
    """Add emulation subcommand and its options."""
    emulator = subparsers.add_parser("emulator", help="Card/Terminal emulation")
    emulator.add_argument("mode", choices=["card", "terminal"], 
                         help="Emulation mode")
    emulator.add_argument("--profile", choices=["nfc", "pcsc", "android"], 
                         default="nfc", help="Emulation profile")
    emulator.add_argument("--hardware", action="store_true", 
                         help="Use hardware NFC/PC/SC interface")
    emulator.add_argument("--card-type", choices=["visa", "mastercard", "amex", "mifare"], 
                         help="Type of card to emulate")
    emulator.add_argument("--aids", type=str, help="Comma-separated list of AIDs")
    emulator.add_argument("--ca-file", type=str, help="CA certificate file")
    emulator.add_argument("--wireless", action="store_true", help="Enable wireless/NFC mode")
    emulator.add_argument("--background", action="store_true", 
                         help="Run emulation in background")
    emulator.add_argument("--issuer", type=str, help="Issuer identifier")
    emulator.add_argument("--dda", action="store_true", help="Enable DDA support")

def _add_nfc_parser(subparsers):
    """Add NFC subcommand and its options."""
    nfc = subparsers.add_parser("nfc", help="NFC operations")
    nfc.add_argument("operation", choices=["read", "write", "emulate", "scan"], 
                    help="NFC operation to perform")
    nfc.add_argument("--device", type=str, help="NFC device identifier")
    nfc.add_argument("--data", type=str, help="Data to write (hex format)")
    nfc.add_argument("--format", choices=["json", "hex", "text"], default="json",
                    help="Output format")

def _add_apdu_parser(subparsers):
    """Add APDU subcommand and its options."""
    apdu = subparsers.add_parser("apdu", help="Direct APDU communication")
    apdu.add_argument("command", help="APDU command in hex format")
    apdu.add_argument("--reader", type=str, help="PC/SC reader name")
    apdu.add_argument("--format", choices=["hex", "binary"], default="hex",
                     help="Output format")

def _add_fido_parser(subparsers):
    """Add FIDO subcommand and its options."""
    fido = subparsers.add_parser("fido", help="FIDO/WebAuthn operations")
    fido.add_argument("operation", choices=["register", "authenticate", "test"], 
                     help="FIDO operation")
    fido.add_argument("--device", type=str, help="FIDO device path")
    fido.add_argument("--challenge", type=str, help="Challenge data")

def _add_gp_parser(subparsers):
    """Add GlobalPlatform subcommand and its options."""
    gp = subparsers.add_parser("gp", help="Execute GlobalPlatformPro (gp.jar) commands")
    gp.add_argument("--production", action="store_true", 
                   help="Run in production mode")
    gp.add_argument("gp_args", nargs=argparse.REMAINDER, 
                   help="Arguments to pass to gp.jar")

def _add_install_cap_parser(subparsers):
    """Add install-cap subcommand and its options."""
    install_cap = subparsers.add_parser("install-cap", help="Install JavaCard applet (.cap file)")
    install_cap.add_argument("cap_file", help="Path to .cap file")
    install_cap.add_argument("--reader", type=str, help="PC/SC reader name")
    install_cap.add_argument("--android", type=str, help="Android device ID for HCE installation")
    install_cap.add_argument("--aid", type=str, help="Override AID for installation")

def _add_log_analysis_parser(subparsers):
    """Add log analysis subcommand and its options."""
    log_analysis = subparsers.add_parser("log-analysis", help="Analyze log files")
    log_analysis.add_argument("operation", choices=["read", "tlv", "hex", "compare"],
                             help="Analysis operation")
    log_analysis.add_argument("--file", type=str, help="Log file to analyze")
    log_analysis.add_argument("--format", choices=["json", "text", "csv"], default="text",
                             help="Output format")

def _add_crypto_parser(subparsers):
    """Add crypto operations subcommand and its options."""
    crypto = subparsers.add_parser("crypto", help="Cryptographic operations")
    crypto_sub = crypto.add_subparsers(dest="crypto_command", required=True)
    
    # Key management
    key_mgmt = crypto_sub.add_parser("keys", help="Key management operations")
    key_mgmt.add_argument("operation", choices=["harvest", "search", "import", "export"],
                         help="Key operation")
    key_mgmt.add_argument("--source", type=str, help="Key source or file")
    key_mgmt.add_argument("--format", choices=["pem", "der", "json"], default="json",
                         help="Key format")
    
    # CA operations
    ca_ops = crypto_sub.add_parser("ca", help="Certificate Authority operations")
    ca_ops.add_argument("operation", choices=["list", "verify", "import"],
                       help="CA operation")
    ca_ops.add_argument("--cert", type=str, help="Certificate file")

def _add_probe_hardware_parser(subparsers):
    """Add probe-hardware subcommand and its options."""
    probe = subparsers.add_parser("probe-hardware", help="Probe and detect hardware")
    probe.add_argument("--type", choices=["all", "nfc", "pcsc", "android"], default="all",
                      help="Hardware type to probe")
    probe.add_argument("--verbose", action="store_true", help="Detailed hardware info")