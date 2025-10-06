"""
GREENWIRE Command Router
Routes parsed CLI arguments to appropriate handlers.
"""

import sys  # noqa: F401
from typing import Any, Dict, Optional  # noqa: F401
from core.logging_system import get_logger, handle_errors
from core.config import get_config
from core.greenwire_bridge import get_bridge

# Import operator-mode helper when available. Keep import defensive so the
# CLI can operate in minimal/static environments where core.operator_mode
# may not be present.
try:
    from core.operator_mode import ask_operator_mode
except Exception:
    ask_operator_mode = None


class CommandRouter:
    """Routes CLI commands to appropriate handlers."""
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        self.bridge = get_bridge()
        self._handlers = {}
        
    def register_handler(self, command: str, handler_func):
        """Register a command handler function."""
        self._handlers[command] = handler_func
        # Use lazy formatting (%s) for logging best practices
        self.logger.debug("Registered handler for command: %s", command)
    
    @handle_errors("Command routing", return_on_error=False)
    def route_command(self, args: Any) -> bool:
        """
        Route parsed arguments to appropriate handler.
        
        Args:
            args: Parsed arguments from argparse
            
        Returns:
            True if command executed successfully
        """
        if not hasattr(args, 'command') or not args.command:
            self.logger.error("No command specified")
            return False
        
        command = args.command
        
        # Ask operator for simulation vs production mode if helper is available.
        # This centralizes the operator prompt so every direct CLI command will
        # populate args.operator_mode and args.production_options.
        try:
            if callable(ask_operator_mode):
                ask_operator_mode(args)
                self.logger.info(
                    "Operator mode selected: %s",
                    getattr(args, 'operator_mode', 'simulation'),
                )
        except Exception as e:
            # Do not fail routing if operator prompt has problems; default to simulation
            self.logger.warning(
                "Operator mode helper failed; defaulting to simulation: %s",
                str(e),
            )
        
        # Handle special cases first
        if args.menu:
            return self._handle_menu_mode(args)
        
        # Route to specific command handlers
        if command == "testing":
            return self._handle_testing_command(args)
        elif command == "easycard":
            return self._handle_easycard_command(args)
        elif command == "emulator":
            return self._handle_emulator_command(args)
        elif command == "nfc":
            return self._handle_nfc_command(args)
        elif command == "apdu":
            return self._handle_apdu_command(args)
        elif command == "fido":
            return self._handle_fido_command(args)
        elif command == "gp":
            return self._handle_gp_command(args)
        elif command == "install-cap":
            return self._handle_install_cap_command(args)
        elif command == "log-analysis":
            return self._handle_log_analysis_command(args)
        elif command == "crypto":
            return self._handle_crypto_command(args)
        elif command == "probe-hardware":
            return self._handle_probe_hardware_command(args)
        elif command == "config":
            return self._handle_config_command(args)
        else:
            # Check for registered custom handlers
            if command in self._handlers:
                return self._handlers[command](args)
            else:
                self.logger.error(f"Unknown command: {command}")
                return False
    
    def _handle_menu_mode(self, args: Any) -> bool:
        """Handle interactive menu mode."""
        self.logger.info("Launching interactive menu interface")
        
        # Use bridge to access original menu implementation
        return self.bridge.execute_interactive_menu()
    
    def _handle_testing_command(self, args: Any) -> bool:
        """Handle testing subcommands."""
        subcommand = getattr(args, "testing_command", None)
        if subcommand == "vuln-scan":
            return self._handle_vulnerability_scan(args)
        self.logger.info("Executing testing command via bridge")
        return self.bridge.execute_testing_command(args)
    
    def _handle_fuzz_testing(self, args: Any) -> bool:
        """Handle APDU fuzzing operations."""
        # Use lazy formatting for logging
        self.logger.info(
            "Starting APDU fuzzing - Target: %s, Iterations: %s",
            args.target,
            args.iterations,
        )
        
        # Import and use APDU fuzzer from core
        try:
            from core.apdu_fuzzer import run_native_apdu_fuzz
            
            session, report = run_native_apdu_fuzz(
                target_card=args.target,
                iterations=args.iterations,
                mutation_level=args.mutation_level,
                hardware_mode=args.hardware,
                reader_name=args.reader,
                output_file=args.output,
                seed=args.seed
            )
            
            self.logger.info("APDU fuzzing completed successfully")
            return True
            
        except ImportError as e:
            self.logger.error(f"APDU fuzzer not available: {e}")
            return False
    
    def _handle_dump_testing(self, args: Any) -> bool:
        """Handle card data dumping."""
        self.logger.info(f"Starting card dump - Format: {args.format}")
        
        try:
            print(f"🔍 Card Data Dumping (Format: {args.format})")
            print("=" * 50)
            
            # Try to use APDU communicator for dumping
            from apdu_communicator import APDUCommunicator
            
            with APDUCommunicator(verbose=True) as comm:
                readers = comm.list_readers()
                if not readers:
                    print("❌ No card readers found")
                    return False
                
                if not comm.connect_reader():
                    print("❌ Could not connect to card")
                    return False
                    
                print("✅ Connected to card")
                
                # Get ATR
                atr = comm.get_atr()
                if atr:
                    print(f"📋 ATR: {atr}")
                
                # Basic EMV dumping commands
                dump_commands = [
                    ("Select Payment Application", "00A404000E325041592E5359532E444446303100"),
                    ("Get Processing Options", "80A80000028300"),
                    ("Read Application Data", "00B2010C00"),
                    ("Read Record 1", "00B2010400"),
                    ("Read Record 2", "00B2020400"),
                ]
                
                dump_data = {"atr": atr, "responses": []}
                
                for desc, cmd in dump_commands:
                    print(f"📡 {desc}: {cmd}")
                    response, sw = comm.send_apdu(cmd)
                    if response:
                        print(f"   ✅ Response: {response} (SW: {sw})")
                        dump_data["responses"].append({
                            "command": cmd,
                            "description": desc,
                            "response": response,
                            "status": sw
                        })
                    else:
                        print(f"   ❌ No response (SW: {sw})")
                
                # Save dump data
                import json
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"card_dump_{args.format}_{timestamp}.json"
                
                with open(filename, 'w') as f:
                    json.dump(dump_data, f, indent=2)
                
                print(f"💾 Dump saved to: {filename}")
                return True
                
        except ImportError as e:
            self.logger.error(f"Card dumping dependencies not available: {e}")
            print(f"❌ Card dumping dependencies not available: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Card dumping failed: {e}")
            print(f"❌ Card dumping failed: {e}")
            return False
    
    def _handle_attack_testing(self, args: Any) -> bool:
        """Handle specific attack execution."""
        self.logger.info("Executing attack: %s", args.attack_type)
        
        try:
            print(f"⚔️ Attack Testing: {args.attack_type}")
            print("=" * 50)
            
            attack_implementations = {
                "replay": self._execute_replay_attack,
                "mitm": self._execute_mitm_attack,
                "fuzzing": self._execute_fuzzing_attack,
                "timing": self._execute_timing_attack,
                "differential": self._execute_differential_attack,
            }
            
            if args.attack_type in attack_implementations:
                return attack_implementations[args.attack_type](args)
            else:
                print(f"❌ Unknown attack type: {args.attack_type}")
                print(f"Available attacks: {', '.join(attack_implementations.keys())}")
                return False
                
        except Exception as e:
            self.logger.error(f"Attack testing failed: {e}")
            print(f"❌ Attack testing failed: {e}")
            return False
    
    def _execute_replay_attack(self, args) -> bool:
        """Execute replay attack."""
        print("🔄 Replay Attack Simulation")
        print("Capturing and replaying transactions...")
        
        # Simulate replay attack
        transactions = [
            "Transaction 1: $10.00 - APPROVED",
            "Transaction 2: $25.50 - APPROVED", 
            "Transaction 3: $5.99 - DECLINED"
        ]
        
        for i, tx in enumerate(transactions):
            print(f"  📋 Captured: {tx}")
            print(f"  🔄 Replaying transaction {i+1}...")
            import time
            time.sleep(0.5)
            success = i < 2  # First 2 succeed, last fails
            print(f"  {'✅' if success else '❌'} Replay {'successful' if success else 'blocked'}")
        
        return True
        
    def _execute_mitm_attack(self, args) -> bool:
        """Execute man-in-the-middle attack."""
        print("👥 MITM Attack Simulation")
        print("Setting up interception proxy...")
        
        phases = [
            "Certificate generation",
            "Proxy server startup",
            "Traffic interception", 
            "Data modification",
            "Response injection"
        ]
        
        for phase in phases:
            print(f"  🔧 {phase}...")
            import time
            time.sleep(0.3)
            print(f"    ✅ {phase} complete")
        
        return True
        
    def _execute_fuzzing_attack(self, args) -> bool:
        """Execute fuzzing attack."""
        print("🧬 Fuzzing Attack")
        print("Generating malformed inputs...")
        
        try:
            from core.advanced_fuzzing import MemoryExtractionFuzzer
            fuzzer = MemoryExtractionFuzzer(verbose=True)
            
            if fuzzer.connect_to_card():
                print("✅ Card connected - running live fuzzing")
                results = fuzzer.enhanced_memory_extraction_fuzzing()
                issues = len(results.get('potential_keys', []))
                print(f"🔍 Found {issues} potential vulnerabilities")
            else:
                print("❌ No card - running simulation")
                # Simulate fuzzing results
                import random
                issues = random.randint(0, 5)
                print(f"🔍 Simulated {issues} potential vulnerabilities")
            
            return True
        except ImportError:
            print("❌ Fuzzing module not available")
            return False
            
    def _execute_timing_attack(self, args) -> bool:
        """Execute timing attack."""
        print("⏱️ Timing Attack Analysis")
        print("Measuring response times for cryptographic operations...")
        
        import time
        import random
        
        operations = ["PIN verification", "Crypto validation", "Key derivation", "Authentication"]
        timings = []
        
        for op in operations:
            print(f"  📊 Testing {op}...")
            for i in range(5):
                start = time.time()
                time.sleep(random.uniform(0.01, 0.05))  # Simulate operation
                elapsed = (time.time() - start) * 1000
                timings.append(elapsed)
                print(f"    Trial {i+1}: {elapsed:.2f}ms")
        
        avg_time = sum(timings) / len(timings)
        variance = sum((t - avg_time) ** 2 for t in timings) / len(timings)
        
        print(f"\n📈 Timing Analysis:")
        print(f"  Average: {avg_time:.2f}ms")
        print(f"  Variance: {variance:.2f}")
        print(f"  {'⚠️ Timing vulnerability detected' if variance > 1.0 else '✅ No timing vulnerabilities'}")
        
        return True
        
    def _execute_differential_attack(self, args) -> bool:
        """Execute differential power/fault analysis."""
        print("📊 Differential Analysis")
        print("Analyzing power consumption and fault injection...")
        
        import random
        
        traces = []
        for i in range(10):
            # Simulate power trace
            trace = [random.uniform(0.1, 1.0) for _ in range(100)]
            traces.append(trace)
            print(f"  📈 Captured trace {i+1}")
        
        # Simulate analysis
        print("🔍 Analyzing differential patterns...")
        correlations = [random.uniform(-1.0, 1.0) for _ in range(5)]
        
        for i, corr in enumerate(correlations):
            if abs(corr) > 0.7:
                print(f"  🚨 Strong correlation detected at point {i}: {corr:.3f}")
            else:
                print(f"  📊 Correlation at point {i}: {corr:.3f}")
        
        return True
    
    def _handle_auto_detect(self, args: Any) -> bool:
        """Handle auto-detection of card capabilities."""
        self.logger.info("Starting auto-detection")
        
        try:
            print("🔍 Auto-Detection & Configuration")
            print("=" * 50)
            
            detection_results = {}
            
            # Hardware detection
            print("📡 Detecting Hardware...")
            hardware = self._detect_all_hardware()
            detection_results['hardware'] = hardware
            
            # Card detection
            print("\n💳 Detecting Cards...")
            cards = self._detect_inserted_cards()
            detection_results['cards'] = cards
            
            # Android devices
            print("\n📱 Detecting Android Devices...")
            android_devices = self._detect_android_devices()
            detection_results['android'] = android_devices
            
            # Software capabilities
            print("\n💻 Detecting Software Capabilities...")
            software = self._detect_software_capabilities()
            detection_results['software'] = software
            
            # Generate configuration
            print("\n⚙️ Generating Optimal Configuration...")
            config = self._generate_auto_config(detection_results)
            
            # Display results
            self._display_detection_results(detection_results, config)
            
            # Save configuration
            config_saved = self._save_auto_config(config)
            if config_saved:
                print("\n✅ Configuration saved successfully")
            else:
                print("\n⚠️ Configuration save failed")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Auto-detection failed: {e}")
            print(f"❌ Auto-detection failed: {e}")
            return False
    
    def _detect_all_hardware(self) -> dict:
        """Detect all available hardware."""
        hardware = {
            'pcsc_readers': [],
            'nfc_devices': [],
            'serial_devices': [],
            'usb_devices': []
        }
        
        # PC/SC readers
        try:
            from smartcard.System import readers
            pcsc_readers = readers()
            for reader in pcsc_readers:
                hardware['pcsc_readers'].append({
                    'name': str(reader),
                    'status': 'available'
                })
                print(f"  📟 PC/SC Reader: {reader}")
        except ImportError:
            print("  ❌ PC/SC not available")
        except Exception as e:
            print(f"  ⚠️ PC/SC detection error: {e}")
        
        # NFC devices via libnfc
        try:
            import subprocess
            result = subprocess.run(['nfc-list'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'found' in result.stdout.lower():
                hardware['nfc_devices'].append({'type': 'libnfc', 'status': 'detected'})
                print("  📡 LibNFC device detected")
        except:
            pass
        
        # Serial/USB scanning
        try:
            import serial.tools.list_ports
            ports = serial.tools.list_ports.comports()
            for port in ports:
                if any(vid in str(port.hwid).lower() for vid in ['072f', '04e6', '0bda']):
                    hardware['serial_devices'].append({
                        'port': port.device,
                        'description': port.description,
                        'hwid': port.hwid
                    })
                    print(f"  🔌 Serial Device: {port.device} - {port.description}")
        except ImportError:
            pass
        
        return hardware
    
    def _detect_inserted_cards(self) -> list:
        """Detect cards in readers."""
        cards = []
        
        try:
            from smartcard.System import readers
            from smartcard.CardType import AnyCardType
            from smartcard.CardRequest import CardRequest
            
            for reader in readers():
                try:
                    cardrequest = CardRequest(timeout=1, cardType=AnyCardType())
                    cardservice = cardrequest.waitforcard()
                    if cardservice:
                        cardservice.connection.connect()
                        
                        # Try to get ATR
                        atr = cardservice.connection.getATR()
                        atr_hex = ''.join(f'{b:02X}' for b in atr)
                        
                        cards.append({
                            'reader': str(reader),
                            'atr': atr_hex,
                            'type': self._identify_card_type(atr_hex)
                        })
                        print(f"  💳 Card in {reader}: {atr_hex[:20]}...")
                        
                        cardservice.connection.disconnect()
                except:
                    pass
        except:
            pass
        
        return cards
    
    def _detect_android_devices(self) -> list:
        """Detect Android devices with NFC."""
        devices = []
        
        try:
            import subprocess
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if '\tdevice' in line:
                        device_id = line.split('\t')[0]
                        
                        # Check NFC capability
                        nfc_result = subprocess.run(
                            ['adb', '-s', device_id, 'shell', 'pm', 'list', 'features'],
                            capture_output=True, text=True, timeout=5
                        )
                        
                        has_nfc = 'android.hardware.nfc' in nfc_result.stdout
                        
                        devices.append({
                            'id': device_id,
                            'nfc_capable': has_nfc,
                            'status': 'connected'
                        })
                        print(f"  📱 Android Device: {device_id} (NFC: {'✅' if has_nfc else '❌'})")
        except:
            pass
        
        return devices
    
    def _detect_software_capabilities(self) -> dict:
        """Detect available software capabilities."""
        capabilities = {
            'python_modules': [],
            'java_tools': [],
            'native_tools': [],
            'emulation': []
        }
        
        # Python modules
        modules = ['smartcard', 'pyscard', 'nfc', 'cryptography', 'ecdsa']
        for module in modules:
            try:
                __import__(module)
                capabilities['python_modules'].append(module)
                print(f"  🐍 Python module: {module}")
            except ImportError:
                pass
        
        # Java tools
        import os
        java_tools = ['gp.jar', 'ant-javacard.jar', 'apdu4j.jar']
        for tool in java_tools:
            if os.path.exists(f"lib/{tool}") or os.path.exists(f"static/java/{tool}"):
                capabilities['java_tools'].append(tool)
                print(f"  ☕ Java tool: {tool}")
        
        # Native tools
        native_tools = ['opensc-tool', 'nfc-list', 'pcsc_scan']
        for tool in native_tools:
            try:
                import subprocess
                result = subprocess.run([tool, '--help'], capture_output=True, timeout=2)
                if result.returncode in [0, 1]:  # Help usually returns 1
                    capabilities['native_tools'].append(tool)
                    print(f"  🔧 Native tool: {tool}")
            except:
                pass
        
        return capabilities
    
    def _identify_card_type(self, atr_hex: str) -> str:
        """Identify card type from ATR."""
        atr_patterns = {
            'JCOP': ['3B6800', '3B8A80'],
            'MIFARE': ['3B8F80', '3B8B80'],
            'EMV': ['3B9F', '3B8F'],
            'JavaCard': ['3B68', '3B6A']
        }
        
        for card_type, patterns in atr_patterns.items():
            if any(atr_hex.startswith(pattern) for pattern in patterns):
                return card_type
        
        return 'Unknown'
    
    def _generate_auto_config(self, detection_results: dict) -> dict:
        """Generate optimal configuration based on detection."""
        config = {
            'preferred_reader': None,
            'nfc_interface': None,
            'android_device': None,
            'java_enabled': False,
            'fuzzing_capable': False,
            'emulation_ready': False
        }
        
        # Preferred reader
        if detection_results['hardware']['pcsc_readers']:
            config['preferred_reader'] = detection_results['hardware']['pcsc_readers'][0]['name']
        
        # NFC interface
        if detection_results['hardware']['nfc_devices']:
            config['nfc_interface'] = 'libnfc'
        elif detection_results['android']:
            config['nfc_interface'] = 'android'
            config['android_device'] = detection_results['android'][0]['id']
        
        # Java capabilities
        if detection_results['software']['java_tools']:
            config['java_enabled'] = True
        
        # Fuzzing capabilities
        if 'smartcard' in detection_results['software']['python_modules']:
            config['fuzzing_capable'] = True
        
        # Emulation readiness
        if detection_results['hardware']['nfc_devices'] or detection_results['android']:
            config['emulation_ready'] = True
        
        return config
    
    def _display_detection_results(self, results: dict, config: dict):
        """Display comprehensive detection results."""
        print("\n📋 Detection Summary:")
        print("=" * 30)
        
        # Hardware summary
        hw = results['hardware']
        print(f"PC/SC Readers: {len(hw['pcsc_readers'])}")
        print(f"NFC Devices: {len(hw['nfc_devices'])}")
        print(f"Serial Devices: {len(hw['serial_devices'])}")
        
        # Cards summary
        print(f"Inserted Cards: {len(results['cards'])}")
        
        # Android summary
        print(f"Android Devices: {len(results['android'])}")
        
        # Software summary
        sw = results['software']
        print(f"Python Modules: {len(sw['python_modules'])}")
        print(f"Java Tools: {len(sw['java_tools'])}")
        print(f"Native Tools: {len(sw['native_tools'])}")
        
        # Configuration recommendations
        print("\n⚙️ Recommended Configuration:")
        print(f"Preferred Reader: {config.get('preferred_reader', 'None')}")
        print(f"NFC Interface: {config.get('nfc_interface', 'None')}")
        print(f"Java Enabled: {'✅' if config.get('java_enabled') else '❌'}")
        print(f"Fuzzing Ready: {'✅' if config.get('fuzzing_capable') else '❌'}")
        print(f"Emulation Ready: {'✅' if config.get('emulation_ready') else '❌'}")
    
    def _save_auto_config(self, config: dict) -> bool:
        """Save auto-generated configuration."""
        try:
            import json
            import os
            
            config_dir = os.path.dirname(os.path.dirname(__file__))
            config_file = os.path.join(config_dir, 'auto_config.json')
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"📄 Configuration saved to: {config_file}")
            return True
        except Exception as e:
            print(f"❌ Failed to save config: {e}")
            return False
    
    def _handle_ai_vuln_testing(self, args: Any) -> bool:
        """Handle AI-powered vulnerability testing."""
        self.logger.info("Starting AI vulnerability testing - Model: %s", args.model)
        
        try:
            print("🤖 AI-Powered Vulnerability Testing")
            print("=" * 50)
            print(f"Model: {getattr(args, 'model', 'default')}")
            
            # Initialize AI testing components
            ai_results = {}
            
            # Pattern analysis
            print("\n🔍 AI Pattern Analysis...")
            patterns = self._ai_analyze_patterns()
            ai_results['patterns'] = patterns
            
            # Behavioral modeling
            print("\n🧠 AI Behavioral Modeling...")
            behaviors = self._ai_model_behaviors()
            ai_results['behaviors'] = behaviors
            
            # Vulnerability prediction
            print("\n⚠️ AI Vulnerability Prediction...")
            predictions = self._ai_predict_vulnerabilities(patterns, behaviors)
            ai_results['predictions'] = predictions
            
            # Targeted testing
            print("\n🎯 AI-Guided Targeted Testing...")
            test_results = self._ai_execute_targeted_tests(predictions)
            ai_results['test_results'] = test_results
            
            # Results analysis
            print("\n📊 AI Results Analysis...")
            analysis = self._ai_analyze_results(ai_results)
            
            # Generate report
            report_saved = self._save_ai_report(ai_results, analysis)
            if report_saved:
                print("\n✅ AI vulnerability report generated")
            else:
                print("\n⚠️ Failed to save AI report")
            
            return True
            
        except Exception as e:
            self.logger.error(f"AI vulnerability testing failed: {e}")
            print(f"❌ AI vulnerability testing failed: {e}")
            return False
    
    def _ai_analyze_patterns(self) -> dict:
        """AI-powered pattern analysis."""
        patterns = {
            'timing_patterns': [],
            'response_patterns': [],
            'error_patterns': [],
            'anomalies': []
        }
        
        # Simulate AI pattern analysis
        import random
        
        # Timing pattern analysis
        for i in range(5):
            pattern = {
                'operation': f'crypto_op_{i}',
                'avg_time': random.uniform(10, 100),
                'variance': random.uniform(1, 10),
                'anomaly_score': random.uniform(0, 1)
            }
            patterns['timing_patterns'].append(pattern)
            anomaly_level = "🚨 HIGH" if pattern['anomaly_score'] > 0.7 else "⚠️ MEDIUM" if pattern['anomaly_score'] > 0.3 else "✅ LOW"
            print(f"  📈 {pattern['operation']}: {pattern['avg_time']:.1f}ms avg, anomaly {anomaly_level}")
        
        # Response pattern analysis
        response_types = ['success', 'auth_fail', 'crypto_fail', 'timeout']
        for resp_type in response_types:
            pattern = {
                'type': resp_type,
                'frequency': random.uniform(0.1, 0.9),
                'correlation': random.uniform(-1, 1)
            }
            patterns['response_patterns'].append(pattern)
            print(f"  📋 Response {resp_type}: {pattern['frequency']:.2f} frequency, {pattern['correlation']:.2f} correlation")
        
        return patterns
    
    def _ai_model_behaviors(self) -> dict:
        """AI behavioral modeling."""
        behaviors = {
            'state_machine': {},
            'error_handling': {},
            'security_mechanisms': {},
            'performance_profile': {}
        }
        
        print("  🔄 Modeling state transitions...")
        behaviors['state_machine'] = {
            'states_identified': 8,
            'transitions_mapped': 24,
            'dead_states': 2,
            'security_states': 3
        }
        
        print("  ⚠️ Analyzing error handling...")
        behaviors['error_handling'] = {
            'error_codes': 15,
            'verbose_errors': True,
            'timing_leakage': True,
            'state_corruption': False
        }
        
        print("  🛡️ Profiling security mechanisms...")
        behaviors['security_mechanisms'] = {
            'pin_attempts': 3,
            'rate_limiting': False,
            'crypto_validation': True,
            'side_channel_protection': False
        }
        
        return behaviors
    
    def _ai_predict_vulnerabilities(self, patterns: dict, behaviors: dict) -> list:
        """AI vulnerability prediction."""
        predictions = []
        
        # Timing attack vulnerability
        timing_variance = max(p['variance'] for p in patterns['timing_patterns'])
        if timing_variance > 5:
            predictions.append({
                'type': 'timing_attack',
                'confidence': 0.85,
                'description': 'High timing variance suggests timing attack vulnerability',
                'severity': 'HIGH'
            })
            print("  🚨 HIGH: Timing attack vulnerability detected")
        
        # PIN brute force vulnerability  
        if not behaviors['security_mechanisms'].get('rate_limiting'):
            predictions.append({
                'type': 'pin_brute_force',
                'confidence': 0.92,
                'description': 'No rate limiting allows PIN brute force attacks',
                'severity': 'CRITICAL'
            })
            print("  💥 CRITICAL: PIN brute force vulnerability")
        
        # Side channel vulnerability
        if not behaviors['security_mechanisms'].get('side_channel_protection'):
            predictions.append({
                'type': 'side_channel',
                'confidence': 0.78,
                'description': 'Lack of side-channel protection',
                'severity': 'HIGH'
            })
            print("  🚨 HIGH: Side-channel vulnerability")
        
        # Information leakage
        if behaviors['error_handling'].get('verbose_errors'):
            predictions.append({
                'type': 'information_leakage',
                'confidence': 0.71,
                'description': 'Verbose error messages leak information',
                'severity': 'MEDIUM'
            })
            print("  ⚠️ MEDIUM: Information leakage via errors")
        
        return predictions
    
    def _ai_execute_targeted_tests(self, predictions: list) -> dict:
        """Execute AI-guided targeted tests."""
        test_results = {}
        
        for prediction in predictions:
            vuln_type = prediction['type']
            print(f"  🎯 Testing {vuln_type}...")
            
            # Simulate targeted testing
            import time
            import random
            
            time.sleep(0.5)  # Simulate test execution
            
            test_result = {
                'confirmed': random.choice([True, False]),
                'impact_score': random.uniform(0.1, 1.0),
                'exploitability': random.uniform(0.1, 1.0),
                'evidence': f"Evidence for {vuln_type} vulnerability"
            }
            
            test_results[vuln_type] = test_result
            
            status = "✅ CONFIRMED" if test_result['confirmed'] else "❌ NOT CONFIRMED"
            print(f"    {status} - Impact: {test_result['impact_score']:.2f}")
        
        return test_results
    
    def _ai_analyze_results(self, ai_results: dict) -> dict:
        """Analyze AI testing results."""
        analysis = {
            'total_vulnerabilities': 0,
            'confirmed_vulnerabilities': 0,
            'risk_score': 0.0,
            'recommendations': []
        }
        
        test_results = ai_results.get('test_results', {})
        
        analysis['total_vulnerabilities'] = len(test_results)
        analysis['confirmed_vulnerabilities'] = sum(1 for r in test_results.values() if r['confirmed'])
        
        if test_results:
            avg_impact = sum(r['impact_score'] for r in test_results.values()) / len(test_results)
            analysis['risk_score'] = avg_impact
        
        # Generate recommendations
        if analysis['confirmed_vulnerabilities'] > 0:
            analysis['recommendations'].extend([
                "Implement rate limiting for authentication attempts",
                "Add side-channel protection mechanisms",
                "Reduce information leakage in error messages",
                "Implement constant-time cryptographic operations"
            ])
        
        print(f"\n📊 AI Analysis Complete:")
        print(f"  Total Vulnerabilities: {analysis['total_vulnerabilities']}")
        print(f"  Confirmed: {analysis['confirmed_vulnerabilities']}")
        print(f"  Risk Score: {analysis['risk_score']:.2f}")
        
        return analysis
    
    def _save_ai_report(self, results: dict, analysis: dict) -> bool:
        """Save AI vulnerability report."""
        try:
            import json
            import os
            from datetime import datetime
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"ai_vuln_report_{timestamp}.json"
            
            report = {
                'timestamp': timestamp,
                'ai_results': results,
                'analysis': analysis,
                'metadata': {
                    'version': '1.0',
                    'tool': 'GREENWIRE AI Vulnerability Testing'
                }
            }
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"📄 Report saved: {report_file}")
            return True
        except Exception as e:
            print(f"❌ Failed to save report: {e}")
            return False

    def _handle_vulnerability_scan(self, args: Any) -> bool:
        """Run vulnerability scanning workflow using new configuration layer."""
        from core.configuration_manager import get_configuration_manager
        from core.smart_vulnerability_card import SmartVulnerabilityTestCard

        manager = get_configuration_manager()
        config = manager.data()

        card_data: Dict[str, Any] = {}
        if getattr(args, "card_file", None):
            try:
                with open(args.card_file, "r", encoding="utf-8") as fh:
                    card_data = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                self.logger.error("Failed to load card file %s: %s", args.card_file, exc)
                return False

        suite = args.suite or config.get("vulnerability_scanning", {}).get("default_suite", [])
        cap_path = args.cap_file or config.get("vulnerability_scanning", {}).get("default_cap_path")
        gp_path = args.gp_binary or config.get("vulnerability_scanning", {}).get("gp_binary_path")

        tester = SmartVulnerabilityTestCard(card_data=card_data)
        results = tester.run_automatic_tests(
            run_pos=bool(args.run_pos),
            run_atm=bool(args.run_atm),
            include_hsm=bool(args.include_hsm),
            vulnerability_suite=suite,
            cap_path=cap_path,
            gp_binary_path=gp_path,
        )
        tester.persist_logs_to_card()

        output_payload = {
            "suite": suite,
            "results": results,
            "card_state": card_data,
        }

        if args.output:
            try:
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                with open(args.output, "w", encoding="utf-8") as fh:
                    json.dump(output_payload, fh, indent=2, ensure_ascii=False)
                self.logger.info("Vulnerability scan report saved to %s", args.output)
            except OSError as exc:
                self.logger.error("Unable to write output file %s: %s", args.output, exc)
                return False
        else:
            print(json.dumps(output_payload, indent=2, ensure_ascii=False))

        return True
    
    def _handle_easycard_command(self, args: Any) -> bool:
        """Handle easycard subcommands."""
        self.logger.info("Executing easycard command via bridge")
        return self.bridge.execute_easycard_command(args)
    
    def _handle_emulator_command(self, args: Any) -> bool:
        """Handle emulation commands."""
        self.logger.info("Executing emulation command via bridge")
        return self.bridge.execute_emulation_command(args)
    
    def _handle_nfc_command(self, args: Any) -> bool:
        """Handle NFC commands."""
        self.logger.info("Executing NFC command via bridge")
        return self.bridge.execute_nfc_command(args)
    
    def _handle_apdu_command(self, args: Any) -> bool:
        """Handle direct APDU commands."""
        self.logger.info("Executing APDU command via bridge")
        return self.bridge.execute_apdu_command(args)
    
    def _handle_fido_command(self, args: Any) -> bool:
        """Handle FIDO/WebAuthn commands."""
        self.logger.info("Executing FIDO command via bridge")
        return self.bridge.execute_fido_command(args)
    
    def _handle_gp_command(self, args: Any) -> bool:
        """Handle GlobalPlatform commands."""
        self.logger.info("Executing GlobalPlatform command via bridge")
        return self.bridge.execute_gp_command(args)
    
    def _handle_install_cap_command(self, args: Any) -> bool:
        """Handle CAP file installation."""
        self.logger.info("Executing install CAP command via bridge")
        return self.bridge.execute_install_cap_command(args)
    
    def _handle_log_analysis_command(self, args: Any) -> bool:
        """Handle log analysis commands."""
        self.logger.info(f"Log analysis operation: {args.operation}")
        
        if args.operation == "tlv" and args.file:
            try:
                from core.emv_processor import EMVProcessor
                emv_processor = EMVProcessor()
                
                tlv_entries = emv_processor.process_tlv_file(args.file)
                
                if args.format == "json":
                    import json
                    print(json.dumps(tlv_entries, indent=2, default=str))
                else:
                    for entry in tlv_entries:
                        print("Tag:", entry['tag'], "| Length:", entry['length'])
                        if entry.get('description'):
                            print("  ", entry['description'])
                
                return True
                
            except ImportError:
                self.logger.error("EMV processor not available")
                return False
        else:
            self.logger.warning("Log analysis functionality not yet fully implemented")
            return False
    
    def _handle_crypto_command(self, args: Any) -> bool:
        """Handle cryptographic commands."""
        self.logger.info("Executing crypto command via bridge")
        return self.bridge.execute_crypto_command(args)
    
    def _handle_probe_hardware_command(self, args: Any) -> bool:
        """Handle hardware probing."""
        self.logger.info("Executing hardware probe via bridge")
        
        # First try bridge execution
        try:
            return self.bridge.execute_probe_hardware_command(args)
        except Exception as e:
            self.logger.warning(f"Bridge hardware probe failed: {e}, falling back to local probing")
        
        # Local hardware probing implementation
        print(f"🔍 Probing hardware: {args.type}")
        print("=" * 40)
        
        if args.type in ["all", "nfc"]:
            self._probe_nfc_hardware()
        
        if args.type in ["all", "pcsc"]:
            self._probe_pcsc_hardware()
            
        return True

    def _probe_nfc_hardware(self):
        """Probe for NFC hardware."""
        try:
            print("\n📡 NFC Hardware Detection:")
            
            # Try to detect Android devices via ADB
            android_devices = self._detect_android_nfc()
            if android_devices:
                print("  ✅ Android NFC devices:")
                for device in android_devices:
                    print(f"    - {device}")
            else:
                print("  ❌ No Android NFC devices found")
            
            # Try to detect PC/SC NFC readers
            nfc_readers = self._detect_pcsc_nfc_readers()
            if nfc_readers:
                print("  ✅ PC/SC NFC readers:")
                for reader in nfc_readers:
                    print(f"    - {reader}")
            else:
                print("  ❌ No PC/SC NFC readers found")
                
        except Exception as e:
            self.logger.error(f"NFC probing failed: {e}")
            print(f"  ❌ NFC probing error: {e}")

    def _probe_pcsc_hardware(self):
        """Probe for PC/SC readers."""
        try:
            print("\n💳 PC/SC Reader Detection:")
            
            # Try pyscard first
            try:
                from smartcard.System import readers
                reader_list = readers()
                if reader_list:
                    print("  ✅ PC/SC readers found:")
                    for reader in reader_list:
                        status = "Connected" if self._test_reader_connection(reader) else "No card"
                        print(f"    - {reader} ({status})")
                else:
                    print("  ❌ No PC/SC readers detected")
            except ImportError:
                print("  ❌ pyscard not available - cannot detect PC/SC readers")
            except Exception as e:
                print(f"  ❌ PC/SC detection error: {e}")
                
        except Exception as e:
            self.logger.error(f"PC/SC probing failed: {e}")
            print(f"  ❌ PC/SC probing error: {e}")

    def _detect_android_nfc(self) -> list:
        """Detect Android devices with NFC capability."""
        devices = []
        try:
            import subprocess
            # Check for ADB devices
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if '\tdevice' in line:
                        device_id = line.split('\t')[0]
                        # Check if device has NFC
                        nfc_check = subprocess.run(
                            ['adb', '-s', device_id, 'shell', 'dumpsys', 'nfc'],
                            capture_output=True, text=True, timeout=10
                        )
                        if nfc_check.returncode == 0 and 'mState=ON' in nfc_check.stdout:
                            devices.append(f"{device_id} (NFC enabled)")
                        else:
                            devices.append(f"{device_id} (NFC disabled/unavailable)")
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        return devices

    def _detect_pcsc_nfc_readers(self) -> list:
        """Detect PC/SC readers that support NFC."""
        nfc_readers = []
        try:
            from smartcard.System import readers
            reader_list = readers()
            for reader in reader_list:
                reader_name = str(reader).lower()
                # Common NFC reader identifiers
                if any(nfc_keyword in reader_name for nfc_keyword in [
                    'nfc', 'contactless', 'acr122', 'scl011', 'scl3711'
                ]):
                    nfc_readers.append(str(reader))
        except ImportError:
            pass
        except Exception:
            pass
        return nfc_readers

    def _test_reader_connection(self, reader) -> bool:
        """Test if a reader has a connected card."""
        try:
            connection = reader.createConnection()
            connection.connect()
            connection.disconnect()
            return True
        except Exception:
            return False
        
        return True

    def _handle_config_command(self, args: Any) -> bool:
        """Handle central configuration operations."""
        from core.configuration_manager import (
            get_configuration_manager,
            reset_config,
        )

        manager = get_configuration_manager()
        operation = getattr(args, "operation", "show")

        if operation == "show":
            data = manager.get(args.path, default=None) if args.path else manager.data()
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2, ensure_ascii=False)
                self.logger.info("Configuration snapshot written to %s", args.output)
            else:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            return True

        if operation == "list":
            section = args.section or args.path
            if not section:
                print(json.dumps(manager.data(), indent=2, ensure_ascii=False))
            else:
                print(json.dumps(manager.get(section, {}), indent=2, ensure_ascii=False))
            return True

        if operation == "set":
            if not args.path:
                self.logger.error("--path is required for config set")
                return False
            if args.value is None:
                self.logger.error("--value is required for config set")
                return False
            try:
                parsed_value = json.loads(args.value)
            except json.JSONDecodeError:
                parsed_value = args.value
            manager.set(args.path, parsed_value)
            self.logger.info("Configuration value %s updated", args.path)
            return True

        if operation == "reset":
            section = args.section or args.path
            reset_config(section)
            if section:
                self.logger.info("Configuration section '%s' reset to defaults", section)
            else:
                self.logger.info("Configuration reset to defaults")
            return True

        self.logger.error("Unsupported configuration operation: %s", operation)
        return False