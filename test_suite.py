#!/usr/bin/env python3
"""
GREENWIRE UI Test Suite
Comprehensive testing for the entire GREENWIRE application suite
"""

import subprocess
import logging
import sys
import os
import json
import time
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_suite.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class GreenWireTestSuite:
    def __init__(self):
        self.test_results = {
            'passed': 0,
            'failed': 0,
            'errors': [],
            'details': []
        }
        self.base_path = Path(__file__).parent

    def run_command(self, cmd, description, timeout=30):
        """Run a command and capture results"""
        logger.info(f"Running test: {description}")
        logger.info(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.base_path
            )
            if result.returncode == 0:
                self.test_results["passed"] += 1
                logger.info(f"[PASS] {description}")
                self.test_results["details"].append(
                    {
                        "test": description,
                        "status": "PASSED",
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }
                )
                return True
            else:
                self.test_results["failed"] += 1
                error_msg = (
                    f"FAILED: {description} - Return code: {result.returncode}"
                )
                logger.error(error_msg)
                self.test_results["errors"].append(error_msg)
                self.test_results["details"].append(
                    {
                        "test": description,
                        "status": "FAILED",
                        "returncode": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }
                )
                return False
                
        except subprocess.TimeoutExpired:
            self.test_results['failed'] += 1
            error_msg = f"TIMEOUT: {description} - Exceeded {timeout}s"
            logger.error(error_msg)
            self.test_results['errors'].append(error_msg)
            return False
            
        except Exception as e:
            self.test_results['failed'] += 1
            error_msg = f"ERROR: {description} - {str(e)}"
            logger.error(error_msg)
            self.test_results['errors'].append(error_msg)
            return False

    def test_file_existence(self):
        """Test that all required files exist"""
        logger.info("=" * 50)
        logger.info("TESTING FILE EXISTENCE")
        logger.info("=" * 50)
        
        required_files = [
            'greenwire_ui.py',
            'greenwire-brute.py',
            'test_cli.py',
            'test_hsm.py',
            'smartcard_utils.py',
            'analysis.py'        ]
        
        for file_name in required_files:
            file_path = self.base_path / file_name
            if file_path.exists():
                logger.info(f"[✓] Found: {file_name}")
                self.test_results['passed'] += 1
            else:
                error_msg = f"Missing required file: {file_name}"
                logger.error(f"[✗] {error_msg}")
                self.test_results['failed'] += 1
                self.test_results['errors'].append(error_msg)

    def test_python_syntax(self):
        """Test Python syntax for all Python files"""
        logger.info("=" * 50)
        logger.info("TESTING PYTHON SYNTAX")
        logger.info("=" * 50)
        
        python_files = list(self.base_path.glob("*.py"))
        
        for py_file in python_files:
            if py_file.name.startswith('test_suite'):
                continue  # Skip self
                
            cmd = [sys.executable, "-m", "py_compile", str(py_file)]
            self.run_command(
                cmd, 
                f"Syntax check: {py_file.name}",
                timeout=10
            )

    def test_greenwire_brute_help(self):
        """Test that greenwire-brute.py shows help"""
        logger.info("=" * 50)
        logger.info("TESTING GREENWIRE BRUTE HELP")
        logger.info("=" * 50)
        
        cmd = [sys.executable, "greenwire-brute.py", "--help"]
        self.run_command(cmd, "GREENWIRE Brute Help", timeout=10)

    def test_greenwire_brute_modes(self):
        """Test various modes of greenwire-brute.py with dry run"""
        logger.info("=" * 50)
        logger.info("TESTING GREENWIRE BRUTE MODES")
        logger.info("=" * 50)
        
        # Test modes that should work without hardware
        test_modes = [
            {
                'cmd': [sys.executable, "greenwire-brute.py", "--mode", "dry-run", "--count", "1"],
                'desc': "Dry run mode"
            },
            # Add more test modes as needed
        ]
        
        for test in test_modes:
            self.run_command(test['cmd'], test['desc'], timeout=15)

    def test_hsm_functionality(self):
        """Test HSM functionality"""
        logger.info("=" * 50)
        logger.info("TESTING HSM FUNCTIONALITY")
        logger.info("=" * 50)
        
        # Test key generation
        cmd = [sys.executable, "test_hsm.py", "--generate-keys", "--output", "test_keys"]
        self.run_command(cmd, "HSM Key Generation", timeout=20)

    def test_ui_import(self):
        """Test that UI modules can be imported"""
        logger.info("=" * 50)
        logger.info("TESTING UI IMPORTS")
        logger.info("=" * 50)
        
        test_imports = [
            "import greenwire_ui",
            "import smartcard_utils",
            "import analysis"
        ]
        
        for import_stmt in test_imports:
            cmd = [sys.executable, "-c", import_stmt]
            self.run_command(cmd, f"Import test: {import_stmt}", timeout=10)

    def test_dependencies(self):
        """Test that required Python packages are available"""
        logger.info("=" * 50)
        logger.info("TESTING DEPENDENCIES")
        logger.info("=" * 50)
        
        dependencies = [
            "cryptography",
            "argparse",
            "logging",
            "subprocess",
            "json"
        ]
        
        for dep in dependencies:
            cmd = [sys.executable, "-c", f"import {dep}; print(f'{dep} is available')"]
            self.run_command(cmd, f"Dependency check: {dep}", timeout=5)

    def run_comprehensive_test(self):
        """Run all tests in the suite"""
        logger.info("🚀 Starting GREENWIRE Comprehensive Test Suite")
        logger.info(f"Working directory: {self.base_path}")
        logger.info("=" * 80)
        
        start_time = time.time()
        
        # Run all test categories
        self.test_file_existence()
        self.test_dependencies()
        self.test_python_syntax()
        self.test_ui_import()
        self.test_greenwire_brute_help()
        self.test_greenwire_brute_modes()
        self.test_hsm_functionality()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Generate final report
        self.generate_report(duration)
        
        return self.test_results['failed'] == 0

    def generate_report(self, duration):
        """Generate comprehensive test report"""
        logger.info("=" * 80)
        logger.info("🏁 TEST SUITE COMPLETE")
        logger.info("=" * 80)
        
        total_tests = self.test_results['passed'] + self.test_results['failed']
        success_rate = (self.test_results['passed'] / total_tests * 100) if total_tests > 0 else 0
        
        logger.info(f"📊 RESULTS SUMMARY:")
        logger.info(f"   Total Tests: {total_tests}")
        logger.info(f"   Passed: {self.test_results['passed']} ✓")
        logger.info(f"   Failed: {self.test_results['failed']} ✗")
        logger.info(f"   Success Rate: {success_rate:.1f}%")
        logger.info(f"   Duration: {duration:.2f} seconds")
        
        if self.test_results['errors']:
            logger.info(f"\n❌ ERRORS ENCOUNTERED:")
            for i, error in enumerate(self.test_results['errors'], 1):
                logger.error(f"   {i}. {error}")
        
        # Save detailed results to JSON
        report_file = self.base_path / "test_results.json"
        with open(report_file, 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        logger.info(f"\n📄 Detailed results saved to: {report_file}")
        
        if self.test_results['failed'] == 0:
            logger.info("🎉 ALL TESTS PASSED! GREENWIRE UI suite is ready for deployment.")
        else:
            logger.warning("⚠️  Some tests failed. Please review the errors above.")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="GREENWIRE UI Test Suite")
    parser.add_argument("--quick", action="store_true", help="Run quick tests only")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    test_suite = GreenWireTestSuite()
    success = test_suite.run_comprehensive_test()
    
    sys.exit(0 if success else 1)
