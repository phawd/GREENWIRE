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

# Setup logging with proper encoding
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
                self.test_results['passed'] += 1
                logger.info(f"[PASS] {description}")
                self.test_results['details'].append({
                    'test': description,
                    'status': 'PASSED',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                })
                return True
            else:
                self.test_results['failed'] += 1
                error_msg = f"FAILED: {description} - Return code: {result.returncode}"
                logger.error(error_msg)
                self.test_results['errors'].append(error_msg)
                self.test_results['details'].append({
                    'test': description,
                    'status': 'FAILED',
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                })
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
            'analysis.py'
        ]
        
        for file_name in required_files:
            file_path = self.base_path / file_name
            if file_path.exists():
                logger.info(f"[PASS] Found: {file_name}")
                self.test_results['passed'] += 1
            else:
                error_msg = f"Missing required file: {file_name}"
                logger.error(f"[FAIL] {error_msg}")
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

    def test_greenwire_ui_functionality(self):
        """Test GREENWIRE UI basic functionality"""
        logger.info("=" * 50)
        logger.info("TESTING GREENWIRE UI FUNCTIONALITY")
        logger.info("=" * 50)
        
        # Test that UI can be imported and run (dry run)
        cmd = [sys.executable, "-c", "import greenwire_ui; print('UI module loaded successfully')"]
        self.run_command(cmd, "GREENWIRE UI Import Test", timeout=10)

    def test_dependencies(self):
        """Test that required Python packages are available"""
        logger.info("=" * 50)
        logger.info("TESTING DEPENDENCIES")
        logger.info("=" * 50)
        
        # Test core Python modules (these should always be available)
        core_dependencies = [
            "argparse",
            "logging", 
            "subprocess",
            "json",
            "os",
            "sys"
        ]
        
        for dep in core_dependencies:
            cmd = [sys.executable, "-c", f"import {dep}; print(f'{dep} is available')"]
            self.run_command(cmd, f"Dependency check: {dep}", timeout=5)
            
        # Test optional dependencies (these might fail, but we'll note it)
        optional_dependencies = [
            "cryptography"
        ]
        
        for dep in optional_dependencies:
            cmd = [sys.executable, "-c", f"try:\n    import {dep}\n    print(f'{dep} is available')\nexcept ImportError:\n    print(f'{dep} not available (optional)')"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, cwd=self.base_path)
                if result.returncode == 0:
                    logger.info(f"[PASS] Optional dependency: {dep}")
                    self.test_results['passed'] += 1
                else:
                    logger.warning(f"[WARN] Optional dependency missing: {dep}")
                    # Don't count as failure since it's optional
            except Exception as e:
                logger.warning(f"[WARN] Could not test optional dependency {dep}: {e}")

    def test_ui_imports(self):
        """Test that UI modules can be imported"""
        logger.info("=" * 50)
        logger.info("TESTING UI IMPORTS")
        logger.info("=" * 50)
        
        test_imports = [
            "greenwire_ui",
            "smartcard_utils", 
            "analysis"
        ]
        
        for import_stmt in test_imports:
            cmd = [sys.executable, "-c", f"import {import_stmt}; print('{import_stmt} imported successfully')"]
            self.run_command(cmd, f"Import test: {import_stmt}", timeout=10)

    def run_comprehensive_test(self):
        """Run all tests in the suite"""
        logger.info("[INFO] Starting GREENWIRE Comprehensive Test Suite")
        logger.info(f"Working directory: {self.base_path}")
        logger.info("=" * 80)
        
        start_time = time.time()
        
        # Run all test categories
        self.test_file_existence()
        self.test_dependencies()
        self.test_python_syntax()
        self.test_ui_imports()
        self.test_greenwire_ui_functionality()
        
        # Only test greenwire-brute help if the file exists and compiles
        if (self.base_path / "greenwire-brute.py").exists():
            self.test_greenwire_brute_help()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Generate final report
        self.generate_report(duration)
        
        return self.test_results['failed'] == 0

    def generate_report(self, duration):
        """Generate comprehensive test report"""
        logger.info("=" * 80)
        logger.info("[FINAL] TEST SUITE COMPLETE")
        logger.info("=" * 80)
        
        total_tests = self.test_results['passed'] + self.test_results['failed']
        success_rate = (self.test_results['passed'] / total_tests * 100) if total_tests > 0 else 0
        
        logger.info(f"[SUMMARY] RESULTS:")
        logger.info(f"   Total Tests: {total_tests}")
        logger.info(f"   Passed: {self.test_results['passed']} [PASS]")
        logger.info(f"   Failed: {self.test_results['failed']} [FAIL]")
        logger.info(f"   Success Rate: {success_rate:.1f}%")
        logger.info(f"   Duration: {duration:.2f} seconds")
        
        if self.test_results['errors']:
            logger.info(f"\n[ERRORS] ENCOUNTERED:")
            for i, error in enumerate(self.test_results['errors'], 1):
                logger.error(f"   {i}. {error}")
        
        # Save detailed results to JSON
        report_file = self.base_path / "test_results.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.test_results, f, indent=2)
        
        logger.info(f"\n[REPORT] Detailed results saved to: {report_file}")
        
        if self.test_results['failed'] == 0:
            logger.info("[SUCCESS] ALL TESTS PASSED! GREENWIRE UI suite is ready.")
        else:
            logger.warning("[WARNING] Some tests failed. Please review the errors above.")

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
