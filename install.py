#!/usr/bin/env python3
"""
GREENWIRE Setup and Installation Script

Installs and configures dependencies including pyAPDUFuzzer integration
and sets up security scanning tools.
"""

import os
import sys
import subprocess
import urllib.request
from pathlib import Path

def run_command(cmd, description, capture_output=True):
    """Run a shell command with error handling."""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=capture_output, text=True)
        if result.returncode == 0:
            print(f"✅ {description} completed successfully")
            return True
        else:
            print(f"❌ {description} failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ {description} failed with exception: {e}")
        return False

def install_pyapdufuzzer():
    """Install pyAPDUFuzzer from GitHub."""
    print("\n📥 Installing pyAPDUFuzzer...")
    
    # Create external directory
    external_dir = Path("external")
    external_dir.mkdir(exist_ok=True)
    
    # Check if already installed
    pyapdu_dir = external_dir / "pyAPDUFuzzer"
    if pyapdu_dir.exists():
        print("✅ pyAPDUFuzzer already installed")
        return True
    
    # Clone repository
    clone_cmd = f"git clone https://github.com/petrs/pyAPDUFuzzer.git {pyapdu_dir}"
    if run_command(clone_cmd, "Cloning pyAPDUFuzzer repository"):
        print("✅ pyAPDUFuzzer installed successfully")
        return True
    else:
        print("❌ Failed to install pyAPDUFuzzer")
        return False

def install_dependencies():
    """Install Python dependencies."""
    print("\n📦 Installing Python dependencies...")
    
    # Upgrade pip first
    run_command("python -m pip install --upgrade pip", "Upgrading pip")
    
    # Install requirements
    if run_command("pip install -r requirements.txt", "Installing requirements"):
        print("✅ Dependencies installed successfully")
        return True
    else:
        print("❌ Failed to install dependencies")
        return False

def setup_security_scanning():
    """Set up security scanning tools."""
    print("\n🔒 Setting up security scanning...")
    
    # Install security tools if not already present
    security_tools = [
        "safety",
        "bandit", 
        "semgrep"
    ]
    
    for tool in security_tools:
        run_command(f"pip install {tool}", f"Installing {tool}")
    
    print("✅ Security scanning tools installed")

def create_config_files():
    """Create configuration files for GREENWIRE."""
    print("\n⚙️ Creating configuration files...")
    
    # Create .gitleaks.toml for secret scanning
    gitleaks_config = '''# Gitleaks configuration for GREENWIRE
title = "GREENWIRE Security Scanning"

[allowlist]
description = "Global allowlist"
commits = []
paths = [
    "static/data/test_keys.json",  # Test keys are expected
    "ca_keys.json",               # CA keys are public
]
regexes = [
    '''API_KEY_TEST''',          # Test API keys
]

[[rules]]
id = "generic-api-key"
description = "Generic API Key"
regex = '''(?i)(api_key|apikey)(.{0,20})?['"\s:=]([0-9a-zA-Z]{16,})'''
tags = ["api", "key"]

[[rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "access-key"]

[[rules]]
id = "private-key"
description = "Private Key"
regex = '''-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'''
tags = ["private-key"]
'''
    
    with open('.gitleaks.toml', 'w') as f:
        f.write(gitleaks_config)
    
    # Create .bandit configuration
    bandit_config = '''[bandit]
exclude_dirs = ["external", "test", "tests"]
skips = ["B101", "B601"]  # Skip assert and shell usage warnings for testing tools

[bandit.assert_used]
skips = ["*/test_*.py", "*/tests/*.py"]
'''
    
    with open('.bandit', 'w') as f:
        f.write(bandit_config)
    
    print("✅ Configuration files created")

def verify_installation():
    """Verify the installation is working."""
    print("\n🔍 Verifying installation...")
    
    # Test Python imports
    try:
        import greenwire
        print("✅ GREENWIRE imports successfully")
    except ImportError as e:
        print(f"❌ GREENWIRE import failed: {e}")
        return False
    
    # Test pyAPDUFuzzer integration
    try:
        from static.lib.greenwire_pyapdu_fuzzer import GreenwirePyAPDUFuzzer
        fuzzer = GreenwirePyAPDUFuzzer(verbose=False)
        print("✅ pyAPDUFuzzer integration working")
    except ImportError:
        print("⚠️ pyAPDUFuzzer integration not available (external dependency)")
    
    # Test menu system
    if run_command("python greenwire.py --help", "Testing CLI", capture_output=True):
        print("✅ CLI working correctly")
        return True
    else:
        print("❌ CLI test failed")
        return False

def main():
    """Main setup function."""
    print("🌟 GREENWIRE Setup Script")
    print("="*50)
    print("Setting up GREENWIRE with enhanced security and fuzzing capabilities")
    
    # Change to GREENWIRE directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    steps = [
        ("Installing Python dependencies", install_dependencies),
        ("Installing pyAPDUFuzzer", install_pyapdufuzzer),
        ("Setting up security scanning", setup_security_scanning),
        ("Creating configuration files", create_config_files),
        ("Verifying installation", verify_installation),
    ]
    
    success_count = 0
    for description, func in steps:
        print(f"\n{'='*50}")
        print(f"Step {success_count + 1}/{len(steps)}: {description}")
        print(f"{'='*50}")
        
        if func():
            success_count += 1
        else:
            print(f"\n❌ Setup failed at step: {description}")
            break
    
    print(f"\n{'='*50}")
    if success_count == len(steps):
        print("🎉 GREENWIRE setup completed successfully!")
        print("\nNext steps:")
        print("1. Run 'python greenwire.py --menu' to start the interactive interface")
        print("2. Try 'python greenwire.py --help' to see all available commands")
        print("3. Check the Testing & Security menu for pyAPDUFuzzer integration")
        print("4. Use EasyCard Creation for advanced testing cards")
    else:
        print(f"⚠️ Setup completed with issues ({success_count}/{len(steps)} steps successful)")
        print("Check the error messages above and run install.py again")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()