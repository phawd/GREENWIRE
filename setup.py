#!/usr/bin/env python3
"""
GREENWIRE Static Distribution Setup Script

This script creates a static distribution of GREENWIRE with all dependencies
bundled for easy deployment and distribution.
"""

from setuptools import find_packages, setup
import os, shutil, sys
from pathlib import Path

# Version information
VERSION = "1.0.0"

# Read requirements
with open('requirements.txt', 'r') as f:
    requirements = [
        line.strip() 
        for line in f.readlines() 
        if line.strip() and not line.startswith('#')
    ]

# Data files to include in the distribution
data_files = [
    ('static/java', ['static/java/gp.jar']),
    ('static/data', [
        'data/bank_data.json',
        'data/merchant_categories.json', 
        'data/card_defaults.json'
    ]),
    ('', ['requirements.txt', 'README.md']),
]

# Additional files to include
package_data = {
    'greenwire': [
        'core/*.py',
        'cli/*.py',
        'data/*.json',
    ]
}

setup(
    name="greenwire-static",
    version=VERSION,
    description="GREENWIRE EMV/NFC Testing Toolkit - Static Distribution",
    long_description=open('README.md', 'r', encoding='utf-8').read(),
    long_description_content_type="text/markdown",
    author="GREENWIRE Team",
    author_email="contact@nexa.work",
    url="https://github.com/phawd/greenwire",
    
    # Package configuration
    packages=find_packages(),
    package_data=package_data,
    data_files=data_files,
    include_package_data=True,
    zip_safe=False,
    
    # Dependencies
    install_requires=requirements,
    python_requires=">=3.8",
    
    # Entry points
    entry_points={
        'console_scripts': [
            'greenwire=greenwire:main',
            'greenwire-static=greenwire:main_static',
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Java",
        "Topic :: Security",
        "Topic :: System :: Hardware",
        "Topic :: Communications",
    ],
    
    # Keywords
    keywords="emv nfc smartcard security testing fuzzing",
    
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/greenwire/greenwire/issues",
        "Source": "https://github.com/greenwire/greenwire",
        "Documentation": "https://greenwire.readthedocs.io/",
    },
)

def create_static_distribution():
    """Create a complete static distribution with all dependencies."""
    
    print("Creating GREENWIRE Static Distribution...")
    
    # Create distribution directory
    dist_dir = Path("dist/greenwire-static")
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    dist_dir.mkdir(parents=True)
    
    # Copy main files
    print("Copying main application files...")
    shutil.copy2("greenwire.py", dist_dir / "greenwire.py")
    shutil.copy2("requirements.txt", dist_dir / "requirements.txt")
    
    # Copy greenwire package
    if Path("greenwire").exists():
        print("Copying greenwire package...")
        shutil.copytree("greenwire", dist_dir / "greenwire")
    
    # Copy static directory
    if Path("static").exists():
        print("Copying static resources...")
        shutil.copytree("static", dist_dir / "static")
    
    # Copy data directory
    if Path("data").exists():
        print("Copying data files...")
        shutil.copytree("data", dist_dir / "data")
    
    # Create launcher script
    print("Creating launcher scripts...")
    
    # Windows batch launcher
    with open(dist_dir / "greenwire.bat", "w") as f:
        f.write("""@echo off
REM GREENWIRE Static Distribution Launcher
python greenwire.py --static %*
""")
    
    # Unix shell launcher
    with open(dist_dir / "greenwire.sh", "w") as f:
        f.write("""#!/bin/bash
# GREENWIRE Static Distribution Launcher
python3 greenwire.py --static "$@"
""")
    
    # Make shell script executable
    if os.name != 'nt':
        os.chmod(dist_dir / "greenwire.sh", 0o755)
    
    # Create installation instructions
    with open(dist_dir / "INSTALL.txt", "w") as f:
        f.write("""GREENWIRE Static Distribution Installation
==========================================

This is a static distribution of GREENWIRE with all dependencies included.

Installation:
1. Install Python 3.8 or newer if not already installed
2. Install dependencies: pip install -r requirements.txt
3. Run GREENWIRE: python greenwire.py --static

OR use the launcher scripts:
- Windows: greenwire.bat
- Unix/Linux: ./greenwire.sh

Features included:
- All Python dependencies pinned to specific versions
- Java tools (gp.jar) included in static/java/
- Real-world bank data and configurations
- Complete EMV/NFC testing toolkit

For help: python greenwire.py --static --help
For interactive menu: python greenwire.py --static --menu
""")
    
    print(f"Static distribution created in: {dist_dir}")
    print("To test: cd dist/greenwire-static && python greenwire.py --static --help")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "create_static":
        create_static_distribution()
    else:
        setup()
