#!/bin/bash

# GREENWIRE Repository Setup Script
# Author: John Moore Westmoreland Grandfield
# Date: June 8, 2025

set -e  # Exit on any error

# Configuration
REPO_URL="https://github.com/phawd/GREENWIRE.git"
TARGET_DIR="F:/repo/GREENWIRE"
LOG_FILE="setup_log.txt"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting GREENWIRE repository setup..."

# Create target directory
log "Creating target directory..."
mkdir -p "$TARGET_DIR"

# Clone repository
log "Cloning repository..."
git clone "$REPO_URL" "$TARGET_DIR"

# Change to repository directory
cd "$TARGET_DIR"

# Create Python virtual environment
log "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
log "Installing dependencies..."
python3 -m pip install --upgrade pip
pip install -r requirements.txt

# Run tests
log "Running tests..."
python3 -m pytest tests/ -v

log "Setup complete! GREENWIRE is ready to use."
echo "==============================================="
echo "GREENWIRE has been set up in $TARGET_DIR"
echo "To activate the environment:"
echo "cd $TARGET_DIR"
echo "source venv/bin/activate"
echo "==============================================="
