# GREENWIRE Code Verification & Fixes

Status update (2026-03-18):
- `commands/` exists in the repository and the missing-module concern is no longer current.
- `greenwire_modern.py` now uses explicit command import aliases, safer dynamic command registration, `parents=True` log directory creation, and a YAML fallback when PyYAML is unavailable.
- `install.py` now runs subprocesses without `shell=True`, uses `sys.executable`, and reports import verification more defensively.
- The remaining sections below should be treated as historical review notes and revalidated before being considered open defects.

## Critical Issues Found

### 1. **Missing Commands Module Structure**

**Problem:** `greenwire_modern.py` imports from non-existent `commands` module:
```python
from commands.rfid_testing import get_command
from commands.cap_management import get_command
from commands.issuer_pipeline import get_command
from commands import register_all_commands
```

**Fix:** Create the following directory structure:
```
commands/
├── __init__.py
├── rfid_testing.py
├── cap_management.py
└── issuer_pipeline.py
```

---

### 2. **Duplicate Import Names in `_register_dynamic_commands`**

**Problem:** All three command imports use the same function name `get_command`:
```python
from commands.rfid_testing import get_command
cmd_info = get_command()  # First use

from commands.cap_management import get_command  # Overwrites!
cmd_info = get_command()  # Uses cap_management version

from commands.issuer_pipeline import get_command  # Overwrites again!
cmd_info = get_command()  # Uses issuer_pipeline version
```

**Fix:** Use aliased imports:
```python
from commands.rfid_testing import get_command as get_rfid_cmd
from commands.cap_management import get_command as get_cap_cmd
from commands.issuer_pipeline import get_command as get_pipeline_cmd
```

---

### 3. **Type Annotation Error in `_register_dynamic_commands`**

**Problem:** Invalid type hint comment:
```python
for name, cmd_info in self.commands.items(): # type: ignore
```

**Fix:** Proper typing:
```python
for name, cmd_info in self.commands.items():
    if not isinstance(cmd_info, dict):
        continue
```

---

### 4. **Missing EMV Module in `test_emv.py.bak`**

**Problem:** Test file imports from non-existent `emv_data` module:
```python
from emv_data.commands.emv_commands import EMVCommand
from emv_data.commands.apdu_responses import APDUResponse
from emv_data.commands.hsm_commands import HSMCommand
from emv_data.emv_integration import GREENWIREEMVInterface
```

**Fix:** Either create the EMV module structure or remove/update the test file.

---

### 5. **Unsafe Command Execution in `install.py`**

**Problem:** Using `shell=True` which is a security risk:
```python
subprocess.run(cmd, shell=True, capture_output=capture_output, text=True)
```

**Fix:** Use list-based commands:
```python
def run_command(cmd_list, description, capture_output=True):
    """Run a command with error handling."""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(cmd_list, capture_output=capture_output, text=True)
        # ... rest of function
```

---

### 6. **Missing Error Handling for Module Imports**

**Problem:** `install.py` tries to import `greenwire` module that may not exist:
```python
import greenwire  # May fail if not installed
```

**Fix:** Add proper error handling:
```python
try:
    import greenwire
    print("✅ GREENWIRE imports successfully")
except ImportError as e:
    print(f"⚠️ GREENWIRE module not found: {e}")
    print("This is expected during initial setup")
```

---

### 7. **Inconsistent Command Registration Pattern**

**Problem:** Three different patterns for handling commands:
- Built-in commands (list, docs, config, health)
- Dynamic registered commands (self.commands)
- Special-case commands (rfid-test, cap, card-issue)

**Fix:** Unify command registration through a single pattern.

---

### 8. **Missing YAML Import Handling**

**Problem:** `import yaml` without checking if PyYAML is installed:
```python
import yaml
```

**Fix:** Add fallback:
```python
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    # Fallback behavior
```

---

### 9. **Path Handling Issues**

**Problem:** Hardcoded path separators:
```python
log_file = Path("logs") / "greenwire.log"
```

**Fix:** Already correct using `pathlib.Path`, but ensure parent directory creation:
```python
log_file = Path("logs") / "greenwire.log"
log_file.parent.mkdir(parents=True, exist_ok=True)  # Add parents=True
```

---

### 10. **Missing `greenwire.py` Main Entry Point**

**Problem:** `install.py` references `greenwire.py` but only `greenwire_modern.py` exists:
```python
run_command("python greenwire.py --help", "Testing CLI", capture_output=True)
```

**Fix:** Either:
- Rename `greenwire_modern.py` to `greenwire.py`, or
- Update references to use `greenwire_modern.py`

---

## Priority Fixes (High to Low)

### High Priority
1. ✅ Create missing `commands/` module structure
2. ✅ Fix duplicate import names in `_register_dynamic_commands`
3. ✅ Fix path handling in logging setup
4. ✅ Resolve `greenwire.py` vs `greenwire_modern.py` naming

### Medium Priority
5. Fix shell=True security issue in `install.py`
6. Add proper YAML import fallback
7. Unify command registration pattern

### Low Priority
8. Clean up or fix `test_emv.py.bak` test file
9. Add more comprehensive error messages
10. Improve type hints throughout

---

## Corrected Code Snippets

### Fixed `_register_dynamic_commands` Method

```python
def _register_dynamic_commands(self, subparsers):
    """Register dynamically added commands"""
    
    # Import and register new RFID testing command
    try:
        from commands.rfid_testing import get_command as get_rfid_cmd
        cmd_info = get_rfid_cmd()
        parser = subparsers.add_parser(
            cmd_info.get_name(), 
            help=cmd_info.get_description(), 
            add_help=False
        )
        parser.add_argument('sub_args', nargs=argparse.REMAINDER, 
                           help='Arguments for the command')
    except ImportError as e:
        self.logger.debug(f"RFID testing command not available: {e}")
    
    # Import and register CAP management command
    try:
        from commands.cap_management import get_command as get_cap_cmd
        cmd_info = get_cap_cmd()
        parser = subparsers.add_parser(
            cmd_info.get_name(), 
            help=cmd_info.get_description(), 
            add_help=False
        )
        parser.add_argument('sub_args', nargs=argparse.REMAINDER, 
                           help='Arguments for the command')
    except ImportError as e:
        self.logger.debug(f"CAP management command not available: {e}")
    
    # Import and register issuer pipeline command
    try:
        from commands.issuer_pipeline import get_command as get_pipeline_cmd
        cmd_info = get_pipeline_cmd()
        parser = subparsers.add_parser(
            cmd_info.get_name(), 
            help=cmd_info.get_description(), 
            add_help=False
        )
        parser.add_argument('sub_args', nargs=argparse.REMAINDER, 
                           help='Arguments for the command')
    except ImportError as e:
        self.logger.debug(f"Issuer pipeline command not available: {e}")
    
    # Register existing dynamic commands
    seen_commands = set()
    for name, cmd_info in self.commands.items():
        if not isinstance(cmd_info, dict):
            continue
            
        # Skip aliases (they point to the same command info)
        if name in seen_commands:
            continue
            
        # Skip if this is an alias of another command
        is_alias = False
        for other_name, other_info in self.commands.items():
            if isinstance(other_info, dict) and name in other_info.get('aliases', []):
                is_alias = True
                break
        
        if is_alias:
            continue
        
        seen_commands.add(name)
        
        cmd_parser = subparsers.add_parser(name, help=cmd_info['description'])
        
        # Add command-specific arguments
        for arg_spec in cmd_info.get('args', []):
            arg_spec_copy = arg_spec.copy()
            arg_name = arg_spec_copy.pop('name')
            cmd_parser.add_argument(arg_name, **arg_spec_copy)
```

### Fixed Logging Setup

```python
def _setup_logging(self) -> logging.Logger:
    """Setup structured logging"""
    logger = logging.getLogger("greenwire")
    
    # Console handler with clean format
    console_handler = logging.StreamHandler(sys.stderr)
    console_format = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler for detailed logs
    log_file = Path("logs") / "greenwire.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)  # Fixed: added parents=True
    
    file_handler = logging.FileHandler(log_file)
    file_format = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    logger.setLevel(logging.INFO)
    return logger
```

### Fixed YAML Import

```python
import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum

# Optional YAML support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
```

Then in the output method:

```python
def output(self, result: CommandResult) -> None:
    """Output result in requested format"""
    if self.output_format == OutputFormat.JSON:
        print(json.dumps(asdict(result), indent=2))
    elif self.output_format == OutputFormat.YAML:
        if YAML_AVAILABLE:
            print(yaml.dump(asdict(result), default_flow_style=False))
        else:
            self.logger.warning("YAML output requested but PyYAML not installed, using JSON")
            print(json.dumps(asdict(result), indent=2))
    # ... rest of method
```

---

## Files to Create

### `commands/__init__.py`
```python
"""GREENWIRE Commands Module"""

def register_all_commands(cli):
    """Register all available commands with the CLI"""
    # Import and register commands as they become available
    try:
        from .rfid_testing import register_command as register_rfid
        register_rfid(cli)
    except ImportError:
        pass
    
    try:
        from .cap_management import register_command as register_cap
        register_cap(cli)
    except ImportError:
        pass
    
    try:
        from .issuer_pipeline import register_command as register_pipeline
        register_pipeline(cli)
    except ImportError:
        pass
```

### Basic Command Template (`commands/rfid_testing.py`)
```python
"""RFID Testing Command"""

class RFIDTestCommand:
    def get_name(self):
        return "rfid-test"
    
    def get_description(self):
        return "RFID testing and analysis"
    
    def execute(self, args):
        return {
            'success': True,
            'message': 'RFID test completed',
            'data': {'status': 'not implemented'}
        }

def get_command():
    return RFIDTestCommand()

def register_command(cli):
    """Register with CLI"""
    pass
```

---

## Testing Checklist

After applying fixes:

- [ ] Run `python greenwire_modern.py --help`
- [ ] Test `python greenwire_modern.py list commands`
- [ ] Test `python greenwire_modern.py config show`
- [ ] Test `python greenwire_modern.py health`
- [ ] Verify logging creates `logs/greenwire.log`
- [ ] Test JSON output: `python greenwire_modern.py health --format json`
- [ ] Test with missing commands module (graceful degradation)
- [ ] Run `python install.py` to verify setup script

---

## Recommended Next Steps

1. **Rename the main file**: `greenwire_modern.py` → `greenwire.py`
2. **Create stub command modules** to prevent ImportErrors
3. **Add comprehensive docstrings** to all public methods
4. **Write unit tests** for core functionality
5. **Add CI/CD pipeline** with automated testing
6. **Document API** for command module development
7. **Add configuration file support** (JSON/YAML)
8. **Implement proper logging rotation**

---

## Security Considerations

1. Replace `shell=True` in subprocess calls
2. Validate all file paths before operations
3. Add input sanitization for command arguments
4. Implement rate limiting for fuzzing operations
5. Add authentication for sensitive operations
6. Review and update `.gitleaks.toml` patterns
7. Regular dependency updates for security patches
