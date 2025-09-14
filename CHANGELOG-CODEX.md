# GREENWIRE Changes & AI Integration Notes

## For AI Models & Future Development

### Code Organization
- Core fuzzing logic in `core/fuzzer.py`
- Card utilities in `core/smartcard.py` 
- Analysis tools in `core/analysis.py`
- CLI interface in `greenwire.py`

### Key Functions
1. Card Operations:
   - `SmartcardFuzzer.identify()`: Card identification
   - `SmartcardFuzzer.test_cvm()`: CVM testing
   - `SmartcardFuzzer.fuzz_apdus()`: APDU fuzzing

2. Data Handling:
   - Database operations in `core/db.py`
   - Logging setup in `core/logger.py`
   - Result analysis in `core/analysis.py`

### CLI Structure
- All commands support `--dry-run`
- Consistent output formatting
- Proper error handling
- Clear user feedback

### Testing & Validation
- Run unit tests with `pytest`
- Verify CLI help with `--help`
- Check database with `--show-db`

### Notes for AI
- Respect existing error handling
- Maintain CLI consistency
- Update documentation
- Keep PEP 8 compliance
