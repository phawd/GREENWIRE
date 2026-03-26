# GREENWIRE Archive Manifest

Generated: 2025-09-10

This archive contains dead code removed from the active GREENWIRE codebase.
**Nothing here was deleted — files were moved only.**

---

## ⚠️ Import Notes

Three archived scripts are still lazily imported (via `try/except ImportError`) in the active codebase.
These features will show an import error at runtime if invoked, but will **not** crash the application.
Do NOT delete these from the archive without first removing or updating the relevant imports.

| Archived File | Referenced In | Context |
|---|---|---|
| `root_scripts/tool_audit.py` | `greenwire.py` lines 6451, 6460, 9356 | Lazy import inside functions, caught by `except Exception` |
| `root_scripts/emv_nfc_verify.py` | `greenwire.py` lines 9374–9375 | Lazy import used to build subprocess command |
| `root_scripts/enhanced_data_extraction.py` | `menu_implementations.py` line 1987 | Lazy import inside `enhanced_data_extraction_working()`, caught by `except ImportError` |

---

## .bak Files (Backup Copies)

These are backup copies created during refactoring. The canonical live versions remain at their original paths (without the `.bak` extension).

| Archived Path | Original Location | Reason |
|---|---|---|
| `bak_files/apdu4j_data/apdu_commands.py.bak` | `apdu4j_data/apdu_commands.py` | Backup copy from refactoring |
| `bak_files/apdu4j_data/apdu4j_cli.py.bak` | `apdu4j_data/apdu4j_cli.py` | Backup copy from refactoring |
| `bak_files/apdu4j_data/apdu4j_integration.py.bak` | `apdu4j_data/apdu4j_integration.py` | Backup copy from refactoring |
| `bak_files/apdu4j_data/gp_commands.py.bak` | `apdu4j_data/gp_commands.py` | Backup copy from refactoring |
| `bak_files/apdu4j_data/test_apdu4j.py.bak` | `apdu4j_data/test_apdu4j.py` | Backup copy from refactoring |
| `bak_files/cli/__init__.py.bak` | `cli/__init__.py` | Backup copy from refactoring |
| `bak_files/cli/argument_parser.py.bak` | `cli/argument_parser.py` | Backup copy from refactoring |
| `bak_files/cli/command_router.py.bak` | `cli/command_router.py` | Backup copy from refactoring |
| `bak_files/core/advanced_fuzzing.py.bak` | `core/advanced_fuzzing.py` | Backup copy from refactoring |
| `bak_files/core/ai_vuln_testing.py.bak` | `core/ai_vuln_testing.py` | Backup copy from refactoring |
| `bak_files/core/android_manager.py.bak` | `core/android_manager.py` | Backup copy from refactoring |
| `bak_files/core/apdu_fuzzer.py.bak` | `core/apdu_fuzzer.py` | Backup copy from refactoring |
| `bak_files/core/cap_manager.py.bak` | `core/cap_manager.py` | Backup copy from refactoring |
| `bak_files/core/card_standards.py.bak` | `core/card_standards.py` | Backup copy from refactoring |
| `bak_files/core/config.py.bak` | `core/config.py` | Backup copy from refactoring |
| `bak_files/core/emv_processor.py.bak` | `core/emv_processor.py` | Backup copy from refactoring |
| `bak_files/core/global_defaults.py.bak` | `core/global_defaults.py` | Backup copy from refactoring |
| `bak_files/core/greenwire_bridge.py.bak` | `core/greenwire_bridge.py` | Backup copy from refactoring |
| `bak_files/core/imports.py.bak` | `core/imports.py` | Backup copy from refactoring |
| `bak_files/core/logging_system.py.bak` | `core/logging_system.py` | Backup copy from refactoring |
| `bak_files/core/menu_system.py.bak` | `core/menu_system.py` | Backup copy from refactoring |
| `bak_files/core/nfc_manager.py.bak` | `core/nfc_manager.py` | Backup copy from refactoring |
| `bak_files/core/utils/__init__.py.bak` | `core/utils/__init__.py` | Backup copy from refactoring |
| `bak_files/core/utils/data.py.bak` | `core/utils/data.py` | Backup copy from refactoring |
| `bak_files/core/utils/encoding.py.bak` | `core/utils/encoding.py` | Backup copy from refactoring |
| `bak_files/core/utils/logging.py.bak` | `core/utils/logging.py` | Backup copy from refactoring |
| `bak_files/emv_data_integrator.py.bak` | `emv_data_integrator.py` (root) | Backup copy from refactoring |
| `bak_files/emv_data_translator.py.bak` | `emv_data_translator.py` (root) | Backup copy from refactoring |
| `bak_files/emv_data_verification.py.bak` | `emv_data_verification.py` (root) | Backup copy from refactoring |
| `bak_files/emv_data/__init__.py.bak` | `emv_data/__init__.py` | Backup copy from refactoring |
| `bak_files/emv_data/commands/__init__.py.bak` | `emv_data/commands/__init__.py` | Backup copy from refactoring |
| `bak_files/emv_data/commands/emv_commands.py.bak` | `emv_data/commands/emv_commands.py` | Backup copy from refactoring |
| `bak_files/emv_data/commands/hsm_commands.py.bak` | `emv_data/commands/hsm_commands.py` | Backup copy from refactoring |
| `bak_files/emv_data/emv_integration.py.bak` | `emv_data/emv_integration.py` | Backup copy from refactoring |
| `bak_files/emv_data/test_emv.py.bak` | `emv_data/test_emv.py` | Backup copy from refactoring |
| `bak_files/emv_nfc_verify.py.bak` | `emv_nfc_verify.py` (root) | Backup copy from refactoring |
| `bak_files/enhanced_emv_translator.py.bak` | `enhanced_emv_translator.py` (root) | Backup copy from refactoring |
| `bak_files/final_translation_cleanup.py.bak` | `final_translation_cleanup.py` (root) | Backup copy from refactoring |
| `bak_files/greenwire.py.bak` | `greenwire.py` | Backup copy from refactoring |
| `bak_files/greenwire/__init__.py.bak` | `greenwire/__init__.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/backend.py.bak` | `greenwire/core/backend.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/crypto_engine.py.bak` | `greenwire/core/crypto_engine.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/emv_generator.py.bak` | `greenwire/core/emv_generator.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/file_fuzzer.py.bak` | `greenwire/core/file_fuzzer.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/fuzzer.py.bak` | `greenwire/core/fuzzer.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/nfc_emv.py.bak` | `greenwire/core/nfc_emv.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/nfc_iso.py.bak` | `greenwire/core/nfc_iso.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/real_world_card_issuer.py.bak` | `greenwire/core/real_world_card_issuer.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/symm_analysis.py.bak` | `greenwire/core/symm_analysis.py` | Backup copy from refactoring |
| `bak_files/greenwire/core/test_crypto_engine.py.bak` | `greenwire/core/test_crypto_engine.py` | Backup copy from refactoring |
| `bak_files/greenwire/emulator.py.bak` | `greenwire/emulator.py` | Backup copy from refactoring |
| `bak_files/greenwire/logger.py.bak` | `greenwire/logger.py` | Backup copy from refactoring |
| `bak_files/greenwire/menu_cli.py.bak` | `greenwire/menu_cli.py` | Backup copy from refactoring |
| `bak_files/greenwire/nfc_vuln.py.bak` | `greenwire/nfc_vuln.py` | Backup copy from refactoring |
| `bak_files/greenwire/test_logger.py.bak` | `greenwire/test_logger.py` | Backup copy from refactoring |
| `bak_files/greenwire/tree_menu_cli.py.bak` | `greenwire/tree_menu_cli.py` | Backup copy from refactoring |
| `bak_files/menu_handlers.py.bak` | `menu_handlers.py` | Backup copy from refactoring |
| `bak_files/menu_implementations.py.bak` | `menu_implementations.py` | Backup copy from refactoring |
| `bak_files/modules/android_nfc.py.bak` | `modules/android_nfc.py` | Backup copy from refactoring |
| `bak_files/modules/atm_emulator.py.bak` | `modules/atm_emulator.py` | Backup copy from refactoring |
| `bak_files/modules/crypto/__init__.py.bak` | `modules/crypto/__init__.py` | Backup copy from refactoring |
| `bak_files/modules/crypto/aes.py.bak` | `modules/crypto/aes.py` | Backup copy from refactoring |
| `bak_files/modules/crypto/emv_crypto.py.bak` | `modules/crypto/emv_crypto.py` | Backup copy from refactoring |
| `bak_files/modules/crypto/hashes.py.bak` | `modules/crypto/hashes.py` | Backup copy from refactoring |
| `bak_files/modules/crypto/key_manager.py.bak` | `modules/crypto/key_manager.py` | Backup copy from refactoring |
| `bak_files/modules/crypto/primitives.py.bak` | `modules/crypto/primitives.py` | Backup copy from refactoring |
| `bak_files/modules/crypto/rsa.py.bak` | `modules/crypto/rsa.py` | Backup copy from refactoring |
| `bak_files/modules/emulation.py.bak` | `modules/emulation.py` | Backup copy from refactoring |
| `bak_files/modules/greenwire_crypto_fuzzer.py.bak` | `modules/greenwire_crypto_fuzzer.py` | Backup copy from refactoring |
| `bak_files/modules/greenwire_emv_compliance.py.bak` | `modules/greenwire_emv_compliance.py` | Backup copy from refactoring |
| `bak_files/modules/greenwire_key_manager.py.bak` | `modules/greenwire_key_manager.py` | Backup copy from refactoring |
| `bak_files/modules/greenwire_log_viewer.py.bak` | `modules/greenwire_log_viewer.py` | Backup copy from refactoring |
| `bak_files/modules/greenwire_protocol_logger.py.bak` | `modules/greenwire_protocol_logger.py` | Backup copy from refactoring |
| `bak_files/modules/greenwire_pyapdu_fuzzer.py.bak` | `modules/greenwire_pyapdu_fuzzer.py` | Backup copy from refactoring |
| `bak_files/modules/merchant_emulator.py.bak` | `modules/merchant_emulator.py` | Backup copy from refactoring |
| `bak_files/modules/nfc/__init__.py.bak` | `modules/nfc/__init__.py` | Backup copy from refactoring |
| `bak_files/modules/nfc/core.py.bak` | `modules/nfc/core.py` | Backup copy from refactoring |
| `bak_files/modules/nfc/emulation.py.bak` | `modules/nfc/emulation.py` | Backup copy from refactoring |
| `bak_files/modules/nfc/protocols.py.bak` | `modules/nfc/protocols.py` | Backup copy from refactoring |
| `bak_files/modules/production_crypto_engine.py.bak` | `modules/production_crypto_engine.py` | Backup copy from refactoring |
| `bak_files/modules/ui/__init__.py.bak` | `modules/ui/__init__.py` | Backup copy from refactoring |
| `bak_files/modules/ui/colors.py.bak` | `modules/ui/colors.py` | Backup copy from refactoring |
| `bak_files/modules/ui/menu.py.bak` | `modules/ui/menu.py` | Backup copy from refactoring |
| `bak_files/setup.py.bak` | `setup.py` | Backup copy from refactoring |
| `bak_files/test_emv.py.bak` | `test_emv.py` (root) | Backup copy from refactoring |
| `bak_files/tests/conftest.py.bak` | `tests/conftest.py` | Backup copy from refactoring |
| `bak_files/tool_audit.py.bak` | `tool_audit.py` (root) | Backup copy from refactoring |
| `bak_files/tools/update_engineering_memory.py.bak` | `tools/update_engineering_memory.py` | Backup copy from refactoring |
| `bak_files/tools/verify_java_static_setup.py.bak` | `tools/verify_java_static_setup.py` | Backup copy from refactoring |

**Total: 89 .bak files**

---

## Root One-Off Scripts

These scripts were used for one-time maintenance or data-processing operations and are not part of the active framework.

> ⚠️ **Three of these are still lazily imported** — see the Import Notes section above.

| File | Lines | Original Location | Reason |
|---|---|---|---|
| `root_scripts/verify_static.py` | 79 | `verify_static.py` | One-off: verifies static distribution integrity |
| `root_scripts/final_verification.py` | 22 | `final_verification.py` | One-off: post-refactor verification script |
| `root_scripts/final_translation_cleanup.py` | 163 | `final_translation_cleanup.py` | One-off: translation cleanup during data migration |
| `root_scripts/lint_and_consolidate.py` | 327 | `lint_and_consolidate.py` | One-off: linting/consolidation utility |
| `root_scripts/tool_audit.py` | 95 | `tool_audit.py` | One-off audit script — **⚠️ still lazily imported in `greenwire.py`** |
| `root_scripts/emv_data_integrator.py` | 756 | `emv_data_integrator.py` | One-off: EMV dataset integration script |
| `root_scripts/emv_data_translator.py` | 227 | `emv_data_translator.py` | One-off: EMV data translation utility |
| `root_scripts/emv_data_verification.py` | 92 | `emv_data_verification.py` | One-off: EMV data verification script |
| `root_scripts/emv_nfc_verify.py` | 471 | `emv_nfc_verify.py` | One-off NFC verify script — **⚠️ still lazily imported in `greenwire.py`** |
| `root_scripts/enhanced_data_extraction.py` | 1143 | `enhanced_data_extraction.py` | One-off extraction tool — **⚠️ still lazily imported in `menu_implementations.py`** |
| `root_scripts/enhanced_emv_translator.py` | 263 | `enhanced_emv_translator.py` | One-off: enhanced EMV translation utility |

**Total: 11 root scripts**

---

## AI Session Data

SQLite databases containing AI learning session logs accumulated during development. Not required for runtime operation.

| File | Original Location | Reason |
|---|---|---|
| `ai_sessions/hsm_atm_knowledge.db` | `ai_learning_sessions/hsm_atm_knowledge.db` | AI learning session data — HSM/ATM knowledge base |
| `ai_sessions/learning_sessions.db` | `ai_learning_sessions/learning.db` | AI learning session log database |
| `ai_sessions/knowledge_base.db` | `ai_knowledge_base/learning.db` | AI knowledge base SQLite database |

**Total: 3 database files**

---

## Deleted Files

| File | Reason |
|---|---|
| `file_inventory.csv` | Transient inventory file, not part of the codebase |
