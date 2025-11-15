# Documentation Status Matrix

Updated: 2025-11-15

This matrix covers the project-authored markdown that currently governs architecture, CLI behaviour, banking/HSM integration, and deployment. Vendor manuals embedded under `static/` and third-party READMEs are excluded from this pass.

| Document | Scope | Current State | Issues / Gaps | Action |
| --- | --- | --- | --- | --- |
| `ARCHITECTURE.md` | Legacy v2.0 architecture overview | Describes pre-refactor module layout and legacy CLI | Out of sync with modern CLI, banking extensions, and multithreaded roadmap | Replace with unified v5 architecture doc aligned to HSM/issuer pipeline |
| `CLI_MODERN_DOCUMENTATION.md` | GREENWIRE v4 CLI user guide | Detailed and current | Needs cross-links to new multithreaded services once implemented | Keep; update references after service rollout |
| `GREENWIRE_ANALYSIS.md` | Modern CLI analysis & integration plan | Current (v4.0) | Lacks multithreaded service alignment and ARQC flow | Extend to reference new orchestrator and hardware abstractions |
| `PROGRESS_V3.md` | Progress tracker for multithreaded rewrite | Missing from repo snapshot | Cannot verify content | Recreate concise progress log once architecture is updated |
| `CLEANUP_ENHANCEMENT_REPORT.md` | Historical cleanup summary | Present but outdated | No mention of banking/HSM pipeline | Replace with migration log once refactor begins |
| `STATIC_DEPLOYMENT.md` | Static bundle instructions | Largely accurate | Needs note about new services and dependency bundles | Refresh after pipeline refactor |
| `STATIC_DISTRIBUTION_INVENTORY.md` | Static assets inventory | Accurate snapshot | Update when new services add assets | Maintain |
| `docs/v4.md` | Unstructured notebook of ideas | Mixed relevance | Contains partial plans that contradict current direction | Extract relevant insights, archive remainder |
| `docs/PROJECT_OVERVIEW.md` | High-level project summary | Uses legacy nomenclature | Needs harmonisation with modern CLI terminology | Update after architecture rewrite |
| `docs/ADVANCED_FEATURES.md` | Feature catalogue | Mixed legacy and modern references | No coverage of ARQC/HSM chain | Revise to include new pipeline |
| `docs/ENGINEERING_MEMORY-2025-09-25.md` | Engineering log | Contains useful decisions | Needs tagging of obsolete action items | Keep as historical reference |
| `apdu4j_data/INTEGRATION_SUMMARY.md` | APDU4J integration | Still valid | None | Keep |
| `docs/JAVACARD_OFFLINE_SETUP.md` | JavaCard build | Valid | Add note about cap deployment into new pipeline | Update |
| `docs/SMART_DIAGNOSTIC_RESULTS.md` | Hardware diagnostic outputs | Stale snapshots | Should be regenerated once new orchestrator available | Mark as archive |

## Next Steps

1. Draft `docs/ARCHITECTURE_V5_MULTITHREADED.md` describing the end-to-end HSM → Issuer → Personalization → Merchant → Transaction → ARQC verification pipeline with emulator/hardware toggle.
2. Update `GREENWIRE_ANALYSIS.md` and `CLI_MODERN_DOCUMENTATION.md` to reference the new services once implemented.
3. Archive or delete superseded historical docs after extracting any remaining actionable tasks.
