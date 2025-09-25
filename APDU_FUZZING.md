# APDU Fuzzing Usage

This document describes how to use the modular native APDU fuzzer integrated into GREENWIRE.

## Quick Start (Interactive Menu)

1. Run: `python greenwire.py --menu`
2. Navigate to Testing & Security -> APDU Fuzzing
3. Pick target (JCOP / NXP / EMV / All)
4. Choose iterations & mutation level
5. Optional: enable hardware mode if a PC/SC reader + card are present
6. Review summary + generated markdown report (native_apdu_fuzz_report_TIMESTAMP.md)

## Direct Programmatic Use

```python
from core.apdu_fuzzer import run_native_apdu_fuzz
session, report_path = run_native_apdu_fuzz(target_card="emv", iterations=200, mutation_level=4)
print(report_path)
```

## Parameters

| Parameter       | Description                                                     | Default |
|-----------------|-----------------------------------------------------------------|---------|
| target_card     | Target group: jcop / nxp / emv / all                            | all     |
| iterations      | Max commands to execute (may be fewer if mutations < iterations)| 500     |
| mutation_level  | Complexity (1-10) for field & data mutations                    | 5       |
| hardware_mode   | If reader present & opted, short APDUs are transmitted          | off     |

## Vulnerability Categories

- Unexpected Success (fuzzed command returned 9000)
- Potential Buffer Overflow (large payload accepted w/out length/status error)
- Information Disclosure (any response data provided)

## Safety in Hardware Mode

- Large (>220 bytes) payload APDUs skipped
- Long (extended) APDUs not generated yet
- All transmit exceptions captured and logged; fuzzing continues

## Extending

Add new base commands by updating methods in `NativeAPDUFuzzer` (`_get_jcop_commands`, etc.) or by subclassing and injecting custom command sets.

## Roadmap

- Parallel execution batches
- Differential session comparison (planned)

## Dedicated CLI Subcommand

You can run fuzzing directly without the interactive menu:

```bash
python greenwire.py apdu-fuzz --target emv --iterations 800 --mutation-level 6 --json-artifact --report-dir fuzz_reports
```

Flags:

- --target (jcop|nxp|emv|all)
- --iterations N
- --mutation-level 1-10
- --hardware (attempt first reader)
- --json-artifact (write structured session JSON)
- --report-dir DIR
- --verbose

## JSON Session Artifact

When enabled (menu option future / CLI flag), a JSON file captures:

- counts (commands, vulns, errors)
- vulnerability entries (command metadata without raw binary data)
- mode (SIMULATION / HARDWARE)
- timestamps

Binary payloads are hex-encoded when serialized.

## Extended APDU Support

Simulation mode now builds basic extended APDUs (00 LcHi LcLo) for payloads >255 bytes (up to 65535). Hardware mode still restricts to safe short APDUs (payload <= 220) to avoid compatibility issues.

## Timing Metrics

Per-command response times (ms) are recorded internally and summarized (average) in the markdown report (placeholder implementation—future enhancement will store per-command detail for statistical analysis).

## Percentiles & Distribution

The fuzzer now records every command response time and reports:

- Average (mean)
- P50 (median)
- P95 high percentile

Future: Add P99 and histogram bucketing.

## Stateful Sequence Fuzzing

Use `--stateful` with the `apdu-fuzz` subcommand to execute a second ordered pass across canonical EMV phases:

1. SELECT
2. GPO
3. READ RECORD
4. VERIFY PIN

Each phase gets light mutations; results are merged into the primary session statistics.

## Comparing Runs

Use `compare_fuzz_runs.py old.json new.json` to view vulnerability deltas and timing shifts across runs.

## Historical Dashboard

Run `python fuzz_dashboard.py` (or via the new dashboard menu entry) to aggregate all `native_apdu_fuzz_session_*.json` artifacts into `fuzz_dashboard_summary.md` with per-run metrics and vulnerability type counts.

- Extended APDUs & chaining
- Stateful / sequence-aware fuzzing
- Timing side-channel metrics
- Adaptive mutation scoring

## Configuration Center & Global Defaults

GREENWIRE now provides a unified persistent configuration layer shared across menu and CLI.

Global defaults live in `core/global_defaults.py` and are stored at runtime in `global_defaults.json` (auto-created at first use).

### Managed Keys

- verbose_default (bool): Default verbose flag for fuzzers/tools
- max_payload_default (int): Upper bound for auto-generated payload sizes (esp. hardware safe limit)
- stateful_default (bool): Whether to run secondary stateful fuzz phases by default
- artifact_dir_default (str): Base directory for reports and JSON artifacts

### Editing via Interactive Menu

1. Launch menu: `python greenwire.py --menu`
2. Choose `11. Configuration Center`
3. Adjust settings; they persist immediately to `global_defaults.json`.

### Editing via CLI

List current defaults:

```bash
python greenwire.py config-defaults --list
```

Update one or more defaults (examples):

```bash
python greenwire.py config-defaults --verbose-default false
python greenwire.py config-defaults --max-payload-default 300 --artifact-dir-default fuzz_artifacts
python greenwire.py config-defaults --stateful-default true
```

All unspecified keys retain their previous values.

### Interaction with apdu-fuzz

When a flag is omitted on the `apdu-fuzz` subcommand, the fuzzer falls back to the corresponding global default:

- `--verbose` omitted -> uses `verbose_default`
- payload limit logic references `max_payload_default`
- stateful secondary phase triggers when `--stateful` not passed but `stateful_default` is true
- report output directory uses `--report-dir` if given else `artifact_dir_default`

### Recommended Workflow

1. Set global policies once (e.g., larger payloads in simulation):
   `python greenwire.py config-defaults --max-payload-default 4096 --verbose-default false`
2. Run repeated fuzz sessions without re-specifying flags.
3. Adjust `artifact_dir_default` to keep outputs organized per project.

### Safety Notes

- Hardware mode still enforces internally safe short APDUs regardless of a very large `max_payload_default`.
- Invalid directories for `artifact_dir_default` are created automatically when possible; failures are warned but non-fatal.

---
Generated automatically; edit as needed.
