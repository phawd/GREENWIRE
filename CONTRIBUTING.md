# Contributing to GREENWIRE

Thanks for contributing. This short guide explains local pre-commit checks and basic PR hygiene for this repository.

## Pre-commit (local checks)

Install pre-commit and enable hooks:

```bash
pip install pre-commit
pre-commit install
```

Run pre-commit on all files (useful before a PR):

```bash
pre-commit run --all-files
```

### What the hooks do

- ruff --fix: fast linting and many automatic fixes
- black: code formatting
- isort: import sorting
- end-of-file-fixer and trailing-whitespace: whitespace corrections

## CI and PR guidance

The repository runs a CI workflow with two primary jobs: `CI / Lint` and `CI / Tests`.

Keep changes small and focused; run the Pre-PR checklist in `.github/copilot-instructions.md`.

Use `--non-interactive` CLI flags when adding automated test cases.

## How to handle operator prompts in CI

CLI features that require operator interaction must accept `--non-interactive` and other `--prod-*` flags so CI can exercise them.

Use `core.operator_mode.ask_operator_mode(args)` in code paths that may need operator decisions; this helper is idempotent and will respect `args.non_interactive`.

## When to open a PR

All tests should pass locally and on CI.

Include a short verification checklist in the PR description for any manual steps (device attached, gp.jar path, CA keys).

Thanks for improving GREENWIRE!