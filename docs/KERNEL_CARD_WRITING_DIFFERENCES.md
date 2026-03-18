# Kernel Card-Writing Differences and Configurable Settings

Updated: 2026-03-18

Purpose: document each EMV contactless kernel in GREENWIRE kernel mapping and show what differs between them when writing cards, plus which settings are currently configurable.

## Source of Truth in Code

- `core/emv_kernel_registry.py` (C-2..C-8 mapping)
- `commands/card_commands.py` (`card-create`, `mutant-card` write paths)
- `modules/emvco_card_personalizer.py` (EMVCo TLV/card-interface write path)
- `core/synthetic_identity.py` (scheme PAN/CVV/issuer generation defaults)

## Kernel Write-Support Matrix

| Kernel | Scheme Mapping | Current Card-Writing Support in Repo | Key Differences You Should Expect | Settings That Can Differ |
|---|---|---|---|---|
| C-2 | Mastercard (RID `A000000004`) | `card-create`, `mutant-card`, EMVCo personalizer | 16-digit PAN profile, Mastercard-oriented AID/kernel inference | `card_type=mastercard`, `bin_prefix`, `length`, `expiry`, `cvv`, `issuer`, `contactless_limit`, `cvm_limit`, merchant/HSM/ATM context flags |
| C-3 | Visa (RID `A000000003`) | `card-create`, `mutant-card`, EMVCo personalizer | 16-digit PAN profile, Visa AID defaults, base for secure-vault profile decisions | `card_type=visa`, `bin_prefix`, `length`, `expiry`, `cvv`, `issuer`, `contactless_limit`, `cvm_limit`, wireless profile/routing knobs |
| C-4 | Amex (RID `A000000025`) | `card-create`, `mutant-card`, EMVCo personalizer | 15-digit PAN and 4-digit CVV profile | `card_type=amex`, `length` (typically 15), `cvv` (typically 4), `issuer`, CVM/floor/risk settings |
| C-5 | JCB (RID `A000000065`) | EMVCo personalizer write path only (direct CLI test-card generation includes JCB) | Registry maps to Kernel 5; current synthetic issuer profile falls back to Visa-like defaults unless explicit values are supplied | `card_type=JCB` in personalizer JSON, explicit `PAN`, `CVV`, `service_code`, `contactless_limit`, `cvm_limit` recommended |
| C-6 | Discover (RID `A000000152` / `A000000324`) | `card-create`, `mutant-card`, EMVCo personalizer | 16-digit PAN profile with Discover mapping | `card_type=discover`, `bin_prefix`, `length`, `expiry`, `cvv`, issuer/risk/CVM/floor controls |
| C-7 | CUP/UnionPay (RID `A000000333`) | Registry/inference exists; full writer parity is partial | Kernel inference supports C-7, but writer defaults are not fully scheme-specialized (explicit card data overrides are required) | Manual card JSON values for `PAN`, `card_type`, AID-related payload, CVM/floor/risk settings; avoid relying on defaults |
| C-8 | Shared EMVCo kernel | Used as generic/default kernel baseline and by multiple wireless profiles | Shared-kernel path for cross-scheme test posture and generic PPSE-first behavior | Profile-level settings: channel, amount, CVM mode, force-online, fallback/risk windows, HSM session-key mode |

## Configurable Settings by Card-Write Path

### 1) `card-create` command (`commands/card_commands.py`)

Primary kernel-relevant settings:

- Scheme and identity: `--card-type`, `--pan` or `--generate-pan`, `--bin-prefix`, `--length`, `--issuer`, `--name`
- Expiry/security fields: `--expiry`, `--cvv`, `--pin`
- EMV/crypto payload inclusion: `--emv-data`, `--crypto-keys`
- Merchant/terminal context (affects downstream kernel-like decision behavior): `--merchant-id`, `--terminal-id`, `--mcc`, `--acquirer-id`, `--country-code`, `--currency`, `--validate-atm`
- Interface behavior: `--nfc`, `--no-nfc`, `--rfid`, `--no-rfid`
- Key/test policy: `--key-profile`, `--test-function` (or `card-create-test` command)

### 2) `mutant-card` command (`commands/mutant_card_commands.py`)

Kernel-adjacent runtime settings:

- Base card settings: `--card-type`, `--pan`, `--expiry`, `--cvv`, `--pin`, `--issuer`, `--name`, `--length`, `--atc`
- Decision behavior controls: `--floor-limit`, `--cvm-method`, `--mutation-profile`
- Execution channel for behavior differences: `--mode merchant|atm`, `--amount`

### 3) EMVCo personalizer write path (`modules/emvco_card_personalizer.py`)

Card JSON fields that determine kernel-relevant data written to card:

- Required identity: `PAN`, `expiry_date`, `card_type`
- Security/transaction fields: `CVV`, `service_code`
- Country/currency context: `country_code`, `currency_code`
- Contactless behavior: `contactless_limit`, `cvm_limit`
- Derived kernel metadata in RFID block: `kernel_config.kernel_id` inferred from scheme mapping

## Practical Differences to Document Per Kernel

For each kernel test plan, record at least these differences:

- AID/RID family and scheme routing identity
- PAN/CVV format expectations (for example Amex vs others)
- CVM threshold behavior (`cvm_limit`, CVM method, CDCVM enablement)
- Floor-limit and online/offline routing behavior
- ATM enablement and force-online posture
- HSM session behavior expectations (`session_key_mode`, script window, ARQC strictness)

## Current Gaps and Operator Guidance

- C-7 (CUP) and C-5 (JCB) are represented in kernel registry, but default issuer/profile generation is strongest for Visa/Mastercard/Amex/Discover.
- For C-5/C-7 scenarios, provide explicit card fields in input JSON instead of relying on defaults.
- Treat C-8 as a shared/generic profile baseline, then layer merchant/HSM/ATM profile settings for the target environment.

## Minimal Operator Checklist Per Kernel

1. Select kernel/scheme target (C-2..C-8).
2. Set explicit PAN/CVV/issuer values when not using the fully supported default scheme paths.
3. Set CVM and floor limits for the intended channel (merchant/ATM/contactless).
4. Set country/currency/acquirer context for host realism.
5. Validate with `card-read`, `card-read-full`, and `card-history` after write/execution.
