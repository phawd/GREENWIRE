# Wireless Emulator Kernels

Purpose: define emulator wireless kernels built from merchant and HSM operational needs, rather than proprietary scheme Level 2 implementations.

## What These Kernels Are

These are emulator policy kernels for:

- merchant decision flow
- HSM and issuer-host expectations
- ATM/wireless routing posture
- AI mutation and anomaly focus

They are not replacements for licensed payment-scheme kernels.

## Available Kernels

### `gw_retail_bridge`

- retail wallet and contactless acceptance
- CDCVM-friendly
- offline/online mix suitable for merchant test labs

### `gw_transit_wave`

- fast tap and replay-sensitive transit flows
- RFID-aware
- online-biased risk handling

### `gw_secure_vault`

- HSM-centric secure-channel and issuer-script focus
- SCP03-oriented posture
- aggressive online authorization bias

### `gw_lab_chaos`

- mutation-heavy research mode
- broad channel coverage across NFC, RFID, GP, JCOP, ATM, merchant
- intended for AI-assisted anomaly testing

## CLI Examples

List kernels:

```powershell
python greenwire_modern.py wireless-kernel list --format json
```

Show one kernel:

```powershell
python greenwire_modern.py wireless-kernel show --profile gw_secure_vault
```

Infer from merchant/HSM context:

```powershell
python greenwire_modern.py wireless-kernel infer --scheme visa --merchant-mode transit --channel rfid
python greenwire_modern.py wireless-kernel infer --scheme visa --hsm-mode scp03 --channel gp
```

Simulate merchant/HSM decisioning:

```powershell
python greenwire_modern.py wireless-kernel simulate --profile gw_retail_bridge --amount-cents 1250 --channel nfc --cdcvm
python greenwire_modern.py wireless-kernel simulate --profile gw_transit_wave --amount-cents 275 --channel rfid
python greenwire_modern.py wireless-kernel simulate --profile gw_secure_vault --amount-cents 9999 --channel merchant --force-online
python greenwire_modern.py wireless-kernel simulate --profile gw_lab_chaos --amount-cents 3333 --channel gp --force-online
```

## AI Testing Relevance

The AI testing path now uses wireless-kernel context to bias:

- seed corpus expansion
- mutation focus
- merchant/HSM anomaly targeting

Relevant code:

- [core/ai_vuln_testing.py](F:/repo/GREENWIRE/core/ai_vuln_testing.py)
- [modules/ai_test_generator.py](F:/repo/GREENWIRE/modules/ai_test_generator.py)
- [core/wireless_kernel_profiles.py](F:/repo/GREENWIRE/core/wireless_kernel_profiles.py)

Related documentation:

- [KERNEL_CARD_WRITING_DIFFERENCES.md](F:/repo/GREENWIRE/docs/KERNEL_CARD_WRITING_DIFFERENCES.md)
