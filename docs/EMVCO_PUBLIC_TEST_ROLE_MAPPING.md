# Public EMVCo Test Role Mapping

Research date: March 18, 2026

Purpose: map public EMVCo documents to practical testing roles in this repository.

Roles used here:

- issuer-host
- merchant-terminal
- HSM / issuer crypto
- L2 terminal / kernel
- L3 transaction / end-to-end

## Mapping Matrix

| Document | Issuer-Host | Merchant | HSM | L2 | L3 | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Contactless Product Approval Process | Medium | High | Low | High | Medium | Best public process map for contactless kernel-related work |
| Contact Kernel Approval Process | Low | High | Low | High | Low | Contact terminal L2 orientation |
| Book C-8 Test Cases | Medium | High | Medium | High | Medium | Most actionable shared-kernel test material |
| Kernel FAQ | Medium | Medium | Medium | Medium | Low | Best for architecture and role boundaries |
| Contactless Book A/B Test Plan | Low | High | Low | High | Low | Terminal environment and reader-side expectations |
| Contactless Admin Process | Low | Medium | Low | Medium | Low | Process alignment rather than detailed test content |
| Kernel ICS files | Low | High | Low | High | Low | Capability declaration and coverage matrix material |
| TTA bulletins | Low | Medium | Low | Medium | Low | Version and release-state tracking |
| PICC analogue / digital cases | Low | Medium | Low | Medium | Low | Lowest-level wireless/PICC work |

## Role-by-Role Guidance

### Issuer-Host

Most useful public docs:

1. Contactless Product Approval Process
2. Book `C-8` Test Cases
3. Kernel FAQ

Why:

- they explain how terminal-side kernel behavior affects the data the issuer host sees
- they help interpret CVM, routing, and online/offline assumptions before host-side emulator work begins

Repository mapping:

- [commands/issuer_pipeline.py](F:/repo/GREENWIRE/commands/issuer_pipeline.py)
- [core/pipeline_services.py](F:/repo/GREENWIRE/core/pipeline_services.py)
- [core/wireless_kernel_profiles.py](F:/repo/GREENWIRE/core/wireless_kernel_profiles.py)

### Merchant-Terminal

Most useful public docs:

1. Contactless Product Approval Process
2. Contactless Book A/B Test Plan
3. Kernel ICS files
4. Book `C-8` Test Cases

Why:

- merchant-terminal work is where public kernel and ICS materials are strongest
- this is the best-supported role from public EMVCo material

Repository mapping:

- [modules/merchant_emulator.py](F:/repo/GREENWIRE/modules/merchant_emulator.py)
- [commands/wallet_commands.py](F:/repo/GREENWIRE/commands/wallet_commands.py)
- [commands/wireless_kernel_commands.py](F:/repo/GREENWIRE/commands/wireless_kernel_commands.py)

### HSM / Issuer Crypto

Most useful public docs:

1. Kernel FAQ
2. Contactless Product Approval Process
3. Book `C-8` Test Cases

Why:

- public EMVCo material does not expose the full issuer-side cryptographic detail a payment network would
- but it does show the terminal-side and shared-kernel assumptions that shape ARQC and CVM-related observations

Repository mapping:

- [core/hsm_service.py](F:/repo/GREENWIRE/core/hsm_service.py)
- [core/globalplatform_reference.py](F:/repo/GREENWIRE/core/globalplatform_reference.py)
- [commands/gp_commands.py](F:/repo/GREENWIRE/commands/gp_commands.py)

### Level 2 Terminal / Kernel

Most useful public docs:

1. Contactless Product Approval Process
2. Contact Kernel Approval Process
3. Book `C-8` Test Cases
4. Kernel ICS files
5. Contactless Book A/B Test Plan

Why:

- this is the role best covered by public EMVCo material
- it directly informs terminal kernel configuration, reader capability coverage, and emulator-kernel design

Repository mapping:

- [core/emv_kernel_registry.py](F:/repo/GREENWIRE/core/emv_kernel_registry.py)
- [core/wireless_kernel_profiles.py](F:/repo/GREENWIRE/core/wireless_kernel_profiles.py)
- [core/ai_vuln_testing.py](F:/repo/GREENWIRE/core/ai_vuln_testing.py)

### Level 3 Transaction / End-to-End

Most useful public docs:

1. Contactless Product Approval Process
2. Book `C-8` Test Cases
3. Kernel FAQ
4. relevant bulletins for current release assumptions

Why:

- public L3 material is thinner than public L2/process material
- the repository therefore uses public EMVCo process and kernel material as scaffolding, then layers emulator issuer-host and merchant-terminal behavior on top

Repository mapping:

- [commands/issuer_pipeline.py](F:/repo/GREENWIRE/commands/issuer_pipeline.py)
- [greenwire/core/smart_vulnerability_card.py](F:/repo/GREENWIRE/greenwire/core/smart_vulnerability_card.py)
- [commands/wallet_commands.py](F:/repo/GREENWIRE/commands/wallet_commands.py)

## Recommended Document Selection by Task

If the task is:

- kernel selection or terminal capability coverage: start with ICS and process docs
- shared-kernel test shaping: start with `C-8` test cases and FAQ
- historical release drift: start with TTA bulletins
- issuer-host impact analysis: start with process docs, then apply repository issuer/HSM emulation paths

## Sources

- [EMVCO_BEST_TESTING_DOCS.md](F:/repo/GREENWIRE/docs/EMVCO_BEST_TESTING_DOCS.md)
- [emvco_public_archive_harvest_2026-03-18.json](F:/repo/GREENWIRE/docs/sources/emvco_public_archive_harvest_2026-03-18.json)
