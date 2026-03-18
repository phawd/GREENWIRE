# Best EMVCo Testing Documents

Research date: March 18, 2026

Purpose: rank the most useful public EMVCo testing documents and public resource pages for issuer-host, merchant-terminal, HSM, Level 2, and Level 3 work in this repository.

Related inventories:

- [emvco_public_archive_harvest_2026-03-18.json](F:/repo/GREENWIRE/docs/sources/emvco_public_archive_harvest_2026-03-18.json)
- [EMVCO_PUBLIC_TEST_ROLE_MAPPING.md](F:/repo/GREENWIRE/docs/EMVCO_PUBLIC_TEST_ROLE_MAPPING.md)

## Ranking Method

Documents rank higher when they:

1. are public and directly reachable
2. explain real testing process or test-environment assumptions
3. map clearly to terminal, issuer-host, or certification work
4. help align emulator behavior with public testing structures

## Ranked List

### 1. Contactless Product Approval Process

Source:

- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)

Why it ranks first:

- it is the clearest public map of contactless approval structure
- it explicitly ties together Books A/B, kernels `C-2` through `C-8`, ICS, test plans, and approval workflow
- it is the best public anchor for understanding where scheme-managed kernel testing stops and EMVCo-managed testing begins

Best use:

- merchant terminal planning
- Level 2 alignment
- deciding which kernel/process documents matter next

### 2. Contact Kernel Approval Process

Source:

- [EMVCo Contact Kernel Approval Process](https://www.emvco.com/processes/contact-kernel-approval-process/)

Why it ranks highly:

- it is the best public process reference for contact Level 2 work
- it helps keep contact and contactless testing assumptions separated

Best use:

- contact terminal L2 work
- terminal roadmap and certification planning

### 3. EMV Book C-8 Test Cases

Local source:

- [EMV-Book-C-8-Test-Cases-v1.1c_251021.pdf](F:/repo/GREENWIRE/docs/EMV-Book-C-8-Test-Cases-v1.1c_251021.pdf)

Why it ranks highly:

- it is directly actionable for shared-kernel testing
- it provides the strongest public test-case material in the contactless kernel area currently held in the repo

Best use:

- shared-kernel emulator alignment
- terminal test harness design
- AI seed selection for contactless flows

### 4. EMV Contactless Kernel FAQ

Local source:

- [EMV®-Contactless-Kernel-Specification-FAQ.pdf](F:/repo/GREENWIRE/docs/EMV®-Contactless-Kernel-Specification-FAQ.pdf)

Public anchor:

- [EMVCo Kernel FAQ landing page](https://www.emvco.com/resources/faq-emv-contactless-kernel-general-questions/)

Why it ranks highly:

- it explains the shared-kernel initiative in public terms
- it is useful for interpreting what the common kernel does and does not replace

Best use:

- architectural orientation
- merchant and issuer-host planning

### 5. Contactless Book A/B Test Plan

Local source:

- [EMVCo_TTA_Contactless_Book_AB_Test_plan_v211c.r_250917.pdf](F:/repo/GREENWIRE/docs/EMVCo_TTA_Contactless_Book_AB_Test_plan_v211c.r_250917.pdf)

Why it ranks highly:

- it helps anchor terminal and environment assumptions around contactless testing
- it complements the kernel-specific materials well

Best use:

- terminal environment configuration
- reader capability expectations

### 6. Contactless Administrative Process

Local source:

- [EMVCo_TTA_Contactless_Admin_Process_v211c.r_250917.pdf](F:/repo/GREENWIRE/docs/EMVCo_TTA_Contactless_Admin_Process_v211c.r_250917.pdf)

Why it matters:

- process-heavy, but useful for understanding what the test harness is supposed to support
- helps separate operational paperwork from technical test vectors

Best use:

- certification-readiness planning
- lab governance and release alignment

### 7. Kernel ICS Documents (`C-2` through `C-8`)

Local sources:

- [EMVCo_TTA_Contactless_C2_ICS_v211_240314.pdf](F:/repo/GREENWIRE/docs/EMVCo_TTA_Contactless_C2_ICS_v211_240314.pdf)
- [EMVCo_TTA_Contactless_C3_ICS_v29a_230809.pdf](F:/repo/GREENWIRE/docs/EMVCo_TTA_Contactless_C3_ICS_v29a_230809.pdf)
- [EMVCo_TTA_Contactless_C4_ICS_v210_230921.pdf](F:/repo/GREENWIRE/docs/EMVCo_TTA_Contactless_C4_ICS_v210_230921.pdf)
- [EMVCo_TTA_Contactless_C5_ICS_v211_250930_EDIT.pdf](F:/repo/GREENWIRE/docs/EMVCo_TTA_Contactless_C5_ICS_v211_250930_EDIT.pdf)
- [EMVCo_TTA_Contactless_C6_ICS_v211a_260126.pdf](F:/repo/GREENWIRE/docs/EMVCo_TTA_Contactless_C6_ICS_v211a_260126.pdf)
- [EMVCo_TTA_Contactless_C7_ICS_v211a_240329-1.pdf](F:/repo/GREENWIRE/docs/EMVCo_TTA_Contactless_C7_ICS_v211a_240329-1.pdf)
- [EMVCo_TTA_Contactless_C8_ICS_v11b_250711.pdf](F:/repo/GREENWIRE/docs/EMVCo_TTA_Contactless_C8_ICS_v11b_250711.pdf)

Why they rank here:

- they are extremely useful for terminal/kernel feature coverage
- they are not as self-explanatory as the process docs, so they rank slightly lower as starting points

Best use:

- kernel capability matrices
- terminal configuration coverage
- mapping AI scenarios to declared feature sets

### 8. TTA Bulletins on Contactless Releases and Kernel Approval

Local/public sources:

- [TTA_Bulletin_No_279_1st_Ed_C8_approval_incentives_240917.pdf](F:/repo/GREENWIRE/docs/TTA_Bulletin_No_279_1st_Ed_C8_approval_incentives_240917.pdf)
- [TTA Bulletin n284](https://www.emvco.com/resources/tta-bulletin-n284-contactless-product-test-release-2-11c-v2/)
- [TTA Bulletin n290](https://www.emvco.com/resources/tta-bulletin-n290-contact-terminal-level-2-type-approval/)

Why they matter:

- they are version and release signals more than direct test specs
- they are still useful for knowing when assumptions changed

Best use:

- dating environment assumptions
- test-plan version tracking

### 9. PICC Analogue and Digital Test Cases

Local sources:

- [PICC-Analogue-Test-Bench-and-Test-Cases-v3.0b.r-_251114.pdf](F:/repo/GREENWIRE/docs/PICC-Analogue-Test-Bench-and-Test-Cases-v3.0b.r-_251114.pdf)
- [PICC-Digital-Test-Cases-v3.2b.r_20250918-1.pdf](F:/repo/GREENWIRE/docs/PICC-Digital-Test-Cases-v3.2b.r_20250918-1.pdf)

Why they matter:

- they are relevant for low-level wireless behavior
- they are less directly useful for issuer-host/HSM work than the process and kernel materials

Best use:

- reader/PICC lab work
- low-level wireless emulation and timing studies

## Recommended Reading Order

1. Contactless Product Approval Process
2. Contact Kernel Approval Process
3. Book `C-8` Test Cases
4. Kernel FAQ
5. Book A/B Test Plan
6. Relevant kernel ICS file for the target scheme or `C-8`
7. Current and historical TTA bulletins
8. PICC analogue/digital test cases

## Practical Guidance for This Repository

Start from process docs if the question is:

- which documents matter
- which role owns the issue
- whether the work belongs to L2, L3, issuer-host, or merchant-terminal testing

Start from ICS or test-case docs if the question is:

- which capability must be declared or emulated
- what terminal/kernel behavior to configure
- which kernel path to attach to AI mutation or emulator profiles

Start from bulletins if the question is:

- what changed across releases
- why a prior assumption may now be stale

## Sources

- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
- [EMVCo Contact Kernel Approval Process](https://www.emvco.com/processes/contact-kernel-approval-process/)
- [EMVCo Kernel FAQ landing page](https://www.emvco.com/resources/faq-emv-contactless-kernel-general-questions/)
- local authorized/public PDFs already stored in [docs](F:/repo/GREENWIRE/docs)
