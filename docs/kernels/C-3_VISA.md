# C-3 VISA

Status: public working notes for Visa contactless kernel behavior.

Public anchors:

- EMVCo public LoA maps `Book C-3` to `VISA`.
- The downloaded Visa Transaction Acceptance Device Guide is useful for merchant-side acceptance notes even though it is not the kernel specification itself.

Scheme identity:

- Kernel family: `C-3`
- Network: `Visa`
- Common contactless framing in GREENWIRE terms: `qVSDC`, `Kernel 3`
- Common RID/AID family for inference: `A000000003...`

Issuer view:

- Visa issuance has to line up the contactless application profile with Visa acceptance expectations, especially around CVM decisions, contactless limits, and card/terminal data consistency.
- A Visa contactless card that is personalized like a generic EMV card can still fail if the issuer-side settings do not match what Visa terminals expect from the Visa contactless application.
- Greenwire comment: `C-3` issuance tests should validate personalization artifacts and terminal-acceptance behavior together.

Merchant view:

- Merchant terminals need Visa-specific acceptance tuning, especially for contactless outcome processing, limit handling, and fallback.
- The public Visa terminal guide is useful because it reflects merchant deployment reality rather than only card-personalization concerns.
- Greenwire comment: `C-3` merchant testing should include reader parameterization, online/offline routing decisions, and fallback from contactless to contact/chip paths.

HSM / issuer-host view:

- The host side has to validate Visa cryptograms and issuer responses in a way that matches the Visa card profile actually issued.
- HSM integration matters for ARQC/ARPC validation, session-key derivation, and any Visa-specific CVN assumptions used by the host stack.
- Greenwire comment: for `C-3`, terminal acceptance and host cryptographic validation should be tested as one flow, not as separate silos.

Operational difference vs other kernels:

- `C-3` differs from `C-2` in merchant guidance, terminal tuning, and network-specific host assumptions.
- `C-3` often becomes the merchant baseline in mixed environments, which makes it a good control case for comparing `C-4` through `C-7`.

Sources:

- `docs/sources/kernels/TCP_LOA_MATS_00043_19Apr18-1.pdf`
- `docs/sources/kernels/visa_transaction_acceptance_device_guide_aug_2025.pdf`
- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
