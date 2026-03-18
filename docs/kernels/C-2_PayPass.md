# C-2 PayPass

Status: public working notes for Mastercard contactless kernel behavior.

Public anchors:

- EMVCo public LoA maps `Book C-2` to `PayPass / Mastercard`.
- EMVCo public process page states `Books C-2 to C-7` are managed by the related payment schemes.

Scheme identity:

- Kernel family: `C-2`
- Network: `Mastercard`
- Common contactless framing in GREENWIRE terms: `PayPass`, `M/Chip`, `Kernel 2`
- Common RID/AID family for inference: `A000000004...`

Issuer view:

- Issuance is not only PAN/profile loading; it has to align the card profile with Mastercard contactless risk rules, CVM behavior, offline data objects, and the contactless application profile actually expected by the terminal.
- Mastercard issuance usually matters most around card risk management, CVM thresholds, and application data consistency between contact and contactless paths.
- Greenwire comment: when we emulate `C-2`, the card profile should be treated as Mastercard-first and not as a generic EMV card with only a different AID.

Merchant view:

- The terminal kernel has to interpret Mastercard contactless outcomes, TVR/TSI semantics, CVM triggers, and fallback behavior correctly.
- Merchant acceptance impact is usually seen in reader configuration, amount limits, CVM threshold handling, and whether the terminal requests online authorization versus approving offline flows.
- Greenwire comment: merchant test cases for `C-2` should stress contactless limits, outcome handling, fallback, and Mastercard-specific terminal action behavior.

HSM / issuer-host view:

- The HSM side has to support the issuer script and authorization flows expected by Mastercard contactless products, not just generic ARQC validation.
- Session-key derivation, ARQC/ARPC validation, CVN handling, and key separation must stay aligned with the Mastercard profile used by the card and host.
- Greenwire comment: treat `C-2` as a host-profile problem as much as a personalization problem; terminal success alone is not enough.

Operational difference vs other kernels:

- Compared with `C-3 VISA`, `C-2` should be assumed to diverge in card-risk settings, CVM handling, and terminal outcome processing.
- Compared with `C-6 DISCOVER` and `C-7 CUP`, `C-2` usually shows up in environments already tuned for Mastercard online processing and PayPass acceptance logic.

Sources:

- `docs/sources/kernels/TCP_LOA_MATS_00043_19Apr18-1.pdf`
- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
