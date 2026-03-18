# C-6 DISCOVER

Status: public working notes for Discover contactless kernel behavior.

Public anchors:

- EMVCo public LoA maps `Book C-6` to `DISCOVER`.
- EMVCo public process material confirms `C-6` remains scheme-managed rather than part of the shared `C-8` path.

Scheme identity:

- Kernel family: `C-6`
- Network: `Discover`
- Common contactless framing in GREENWIRE terms: `D-PAS`, `Kernel 6`
- Common RID/AID family for inference in GREENWIRE: `A000000152...` or `A000000324...`

Issuer view:

- `C-6` issuance should be treated as a Discover contactless profile with its own issuer-host assumptions, not as a generic profile with a Discover AID.
- Discover-specific limits, card-risk choices, and cryptogram expectations need to line up from personalization into authorization.
- Greenwire comment: `C-6` should keep its own issuer profile and test vectors, even when using synthetic identities and emulator-grade data.

Merchant view:

- Merchant readers need to route Discover contactless transactions through the right kernel path and acceptance configuration.
- Mixed estates often fail here because Discover may be enabled commercially but not exercised deeply in terminal regression.
- Greenwire comment: `C-6` merchant tests should check kernel selection, fallback behavior, and network routing visibility in the terminal logs.

HSM / issuer-host view:

- HSM-side processing must remain Discover-aware for cryptogram verification and issuer response generation.
- This matters most when the host platform shares infrastructure across several brands and is tempted to collapse the rules into one generic EMV flow.
- Greenwire comment: keep Discover test cases separate in any issuer/HSM regression matrix.

Operational difference vs other kernels:

- `C-6` is often operationally close to the major schemes from a merchant point of view, but acceptance gaps show up quickly when certification or routing assumptions are incomplete.
- It is valuable for proving that the stack handles more than the top two networks.

Sources:

- `docs/sources/kernels/TCP_LOA_MATS_00043_19Apr18-1.pdf`
- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
