# C-4 AMEX

Status: public working notes for American Express contactless kernel behavior.

Public anchors:

- EMVCo public LoA maps `Book C-4` to `AMEX`.
- EMVCo public process material confirms this remains a scheme-managed kernel family rather than a generic EMVCo shared kernel.

Scheme identity:

- Kernel family: `C-4`
- Network: `American Express`
- Common contactless framing in GREENWIRE terms: `Expresspay`, `Kernel 4`
- Common RID/AID family for inference: `A000000025...`

Issuer view:

- `C-4` issuance has to align Amex contactless application settings, CVM policy, and issuer-host expectations.
- In practice, this means the card profile, limits, and cryptographic host assumptions cannot be copied blindly from Visa or Mastercard issuance flows.
- Greenwire comment: model `C-4` as its own scheme profile, not as a cosmetic AID swap.

Merchant view:

- Merchant readers need to support the Amex kernel path explicitly and handle the transaction outcomes Amex contactless expects.
- Acceptance issues often show up in terminal configuration and routing rather than in card data alone.
- Greenwire comment: merchant tests for `C-4` should emphasize terminal kernel selection, amount-limit behavior, and fallback handling.

HSM / issuer-host view:

- The HSM and host path must support the card-validation and issuer-response patterns used by the Amex contactless profile in deployment.
- Any emulator-grade implementation still needs to keep Amex cryptogram handling and key separation distinct from the other schemes.
- Greenwire comment: `C-4` host validation should be tracked separately in test harnesses so Visa/Mastercard assumptions do not leak in.

Operational difference vs other kernels:

- `C-4` is usually a lower-volume acceptance path than Visa/Mastercard but still operationally distinct.
- It is a good stress case for checking that merchant and host logic are genuinely scheme-aware.

Sources:

- `docs/sources/kernels/TCP_LOA_MATS_00043_19Apr18-1.pdf`
- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
