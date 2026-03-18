# C-5 JCB

Status: public working notes for JCB contactless kernel behavior.

Public anchors:

- EMVCo public LoA maps `Book C-5` to `JCB`.
- EMVCo public process material confirms this kernel remains scheme-managed.

Scheme identity:

- Kernel family: `C-5`
- Network: `JCB`
- Common contactless framing in GREENWIRE terms: `J/Speedy`, `Kernel 5`
- Common RID/AID family for inference: `A000000065...`

Issuer view:

- `C-5` issuance needs to account for the JCB contactless application profile instead of inheriting Visa/Mastercard defaults.
- Personalization differences matter in limits, card-risk controls, and the exact data objects the terminal and host expect back.
- Greenwire comment: if a generated card is labeled JCB, its contactless profile should resolve to `Kernel 5` and follow a separate test track.

Merchant view:

- Merchant terminals have to select the JCB kernel path correctly and maintain configuration that can route the transaction through JCB acceptance rules.
- In mixed estates, JCB often exposes configuration drift because it is less frequently exercised than Visa or Mastercard.
- Greenwire comment: `C-5` should be part of regression testing precisely because it is easy for terminals to under-test.

HSM / issuer-host view:

- The HSM path needs to validate JCB-side cryptographic and issuer-response behavior cleanly without collapsing into a generic EMV path.
- Even when the emulator uses synthetic data, the host flow should stay scheme-aware and separately traceable.
- Greenwire comment: keep `C-5` host logs distinct when replaying issuer decisions or debugging terminal acceptance gaps.

Operational difference vs other kernels:

- `C-5` commonly highlights scheme-coverage gaps in terminals, routing tables, and certification assumptions.
- It is useful as a negative-control kernel when verifying that merchant and HSM logic are not hardcoded around Visa/Mastercard only.

Sources:

- `docs/sources/kernels/TCP_LOA_MATS_00043_19Apr18-1.pdf`
- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
