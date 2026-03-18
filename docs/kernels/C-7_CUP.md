# C-7 CUP

Status: public working notes for China UnionPay contactless kernel behavior.

Public anchors:

- EMVCo public LoA maps `Book C-7` to `CUP`.
- EMVCo public process material confirms that `C-7` remains a scheme-managed kernel family.

Scheme identity:

- Kernel family: `C-7`
- Network: `China UnionPay`
- Common contactless framing in GREENWIRE terms: `qPBOC`, `Kernel 7`
- Common RID/AID family for inference: `A000000333...`

Issuer view:

- `C-7` issuance needs a UnionPay-specific contactless profile, especially for card-risk policy, application data, and issuer-host expectations.
- This is the kernel most likely to be mis-modeled if a platform assumes all schemes are just minor AID variants.
- Greenwire comment: treat `C-7` as its own issuance lane, not as a generic international fallback.

Merchant view:

- Merchant terminals have to carry the CUP kernel path and route the transaction through the right acceptance stack.
- Regional deployment and routing configuration matter more here than for the more globally common Visa/Mastercard paths.
- Greenwire comment: `C-7` merchant testing should include routing visibility and terminal-kernel selection checks, not only APDU success.

HSM / issuer-host view:

- HSM integration must preserve UnionPay-specific host assumptions for cryptogram validation and issuer responses.
- This becomes important in gateways or processors that multiplex several schemes behind one HSM or authorization layer.
- Greenwire comment: keep `C-7` host regression separate so regional and scheme-specific logic is not silently flattened away.

Operational difference vs other kernels:

- `C-7` is often where regional acceptance, routing, and issuer-host specialization become most visible.
- It is a useful test case for proving that the platform handles scheme diversity beyond the most common North American and European baselines.

Sources:

- `docs/sources/kernels/TCP_LOA_MATS_00043_19Apr18-1.pdf`
- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
