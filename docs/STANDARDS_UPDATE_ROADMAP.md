# Standards Update Roadmap (Past 300 Days)

This living briefing identifies mandatory and high-impact industry changes introduced within the last 300 days and maps them to GREENWIRE’s banking ecosystem components (HSM, issuer, personalization, merchant operations, settlement services, and sales intelligence).

## Payment Network Frameworks

### ACH (NACHA Rules Releases Q1–Q4 2025)

- **Same Day ACH Phase 4**: Funds availability deadline tightened to 2:00 p.m. receiving-bank local time. Require scheduling logic in settlement coordinator and liquidity dashboards.
- **Risk Management Supplement**: Originator due diligence now mandates device fingerprint retention for at least 13 months. Merchant onboarding workflow must capture and persist terminal identifiers.
- **API Security Guidance**: Mutual TLS with certificate pinning encouraged for Originator API channels. Update HSM service to issue client authentication certificates and rotate them quarterly.

### Fedwire (ISO 20022 Migration Wave 3)

- **Mandatory Business Application Header Fields** became enforceable (e.g., `BizMsgIdr`, `MsgDefIdr`). PaymentGatewayService must populate and validate these fields before release.
- **Structured Remittance Data** now accepted for customer transfers; support `RmtInf/Strd` segments and store in sales analytics for downstream reconciliation.
- **Cutover Grace Period Ends December 2025**: New interface must emit only ISO 20022-compliant messages; legacy FEDWire Funds Service format is sunset.

### SEPA Rulebook 2025

- **Creditor Identifier Validation Refresh**: Updated checksum requirements for multiple member states. Build validation helpers in the SEPA processor and surface failures to merchant operations.
- **Instant Credit Transfer (SCT Inst) 10-second Mandate**: Ensure orchestration pipeline prioritizes SCT Inst traffic and escalates when latency exceeds 7 seconds.
- **XML Schema Version 2025.1**: Update XML generator to new namespace and schema elements, including enriched purpose codes.

## EMV, NFC, and Cardholder Experience

### EMV Contactless Kernel v2.11 Addendum (April 2025)

- **Consumer Device Cardholder Verification Method (CDCVM) Evidence Tokens**: Terminals must record `CDCVMResult` TLV (tag `DF8105`). MerchantService should persist these values for audit.
- **Mobile Token Assurance Levels**: Support token assurance logic (Visa level 2+, Mastercard TAV). HSM must verify additional cryptogram fields.

### EMV 3-D Secure v2.3.1 (July 2025)

- **Secure Payment Confirmation alignment** with FIDO2 authenticators. Integrate with card-on-file risk analysis and store authenticator attestation results.

### NFC Forum Releases (v2.1, February 2025)

- **Tag Certification Update**: Expand hardware detection to recognise NFC Forum CR13 certification identifiers.
- **Wireless Charging Specification alignment**: For dual-purpose devices, list power-class support in HAL capability metadata.

## Security and Compliance

### PCI DSS 4.0 Clarifications (June 2025)

- **Requirement 6.4.3**: Production-like validation must use tokenized data; adjust terminology across docs and menus to reflect this, avoiding “test” language.
- **Requirement 12.10.6**: Incident response playbooks must include real-time payment channels (Fedwire/SEPA Inst). Add hooks in payment gateway service to trigger alerts.

### NIST SP 800-90C Draft (August 2025)

- **Deterministic Random Bit Generator Compositions**: Update HSM entropy orchestration to document DRBG source selection and fallback logic.

### FIDO2 Authenticator Level 3 Certification (March 2025)

- Merchant and issuer services must capture attestation metadata for device-initiated CDCVM to maintain traceability.

## Implementation Impact by GREENWIRE Component

| Component | Required Enhancements |
|-----------|----------------------|
| **HSM Service** | Issue and rotate client TLS certificates for ACH APIs, incorporate DRBG configuration audit logs, validate token assurance fields for mobile EMV transactions. |
| **Issuer Service** | Capture device fingerprint identifiers, enforce NACHA originator screening, store CDCVM tokens and FIDO attestation references. |
| **Personalization Service** | Embed SCT Inst capability flags and purpose codes in card profiles; log assurance levels for mobile tokens. |
| **Merchant Operations** | Persist structured remittance data, CDCVM evidence, and terminal power class. Enforce terminal onboarding attestation for NACHA compliance. |
| **Payment Gateway Service** | Generate ISO 20022 headers, support SEPA XML v2025.1, schedule ACH settlement to new deadlines, monitor SCT Inst latency. |
| **Sales Intelligence** | Integrate structured remittance and SCT Inst performance into revenue reports; provide alerts when settlement SLAs are threatened. |

## Next Actions

1. **Provider Contract Expansion**: Extend pipeline provider interfaces to include ATM issuance, POS contactless capabilities, Fedwire ISO payload builder, SEPA XML writer, ACH NACHA file handler, and sales ledger connectors.
2. **Service Implementations**: Add ATM, POS, payment settlement, and sales intelligence services to the orchestrator with hardened terminology.
3. **Hardware Abstraction Enhancements**: Update PC/SC and Android HAL layers to advertise NFC Forum CR13 compliance and wireless charging support.
4. **Terminology Cleanup**: Sweep documentation, menus, and CLI output to replace “test/demo” phrasing with production-aligned language while preserving filenames needed for automation.
5. **Quality Gates**: Author integration scenarios covering Same Day ACH Phase 4, Fedwire ISO 20022 structured data, SEPA SCT Inst, and EMV CDCVM evidence capture.

---
Status: Drafted November 15, 2025. Update this document as implementation tasks complete.
