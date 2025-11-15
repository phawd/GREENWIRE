"""Named constants for the issuer pipeline message bus."""

ISSUE_CARD_REQUEST = "pipeline.issue_card_request"
SESSION_KEYS_DERIVED = "pipeline.session_keys_derived"
PERSONALIZATION_REQUEST = "pipeline.personalization_request"
CARD_PERSONALIZED = "pipeline.card_personalized"
MERCHANT_TXN_INITIATED = "pipeline.merchant_txn_initiated"
TRANSACTION_COMPLETED = "pipeline.transaction_completed"
ISSUER_CARD_APPROVED = "pipeline.issuer.card_approved"
PERSONALIZATION_COMPLETED = "pipeline.personalization.completed"
HSM_DERIVE_SESSION_KEYS = "pipeline.hsm.derive_session_keys"
HSM_GENERATE_ARQC = "pipeline.hsm.generate_arqc"
HSM_ARQC_GENERATED = "pipeline.hsm.arqc_generated"
PIPELINE_STATUS_REQUEST = "pipeline.status_request"
PIPELINE_STATUS_RESPONSE = "pipeline.status_response"
PAYMENT_GATEWAY_COMPLETED = "pipeline.payment_gateway.completed"
PAYMENT_GATEWAY_FAILED = "pipeline.payment_gateway.failed"
TOKENIZATION_COMPLETED = "pipeline.tokenization.completed"
SETTLEMENT_COMPLETED = "pipeline.settlement.completed"
SETTLEMENT_FAILED = "pipeline.settlement.failed"
SALES_LEDGER_UPDATED = "pipeline.sales.ledger_updated"
ATM_CARD_PREPARED = "pipeline.atm.card_prepared"
ATM_CASH_DISPENSED = "pipeline.atm.cash_dispensed"
POS_PURCHASE_COMPLETED = "pipeline.pos.purchase_completed"
SETTLEMENT_SCHEDULED = "pipeline.settlement.scheduled"
PCSC_CARD_PROCESSED = "pipeline.pcsc.card_processed"
MOBILE_WALLET_PROVISIONED = "pipeline.wallet.provisioned"

__all__ = [
    "ISSUE_CARD_REQUEST",
    "SESSION_KEYS_DERIVED",
    "PERSONALIZATION_REQUEST",
    "CARD_PERSONALIZED",
    "MERCHANT_TXN_INITIATED",
    "TRANSACTION_COMPLETED",
    "ISSUER_CARD_APPROVED",
    "PERSONALIZATION_COMPLETED",
    "HSM_DERIVE_SESSION_KEYS",
    "HSM_GENERATE_ARQC",
    "HSM_ARQC_GENERATED",
    "PIPELINE_STATUS_REQUEST",
    "PIPELINE_STATUS_RESPONSE",
    "PAYMENT_GATEWAY_COMPLETED",
    "PAYMENT_GATEWAY_FAILED",
    "TOKENIZATION_COMPLETED",
    "SETTLEMENT_COMPLETED",
    "SETTLEMENT_FAILED",
    "SALES_LEDGER_UPDATED",
    "ATM_CARD_PREPARED",
    "ATM_CASH_DISPENSED",
    "POS_PURCHASE_COMPLETED",
    "SETTLEMENT_SCHEDULED",
    "PCSC_CARD_PROCESSED",
    "MOBILE_WALLET_PROVISIONED",
]
