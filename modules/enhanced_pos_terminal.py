"""
Enhanced POS Terminal Processor for GREENWIRE
--------------------------------------------
Simulates a complete EMV POS terminal with EMV flow, merchant profile, and receipt printing.
"""
import random
from datetime import datetime, timezone
from typing import Optional, Dict, Any

class EnhancedPOSTerminal:
    """
    Complete EMV POS terminal processor for GREENWIRE.
    """
    def __init__(self, merchant_id: str, terminal_id: str, location: str, reader: Optional[str] = None, verbose: bool = False):
        """
        Initialize the POS terminal.
        """
        self.merchant_id = merchant_id
        self.terminal_id = terminal_id
        self.location = location
        self.reader = reader
        self.verbose = verbose
        self.transactions = {}
        self.merchant_profile = {
            "mcc": "5411",  # Grocery stores
            "floor_limit": 50.00,
            "contactless_limit": 50.00
        }
        self.terminal_capabilities = "E0F8C8"  # 9F33: contact+contactless+PIN

    def process_transaction(self, config: dict) -> dict:
        """
        Process a transaction based on config dict.
        config: {amount, currency, transaction_type, entry_mode}
        """
        try:
            amount = float(config.get("amount", 0.0))
            currency = config.get("currency", "USD")
            txn_type = config.get("transaction_type", "purchase")
            entry_mode = config.get("entry_mode", "chip")
            if entry_mode == "chip":
                result = self.process_emv_chip(amount, currency)
            elif entry_mode == "nfc":
                result = self.process_contactless(amount, currency)
            elif entry_mode == "magstripe":
                result = self.process_magstripe_fallback(amount, currency)
            else:
                return {"success": False, "message": f"Unknown entry mode: {entry_mode}"}
            txn_id = result.get("transaction_id")
            if txn_id:
                self.transactions[txn_id] = result
            return result
        except Exception as e:
            return {"success": False, "message": f"Transaction error: {e}"}

    def process_emv_chip(self, amount: float, currency: str) -> dict:
        """
        Simulate EMV chip transaction: SELECT → GPO → READ RECORD → GENERATE AC
        """
        try:
            txn_id = self._generate_txn_id()
            cvm = self._select_cvm(amount, entry_mode="chip")
            arqc = self._generate_arqc(amount, currency)
            approved = amount <= self.merchant_profile["floor_limit"]
            code = "00" if approved else "05"
            txn = {
                "transaction_id": txn_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "purchase",
                "amount": amount,
                "currency": currency,
                "entry_mode": "chip",
                "cvm": cvm,
                "arqc": arqc,
                "response_code": code,
                "message": "Approved" if approved else "Do Not Honour"
            }
            if self.verbose:
                print(f"EMV chip txn: {txn}")
            return txn
        except Exception as e:
            return {"success": False, "message": f"EMV chip error: {e}"}

    def process_contactless(self, amount: float, currency: str) -> dict:
        """
        Simulate contactless EMV transaction.
        """
        try:
            txn_id = self._generate_txn_id()
            cvm = self._select_cvm(amount, entry_mode="nfc")
            arqc = self._generate_arqc(amount, currency)
            approved = amount <= self.merchant_profile["contactless_limit"]
            code = "00" if approved else "05"
            txn = {
                "transaction_id": txn_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "purchase",
                "amount": amount,
                "currency": currency,
                "entry_mode": "nfc",
                "cvm": cvm,
                "arqc": arqc,
                "response_code": code,
                "message": "Approved" if approved else "Do Not Honour"
            }
            if self.verbose:
                print(f"Contactless txn: {txn}")
            return txn
        except Exception as e:
            return {"success": False, "message": f"Contactless error: {e}"}

    def process_magstripe_fallback(self, amount: float, currency: str) -> dict:
        """
        Simulate magstripe fallback transaction.
        """
        try:
            txn_id = self._generate_txn_id()
            arqc = self._generate_arqc(amount, currency)
            approved = amount <= self.merchant_profile["floor_limit"]
            code = "00" if approved else "05"
            txn = {
                "transaction_id": txn_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "purchase",
                "amount": amount,
                "currency": currency,
                "entry_mode": "magstripe",
                "cvm": "Signature",
                "arqc": arqc,
                "response_code": code,
                "message": "Approved" if approved else "Do Not Honour"
            }
            if self.verbose:
                print(f"Magstripe fallback txn: {txn}")
            return txn
        except Exception as e:
            return {"success": False, "message": f"Magstripe error: {e}"}

    def void_transaction(self, transaction_id: str) -> dict:
        """
        Void a transaction by ID.
        """
        txn = self.transactions.get(transaction_id)
        if not txn:
            return {"success": False, "message": "Transaction not found."}
        txn["voided"] = True
        txn["response_code"] = "00"
        txn["message"] = "Voided"
        if self.verbose:
            print(f"Transaction voided: {txn}")
        return {"success": True, "transaction": txn}

    def print_merchant_receipt(self, transaction: dict) -> str:
        """
        Print merchant copy of receipt.
        """
        lines = [
            f"MERCHANT RECEIPT",
            f"Merchant ID: {self.merchant_id}",
            f"Terminal ID: {self.terminal_id}",
            f"Location: {self.location}",
            f"Date: {transaction.get('timestamp', '')}",
            f"Type: {transaction.get('type', '')}",
            f"Amount: {transaction.get('amount', 0.0)} {transaction.get('currency', '')}",
            f"Entry Mode: {transaction.get('entry_mode', '')}",
            f"CVM: {transaction.get('cvm', '')}",
            f"Response: {transaction.get('response_code', '')} - {transaction.get('message', '')}"
        ]
        receipt = "\n".join(lines)
        if self.verbose:
            print(receipt)
        return receipt

    def print_cardholder_receipt(self, transaction: dict) -> str:
        """
        Print cardholder copy of receipt.
        """
        lines = [
            f"CARDHOLDER RECEIPT",
            f"Merchant ID: {self.merchant_id}",
            f"Terminal ID: {self.terminal_id}",
            f"Location: {self.location}",
            f"Date: {transaction.get('timestamp', '')}",
            f"Type: {transaction.get('type', '')}",
            f"Amount: {transaction.get('amount', 0.0)} {transaction.get('currency', '')}",
            f"Entry Mode: {transaction.get('entry_mode', '')}",
            f"CVM: {transaction.get('cvm', '')}",
            f"Response: {transaction.get('response_code', '')} - {transaction.get('message', '')}"
        ]
        receipt = "\n".join(lines)
        if self.verbose:
            print(receipt)
        return receipt

    def _select_cvm(self, amount: float, entry_mode: str) -> str:
        """
        Select Cardholder Verification Method (CVM) based on amount and entry mode.
        """
        if entry_mode == "nfc" and amount <= self.merchant_profile["contactless_limit"]:
            return "No CVM"
        elif amount <= self.merchant_profile["floor_limit"]:
            return "Signature"
        else:
            return "Online PIN"

    def _generate_arqc(self, amount: float, currency: str) -> str:
        """
        Generate a stub ARQC (Authorization Request Cryptogram).
        """
        # For simulation, return a random hex string
        return ''.join(random.choices('0123456789ABCDEF', k=16))

    def _generate_txn_id(self) -> str:
        """
        Generate a unique transaction ID.
        """
        return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12))
