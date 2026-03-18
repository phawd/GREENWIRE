from __future__ import annotations

from core.operator_log_codec import seal_log_payload, unseal_log_payload


def test_operator_log_codec_roundtrip() -> None:
    payload = {
        "channel": "merchant",
        "operation": "contactless",
        "status": "success",
        "summary": {"arqc": "ABCDEF1234567890"},
    }
    blob = seal_log_payload(payload)
    assert blob.startswith("gwlog-v1:")
    restored = unseal_log_payload(blob)
    assert restored == payload

