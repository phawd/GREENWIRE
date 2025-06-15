import importlib.util
from pathlib import Path

_gen_path = Path(__file__).resolve().parents[1] / "core" / "emv_generator.py"
spec = importlib.util.spec_from_file_location("emv_generator", _gen_path)
emv_generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(emv_generator)


def test_generated_card_has_valid_pan():
    card = emv_generator.generate_card("Codex Bank")
    assert card["issuer"] == "Codex Bank"
    assert len(card["pan"]) == 16
    assert card["pan"].isdigit()
    assert emv_generator.luhn_validate(card["pan"])
    assert len(card["encryption_key"]) == 64


def test_encryption_key_is_unique():
    card1 = emv_generator.generate_card()
    card2 = emv_generator.generate_card()
    assert card1["encryption_key"] != card2["encryption_key"]
