import importlib.util
from pathlib import Path
import pytest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_backend_path = Path(__file__).resolve().parents[1] / "core" / "backend.py"
spec = importlib.util.spec_from_file_location(
    "greenwire.core.backend", _backend_path
)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)

_emv_path = Path(__file__).resolve().parents[1] / "core" / "emv_generator.py"
emv_spec = importlib.util.spec_from_file_location("emv", _emv_path)
emv = importlib.util.module_from_spec(emv_spec)
emv_spec.loader.exec_module(emv)


def test_issue_card_stores_data(tmp_path):
    conn = backend.init_backend(tmp_path / "db.sqlite")
    card = backend.issue_card(conn, issuer="Bank1")
    assert "verification_code" in card
    assert backend.is_duplicate(conn, card["pan"]) is True


def test_duplicate_detection(tmp_path):
    conn = backend.init_backend(tmp_path / "db.sqlite")
    pan = emv.random_pan()
    backend.issue_card(conn, pan=pan)
    with pytest.raises(ValueError):
        backend.issue_card(conn, pan=pan)
