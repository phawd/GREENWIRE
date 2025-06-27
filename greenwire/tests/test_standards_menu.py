import importlib.util
from pathlib import Path

_menu_path = Path(__file__).resolve().parents[1] / "standards_menu.py"
spec = importlib.util.spec_from_file_location("greenwire.standards_menu", _menu_path)
std_menu = importlib.util.module_from_spec(spec)
import sys
sys.path.insert(0, str(_menu_path.parents[1]))
spec.loader.exec_module(std_menu)


def test_wired_standards_subset_of_all():
    from greenwire.core import standards

    assert set(std_menu.WIRED_STANDARDS).issubset(set(standards.Standard))


def test_wireless_standards_subset_of_all():
    from greenwire.core import standards

    assert set(std_menu.WIRELESS_STANDARDS).issubset(set(standards.Standard))
