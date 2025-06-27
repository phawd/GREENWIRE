import importlib.util
from pathlib import Path
import sys

_menu_path = Path(__file__).resolve().parents[1] / "menu_cli.py"
spec = importlib.util.spec_from_file_location("menu_cli", _menu_path)
menu_cli = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = menu_cli
spec.loader.exec_module(menu_cli)


def test_tool_counts():
    assert len(menu_cli.GENERATION_TOOLS) >= 30
    assert len(menu_cli.ATTACK_TOOLS) >= 30
    assert len(menu_cli.DUMP_TOOLS) >= 30


def test_parser_defaults():
    parser = menu_cli.create_parser()
    args = parser.parse_args(["generate", "gen_tool_1"])  # minimal args
    assert args.subsystem == "generate"
    assert args.tool == "gen_tool_1"
