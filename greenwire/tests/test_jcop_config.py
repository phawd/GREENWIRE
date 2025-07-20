import importlib.util
import sys
from pathlib import Path

_config_path = Path(__file__).resolve().parents[1] / 'core' / 'jcop_applet_config.py'
spec = importlib.util.spec_from_file_location('jcop_applet_config', _config_path)
jcop = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = jcop
spec.loader.exec_module(jcop)


def test_toggle_feature():
    cfg = jcop.JCOPAppletConfig()
    cfg.toggle('feature_01', True)
    assert cfg.is_enabled('feature_01')
    cfg.toggle('feature_01', False)
    assert not cfg.is_enabled('feature_01')


def test_unknown_feature():
    cfg = jcop.JCOPAppletConfig()
    try:
        cfg.toggle('feature_99', True)
    except KeyError:
        pass
    else:
        raise AssertionError('KeyError not raised')
