import os
import tempfile
import pytest
from config_manager import ConfigManager


@pytest.fixture
def temp_config():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
        f.write("[TEST]\nkey = value\n")
        tmp = f.name
    yield tmp
    os.unlink(tmp)


class TestConfigManager:
    def test_init_with_config_file(self, temp_config):
        cm = ConfigManager(temp_config)
        assert cm.get("TEST", "key") == "value"

    def test_get_default_nonexistent_section(self, temp_config):
        cm = ConfigManager(temp_config)
        assert cm.get("NONEXISTENT", "key") is None

    def test_get_boolean_true(self, temp_config):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
            f.write("[TEST]\nflag = true\n")
            tmp = f.name
        cm = ConfigManager(tmp)
        assert cm.get_boolean("TEST", "flag") is True
        os.unlink(tmp)

    def test_get_boolean_false(self, temp_config):
        cm = ConfigManager(temp_config)
        assert cm.get_boolean("TEST", "nonexistent", fallback=False) is False

    def test_get_int(self, temp_config):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
            f.write("[TEST]\ncount = 42\n")
            tmp = f.name
        cm = ConfigManager(tmp)
        assert cm.get_int("TEST", "count") == 42
        os.unlink(tmp)

    def test_get_int_fallback(self, temp_config):
        cm = ConfigManager(temp_config)
        assert cm.get_int("TEST", "nonexistent", fallback=10) == 10

    def test_get_list(self, temp_config):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
            f.write("[TEST]\nitems = a,b,c\n")
            tmp = f.name
        cm = ConfigManager(tmp)
        assert cm.get_list("TEST", "items") == ["a", "b", "c"]
        os.unlink(tmp)

    def test_get_list_fallback(self, temp_config):
        cm = ConfigManager(temp_config)
        assert cm.get_list("TEST", "nonexistent") == []

    def test_set_and_get(self, temp_config):
        cm = ConfigManager(temp_config)
        cm.set("NEW_SECTION", "key1", "value1")
        assert cm.get("NEW_SECTION", "key1") == "value1"