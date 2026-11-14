"""Config layering: defaults <- file <- environment."""

import json
import os

from omni.core import config


def test_defaults(isolated_config):
    cfg = config.load()
    assert cfg["flipper"]["firmware_repo"].startswith("flipperc0d3r")
    assert cfg["android"]["serial"] is None


def test_user_file_layer(isolated_config, monkeypatch):
    cfg_path = isolated_config / "config.json"
    cfg_path.write_text(json.dumps({"news": {"limit": 7}}))
    monkeypatch.setenv("OMNI_CONFIG", str(cfg_path))
    cfg = config.load(path=str(cfg_path))
    assert cfg["news"]["limit"] == 7
    assert cfg["android"]["serial"] is None      # deep merge keeps siblings


def test_env_layer_overrides_file(isolated_config, monkeypatch):
    monkeypatch.setenv("OMNI_NEWS_USER", "tlg")
    cfg = config.load()
    assert cfg["news"]["user"] == "tlg"


def test_roundtrip_set_get(isolated_config, monkeypatch):
    monkeypatch.setenv("OMNI_CONFIG", str(isolated_config / "config.json"))
    config.reload()
    config.set_value("android.serial", "1A2B3C")
    assert config.get_value("android.serial") == "1A2B3C"
    with open(config.config_path(), encoding="utf-8") as fh:
        assert json.load(fh)["android"]["serial"] == "1A2B3C"

