"""Registry and module-contract tests."""

import pytest

from omni.core.module import FAMILIES, Module, Option, registry


def test_all_families_discover():
    for fam in ("wifi", "radio", "car", "brute", "rf", "android", "ios",
                "windows", "pentest", "mobile", "news", "flip", "core"):
        names = [m.NAME for m in registry.all(fam)]
        assert names, f"no modules registered for family {fam}"
        assert all(n.startswith(fam + ".") for n in names)


def test_elite_trades_are_populated():
    """The WiFi, radio, car-key and brute trades must stay substantial."""
    for fam, minimum in (("wifi", 15), ("radio", 10), ("brute", 8), ("car", 7),
                         ("android", 20), ("ios", 25), ("rf", 10)):
        assert len(registry.all(fam)) >= minimum


def test_every_module_is_a_module_subclass():
    for fam in FAMILIES:
        for mod in registry.all(fam):
            assert isinstance(mod, type) and issubclass(mod, Module)
            assert mod.DESCRIPTION


def test_search_finds_wifi():
    hits = [m.NAME for m in registry.search("wifi")]
    assert "windows.wifi" in hits


def test_build_instance_and_options():
    mod = registry.build("news.user", NAME="tlg")
    assert mod.get("NAME") == "tlg"
    with pytest.raises(KeyError):
        mod.set("NOPE", "x")


def test_required_option_validation():
    mod = registry.build("news.user")
    with pytest.raises(ValueError):
        mod.validate()
    mod.set("NAME", "tlg")
    mod.validate()          # nothing raised


def test_choices_enforced():
    mod = registry.build("news.search")
    mod.set("SCOPE", "comments")            # valid choice
    assert mod.get("SCOPE") == "comments"
    with pytest.raises(ValueError):
        mod.set("SCOPE", "shells")          # invalid choice
