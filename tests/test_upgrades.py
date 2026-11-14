"""Upgrade tests: AP channel lock, dashboard counts, override persistence."""

import pytest

from omni.core import dashboard, tui
from omni.wifi.modules import rage


# -- AP channel parsing -----------------------------------------------------

AP_TABLE = ("BSSID, first, last, channel, Speed, ESSID\n"
            "AA:BB:CC:DD:EE:FF, x, y, 6, 54, Office\n"
            "11:22:33:44:55:66, x, y, -60, 12, AA:BB:CC:DD:EE:FF\n")


def test_ap_channel_reads_the_ap_row():
    assert rage._ap_channel(AP_TABLE, "aa:bb:cc:dd:ee:ff") == 6


def test_ap_channel_skips_client_rows():
    # a client row's 4th field is a MAC, not a number
    assert rage._ap_channel(AP_TABLE, "11:22:33:44:55:66") is None


def test_ap_channel_without_a_bssid_returns_the_first_ap():
    assert rage._ap_channel(AP_TABLE) == 6


def test_ap_channel_on_garbage():
    assert rage._ap_channel("") is None
    assert rage._ap_channel("no, csv, here\n") is None


def test_rage_has_a_channel_option_not_scan():
    names = {o.name for o in rage.DeauthRage.OPTIONS}
    assert "CHANNEL" in names and "SCAN" not in names


def test_deauth_passes_the_reason_code():
    import omni.wifi.capture as capture
    captured: list[list[str]] = []

    class Rec:
        @staticmethod
        def run(argv, timeout=None):
            captured.append(argv)
            return type("R", (), {"ok": True, "code": 0, "out": "", "err": "",
                                  "text": ""})()

    original = capture.proc.run
    original_require = capture.proc.require
    capture.proc.run = Rec.run
    capture.proc.require = lambda tool, hint='': tool
    try:
        capture.deauth("wlan0mon", "AA:BB:CC:DD:EE:FF", reason=7)
    finally:
        capture.proc.run = original
        capture.proc.require = original_require
    assert "--reason=7" in captured[0]


def test_deauth_omits_reason_when_unset():
    import omni.wifi.capture as capture
    captured: list[list[str]] = []

    class Rec:
        @staticmethod
        def run(argv, timeout=None):
            captured.append(argv)
            return type("R", (), {"ok": True, "code": 0, "out": "", "err": "",
                                  "text": ""})()

    original = capture.proc.run
    original_require = capture.proc.require
    capture.proc.run = Rec.run
    capture.proc.require = lambda tool, hint='': tool
    try:
        capture.deauth("wlan0mon", "AA:BB:CC:DD:EE:FF")
    finally:
        capture.proc.run = original
        capture.proc.require = original_require
    assert not any("--reason" in part for part in captured[0])


def test_rage_cycles_the_reason_code_into_each_send(monkeypatch):
    seen: list[int] = []
    import omni.wifi.capture as capture
    monkeypatch.setattr(capture, "deauth",
                        lambda mon, bssid, client, count, reason=None:
                        seen.append(reason) or type("R", (), {"code": 0})())
    mod = rage.DeauthRage(BSSID="AA:BB:CC:DD:EE:FF",
                          CLIENTS="11:22:33:44:55:66", RUNTIME="2",
                          CYCLE="0", REFRESH="99")
    mod.monitor = lambda: "wlan0mon"          # type: ignore[method-assign]
    mod.restore = lambda mon: None            # type: ignore[method-assign]
    mod.execute()
    assert seen and seen[0] == 7             # first reason is the classic kick
    assert len(set(seen)) > 1                 # and it does cycle


def test_rage_locks_the_explicit_channel(monkeypatch):
    from omni.wifi import iface as iface_mod
    set_calls: list[tuple] = []
    monkeypatch.setattr(iface_mod, "channel",
                        lambda iface, ch: set_calls.append((iface, ch)) or True)
    mod = rage.DeauthRage(BSSID="AA:BB:CC:DD:EE:FF", CLIENTS="11:22:33:44:55:66",
                          RUNTIME="2", CHANNEL="6")
    mod.monitor = lambda: "wlan0mon"          # type: ignore[method-assign]
    mod.restore = lambda mon: None            # type: ignore[method-assign]
    import omni.wifi.capture as capture
    monkeypatch.setattr(capture, "deauth",
                        lambda mon, bssid, client, count, reason=None: type(
                            "R", (), {"code": 0})())
    mod.execute()
    assert ("wlan0mon", 6) in set_calls


def test_rage_locks_the_channel_learned_from_the_capture(monkeypatch, tmp_path):
    from omni.wifi import iface as iface_mod
    set_calls: list[tuple] = []
    monkeypatch.setattr(iface_mod, "channel",
                        lambda iface, ch: set_calls.append((iface, ch)) or True)
    # airodump "writes" a CSV containing the AP on channel 11
    def fake_run(argv, timeout=None, **kw):
        if argv and argv[0] == "airodump-ng":
            target = argv[argv.index("-w") + 1] + ".csv"
            with open(target, "w", encoding="utf-8") as fh:
                fh.write("BSSID,first,last,channel,Speed,ESSID\n"
                         "AA:BB:CC:DD:EE:FF,x,y,11,54,Office\n")
        return type("R", (), {"ok": True, "code": 0, "out": "", "err": "",
                              "text": ""})()

    monkeypatch.setattr("omni.core.proc.run", fake_run)
    mod = rage.DeauthRage(BSSID="AA:BB:CC:DD:EE:FF", RUNTIME="2", DISCOVER="2")
    mod.monitor = lambda: "wlan0mon"          # type: ignore[method-assign]
    mod.restore = lambda mon: None            # type: ignore[method-assign]
    import omni.wifi.capture as capture
    monkeypatch.setattr(capture, "deauth",
                        lambda mon, bssid, client, count, reason=None: type(
                            "R", (), {"code": 0})())
    result = mod.execute()
    assert ("wlan0mon", 11) in set_calls
    assert result["clients"] == [rage.BROADCAST]


# -- dashboard tab counts ---------------------------------------------------

def make(monkeypatch=None, have=True):
    """Two families; only .b is tool-free, and the tool never exists."""
    mods = {"wifi": [("wifi.a", "first"), ("wifi.b", "second")],
            "rf": [("rf.a", "first"), ("rf.b", "second")]}
    inst = dashboard.Model(mods, have_tool=lambda t: t == "omni-inner-tool")
    inst.set_needs({"wifi.a": ("tool",), "wifi.b": (),
                    "rf.a": ("tool",), "rf.b": ()})
    inst.tab = 1                     # Home is now the first tab
    return inst


def test_rows_for_looks_at_one_family():
    inst = make(None)
    assert [r.name for r in inst.rows_for("rf")] == ["rf.a", "rf.b"]


def test_tab_bar_shows_ready_counts():
    inst = make()
    bar = tui.Dashboard(object(), inst)._tab_bar(200)
    assert "WiFi 1/2" in bar and "RF 1/2" in bar


def test_tab_bar_counts_ready_rows():
    inst = make()
    bar = tui.Dashboard(object(), inst)._tab_bar(200)
    # .a needs a tool that is not installed, .b needs nothing -> 1 of 2 ready
    assert "WiFi 1/2" in bar and "RF 1/2" in bar


def test_tab_bar_shows_zero_when_no_rows_are_ready():
    inst = make()
    inst._needs = {name: ("nope",) for name in inst._needs}
    bar = tui.Dashboard(object(), inst)._tab_bar(200)
    assert "WiFi 0/2" in bar and "RF 0/2" in bar


# -- override persistence ---------------------------------------------------

class Store:
    def __init__(self):
        self.values: dict = {}

    def get_value(self, key, default=None):
        return self.values.get(key, default)

    def set_value(self, key, value):
        self.values[key] = value


def test_overrides_survive_a_round_trip():
    inst = make(None)
    inst.values = ["SSID=Office", "COUNT=9"]
    inst.selected  # ensure a row exists
    store = Store()
    inst.save_overrides(store)
    fresh = make(None)
    fresh.load_overrides(store)
    assert fresh.values == ["SSID=Office", "COUNT=9"]


def test_load_does_not_clobber_typed_values():
    inst = make(None)
    inst.values = ["BSSID=aa"]
    store = Store()
    store.set_value("dash.last.wifi.a", "SSID=x")
    inst.load_overrides(store)
    assert inst.values == ["BSSID=aa"]


def test_switch_tab_saves_and_restores():
    inst = make()
    store = Store()
    store.values["dash.last.wifi.a"] = "SSID=kept"
    dash = tui.Dashboard(object(), inst, store)
    dash.switch_tab(1)
    assert inst.family == "rf"
    assert inst.values == []
    dash.switch_tab(-1)
    assert inst.family == "wifi"
    assert inst.values == ["SSID=kept"]


def test_switch_tab_with_no_store_is_harmless():
    inst = make(None)
    dash = tui.Dashboard(object(), inst, None)
    dash.switch_tab(1)
    assert inst.family == "rf"

