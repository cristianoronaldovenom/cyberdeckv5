"""Wi-Fi jamming: channel plans, mdk4 argv, the hop loop and the fallbacks.

No radio: the plans are pure functions and the Jammer takes its channel setter,
runner and spawner as arguments, so the loop is checked the way a pcap would
show it — which channel, for how long, with which command line.
"""

import pytest

from omni.wifi import jam
from omni.wifi.modules.jam import pick_target

BSSID = "AA:BB:CC:DD:EE:FF"


def test_channels_expand_ranges_and_dedupe():
    assert jam.channels("1-3,3,6") == [1, 2, 3, 6]
    assert jam.channels("") == list(range(1, 14))
    assert jam.channels("", "5")[0] == 36
    assert jam.channels("36-48:8") == [36, 44]


def test_a_bad_channel_spec_says_so():
    with pytest.raises(ValueError):
        jam.channels("abc")
    with pytest.raises(ValueError):
        jam.channels("", "6")


def test_hop_plan_covers_the_window_exactly():
    plan = jam.hop_plan([1, 6, 11], 2.0, 500)
    assert [channel for channel, _ in plan] == [1, 6, 11, 1]
    assert sum(dwell for _, dwell in plan) == pytest.approx(2.0)
    clipped = jam.hop_plan([1, 6], 0.7, 500)
    assert sum(dwell for _, dwell in clipped) == pytest.approx(0.7)


def test_default_ssids_are_realistic_and_overridable():
    assert "Free WiFi" in jam.ssid_list("")
    assert jam.ssid_list("a,b\nc") == ["a", "b", "c"]
    path = jam.ssid_file(["x", "y"])
    with open(path, encoding="utf-8") as fh:
        assert fh.read().split() == ["x", "y"]


def test_beacon_argv_uses_a_list_file_when_given():
    argv = jam.mdk4_argv("beacon", "wlan0mon", ssid_path="ssids.txt",
                         channel=6, pps=500)
    assert argv[:4] == ["mdk4", "wlan0mon", "b", "-f"]
    assert argv[argv.index("-c") + 1] == "6"


def test_a_targeted_flood_requires_a_bssid():
    with pytest.raises(ValueError):
        jam.mdk4_argv("auth", "wlan0mon")
    with pytest.raises(ValueError):
        jam.mdk4_argv("beacon", "wlan0mon")


def test_each_mode_builds_its_own_flags():
    auth = jam.mdk4_argv("auth", "mon0", bssid=BSSID, channel=1)
    assert auth[2] == "a" and "-a" in auth
    deauth = jam.mdk4_argv("deauth", "mon0", bssid=BSSID, reason=1,
                           client="11:22:33:44:55:66")
    assert deauth[2] == "d"
    assert deauth[deauth.index("-r") + 1] == "1"
    assert deauth[deauth.index("-E") + 1] == "11:22:33:44:55:66"
    eapol = jam.mdk4_argv("eapol", "mon0", bssid=BSSID, ssid="Cafe")
    assert eapol[2] == "e" and eapol[eapol.index("-e") + 1] == "Cafe"


def test_aireplay_fallback_is_a_real_command():
    argv = jam.aireplay_argv(BSSID, "mon0", count=32, reason=3)
    assert argv[0] == "aireplay-ng" and argv[1] == "--deauth"
    assert argv[2] == "32" and "--reason=3" in argv
    with pytest.raises(ValueError):
        jam.aireplay_argv("", "mon0")


class FakeChild:
    """Stands in for the mdk4 process the runner spawns."""

    def __init__(self):
        self.terminated = False

    def terminate(self):
        self.terminated = True


def test_jammer_walks_the_plan_and_stops_each_flood(monkeypatch):
    monkeypatch.setattr(jam.proc, "has", lambda name: name == "mdk4")
    tuned, ran = [], []
    child = FakeChild()

    def runner(argv, dwell, spawner):
        ran.append((argv, dwell))
        jam._run_argv(argv, dwell, spawner)

    jammer = jam.Jammer("mon0", "deauth", [(1, 0.2), (6, 0.2)], bssid=BSSID,
                        pps=100,
                        setter=lambda iface, channel: tuned.append(
                            (iface, channel)),
                        runner=runner,
                        spawner=lambda argv: child)
    report = jammer.run()
    assert tuned == [("mon0", 1), ("mon0", 6)]
    assert len(ran) == 2 and child.terminated is True
    assert report["tool"] == "mdk4" and report["slots"] == 2
    assert report["frames"] == 40


def test_jammer_prefers_aireplay_when_mdk4_is_missing(monkeypatch):
    monkeypatch.setattr(jam.proc, "has", lambda name: name == "aireplay-ng")
    seen = []
    jammer = jam.Jammer("mon0", "deauth", [(1, 0.1)], bssid=BSSID, pps=100,
                        setter=lambda *args: True,
                        runner=lambda argv, dwell, spawner: seen.append(argv))
    jammer.run()
    assert seen and seen[0][0] == "aireplay-ng"


def test_auth_flood_without_any_tool_is_an_expected_failure(monkeypatch):
    monkeypatch.setattr(jam.proc, "has", lambda name: False)
    jammer = jam.Jammer("mon0", "auth", [(1, 0.1)], bssid=BSSID)
    with pytest.raises(RuntimeError):
        jammer.run()


def test_beacon_falls_back_to_airodump_when_mdk4_is_absent(monkeypatch):
    monkeypatch.setattr(jam.proc, "has", lambda name: False)
    jammer = jam.Jammer("mon0", "beacon", [(1, 0.1)], ssid="Free WiFi")
    assert jammer.resolve_tool() == "airodump"


def test_pick_target_prefers_the_strongest_signal():
    aps = [{"bssid": "aa:aa:aa:aa:aa:aa", "signal": -80},
           {"bssid": "bb:bb:bb:bb:bb:bb", "signal": -41}]
    assert pick_target(aps)["bssid"].startswith("bb")
    assert pick_target(aps, "AA:AA:AA:AA:AA:AA")["signal"] == -80
    assert pick_target([]) is None


def test_jam_module_is_registered():
    from omni.core.module import registry

    assert "wifi.jam" in {module.NAME for module in registry.all("wifi")}
