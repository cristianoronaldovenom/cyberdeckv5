"""Trust-bypass tests: record handling, route scoring, argv shapes.

The interesting logic (what a pair record buys, which route is cheapest) is
pure, so most of this runs with no device at all. The module tests use the same
recording-stub trick as ``test_ios.py``.
"""

import os
import plistlib

import pytest

from omni.ios import connect as link
from omni.ios import trust
from omni.ios.device import IosError
from omni.ios.modules import bypass
from omni.ios.modules._base import IosModule

UDID = "A" * 40
HOST_ID = "ABCD1234-0000-1111-2222-333344445555"
OTHER_HOST = "11111111-2222-3333-4444-555555555555"


def record_file(tmp_path, udid=UDID, escrow=False) -> str:
    payload = {"UDID": udid, "HostID": "HOST-1",
               "HostCertificate": b"cert", "HostPrivateKey": b"key"}
    if escrow:
        payload["EscrowBag"] = b"bag"
        payload["RootPrivateKey"] = b"root"
    path = tmp_path / f"{udid}.plist"
    path.write_bytes(plistlib.dumps(payload))
    return str(path)


# -- records ----------------------------------------------------------------

def test_load_record_reads_key_material(tmp_path):
    record = trust.load_record(record_file(tmp_path))
    assert record is not None and record.usable
    assert record.udid == UDID and record.readable


def test_load_record_rejects_non_plist(tmp_path):
    path = tmp_path / "junk.plist"
    path.write_text("not a plist")
    assert trust.load_record(str(path)) is None


def test_record_without_a_host_key_is_not_authorization(tmp_path):
    path = tmp_path / f"{UDID}.plist"
    path.write_bytes(plistlib.dumps({"UDID": UDID}))
    assert trust.load_record(str(path)).usable is False


def test_scan_finds_records_in_a_store(tmp_path):
    record_file(tmp_path)
    assert [r.udid for r in trust.scan_records([str(tmp_path)])] == [UDID]


def test_scan_tolerates_a_missing_store():
    assert trust.scan_records(["/nope/nothing"]) == []


def test_escrow_bag_adds_backup_decrypt(tmp_path):
    plain = trust.load_record(record_file(tmp_path))
    rich = trust.load_record(record_file(tmp_path, escrow=True))
    assert any("backup" in c for c in trust.describe_capabilities(rich))
    assert not any("backup" in c for c in trust.describe_capabilities(plain))


# -- bootrom ----------------------------------------------------------------

@pytest.mark.parametrize("model,soc", [("iPhone10,3", "A11"),
                                       ("iPhone6,1", "A7"),
                                       ("iPad7,11", "A10")])
def test_checkm8_flags_old_socs(model, soc):
    assert trust.checkm8_status(model) == ("vulnerable", soc)


@pytest.mark.parametrize("model", ["iPhone14,2", "iPhone16,1", "iPad13,1"])
def test_checkm8_clears_modern_socs(model):
    assert trust.checkm8_status(model)[0] == "patched"


def test_checkm8_unknown_without_a_model():
    assert trust.checkm8_status("") == ("unknown", "")


# -- posture + routes -------------------------------------------------------

def posture(**kwargs) -> trust.Posture:
    return trust.Posture(**kwargs)


def test_record_replay_is_the_cheapest_open_route(tmp_path):
    state = posture(records=[trust.load_record(record_file(tmp_path))])
    routes = trust.assess(state)
    assert routes[0].key == "record-replay" and routes[0].applicable
    assert trust.verdict(routes)[1] == "none"


def test_unpaired_device_falls_back_to_the_trust_tap():
    assert trust.verdict(trust.assess(posture()))[0] == "trust-tap"


def test_blocked_routes_carry_a_blocker():
    for route in trust.assess(posture()):
        if not route.applicable:
            assert route.blocker and route.row()[-1] == "-"


def test_supervised_device_offers_the_keybag_route():
    routes = trust.assess(posture(supervised=True))
    assert next(r for r in routes if r.key == "supervised-pair").applicable


def test_wifi_sync_route_closes_once_it_is_on():
    route = next(r for r in trust.assess(posture(paired=True, wifi_sync=True))
                 if r.key == "wifi-sync")
    assert not route.applicable and "already" in route.blocker


def test_lan_route_needs_both_a_record_and_an_advert(tmp_path):
    records = [trust.load_record(record_file(tmp_path))]
    assert next(r for r in trust.assess(posture(records=records))
                if r.key == "lan-control").applicable is False
    assert next(r for r in trust.assess(
        posture(records=records, network_devices=1))
        if r.key == "lan-control").applicable is True


def test_routes_sort_cheapest_interaction_first():
    ranks = [r.rank for r in trust.assess(posture(paired=True))]
    assert ranks == sorted(ranks)


# -- parsing ----------------------------------------------------------------

def test_parse_bonjour_reads_json():
    text = '[{"udid": "%s", "ip": "10.0.0.9"}]' % UDID
    assert trust.parse_bonjour(text)[0]["ip"] == "10.0.0.9"


def test_parse_bonjour_reads_dns_sd_text():
    found = trust.parse_bonjour(f"  phone.local. {UDID} 62078\n")
    assert found and found[0]["host"] == "phone.local"
    assert found[0]["port"] == "62078"


def test_parse_wifi_state_accepts_json_and_prose():
    assert trust.parse_wifi_state('{"EnableWifiConnections": true}')
    assert trust.parse_wifi_state("true")
    assert not trust.parse_wifi_state('{"EnableWifiConnections": false}')
    assert not trust.parse_wifi_state("")


# -- modules ----------------------------------------------------------------

class RecordingClient:
    """Captures argv; enough surface for trust.snapshot()."""

    def __init__(self, info=None):
        self.calls: list[tuple] = []
        self.udid = UDID
        self.info_map = info if info is not None else {
            "DeviceName": "iPhone", "ProductType": "iPhone14,2",
            "ProductVersion": "18.1", "UniqueDeviceID": UDID}

    def check(self, *args, timeout=None):
        self.calls.append((tuple(args), timeout))
        return type("R", (), {"ok": True, "out": "{}", "err": "",
                              "text": "{}"})()

    def run(self, *args, timeout=None):
        if args[:3] == ("lockdown", "get", "com.apple.mobile.lockdown") \
                and args[-1] == "HostID":
            return type("R", (), {"ok": True, "out": HOST_ID, "err": "",
                                  "text": HOST_ID})()
        return self.check(*args, timeout=timeout)

    def raw(self, *args, timeout=None):
        self.calls.append((tuple(args), timeout))
        return type("R", (), {"ok": True, "out": "", "err": "", "text": ""})()

    def info(self):
        return dict(self.info_map)

    def is_paired(self):
        return True

    def wifi_connections(self, state=None):
        if state:
            self.calls.append((("lockdown", "wifi-connections", state), 60))
        return '{"EnableWifiConnections": false}'

    def save_pair_record(self, path):
        self.calls.append((("lockdown", "save-pair-record", path), 120))
        return path

    def remotepairing(self, pair=True):
        self.calls.append((("remotepair", pair), 180))
        return ""

    def pair_supervised(self, keybag):
        self.calls.append((("supervised", keybag), 180))
        return ""

    def trusted_hosts(self):
        return '["%s", "%s"]' % (HOST_ID, "11111111-2222-3333-4444-555555555555")

    def unpair(self, host_id=""):
        self.calls.append((("unpair", host_id), 120))

    def heartbeat(self, seconds=30):
        self.calls.append((("heartbeat", seconds), seconds))
        return True

    def lock_state(self):
        return "Unlocked"


@pytest.fixture
def stub(monkeypatch):
    client = RecordingClient()
    monkeypatch.setattr(IosModule, "client", lambda self: client)
    return client


def test_wifi_sync_get_reads_the_flag(stub):
    assert bypass.SyncWifi(ACTION="get").execute()["enabled"] is False


def test_wifi_sync_on_passes_the_word(stub):
    bypass.SyncWifi(ACTION="on").execute()
    assert (("lockdown", "wifi-connections", "on"), 60) in stub.calls


def test_remote_pair_refuses_an_untrusted_host(monkeypatch, stub):
    monkeypatch.setattr(stub, "is_paired", lambda: False)
    with pytest.raises(IosError, match="not trusted"):
        bypass.RemotePair().execute()


def test_remote_pair_asks_for_the_promptless_bootstrap(monkeypatch, stub):
    monkeypatch.setattr(
        stub, "remotepairing",
        lambda pair=True: stub.calls.append(("remotepair", pair)) or "")
    bypass.RemotePair().execute()
    assert ("remotepair", True) in stub.calls


def test_supervised_pair_checks_the_keybag(stub, tmp_path):
    mod = bypass.SupervisedPair(KEYBAG=str(tmp_path / "nope.plist"))
    with pytest.raises(FileNotFoundError, match="no such keybag"):
        mod.execute()


def test_supervised_pair_runs_the_keybag_command(monkeypatch, stub, tmp_path):
    keybag = tmp_path / "kb.plist"
    keybag.write_text("x")
    monkeypatch.setattr(stub, "is_paired", lambda: False)
    monkeypatch.setattr(stub, "pair_supervised",
                        lambda path: stub.calls.append(("supervised", path))
                        or "")
    bypass.SupervisedPair(KEYBAG=str(keybag)).execute()
    assert ("supervised", str(keybag)) in stub.calls


def test_record_show_needs_a_real_file(stub, tmp_path):
    with pytest.raises(FileNotFoundError):
        bypass.Record(ACTION="show",
                      RECORD=str(tmp_path / "missing.plist")).execute()


def test_record_scan_reports_an_empty_store(monkeypatch):
    monkeypatch.setattr(trust, "scan_records", lambda dirs=None: [])
    monkeypatch.setattr(trust, "record_dirs", lambda home=None: [])
    assert bypass.Record(ACTION="scan").execute()["records"] == []


def test_record_export_uses_save_pair_record(monkeypatch, stub, tmp_path):
    target = tmp_path / "out.plist"

    def fake_save(path):
        with open(path, "wb") as fh:
            fh.write(plistlib.dumps({"UDID": UDID, "HostPrivateKey": b"k"}))
        return path

    monkeypatch.setattr(stub, "save_pair_record", fake_save)
    result = bypass.Record(ACTION="export", RECORD=str(target)).execute()
    assert result["udid"] == UDID and os.path.isfile(target)


def test_record_plant_copies_into_the_store(tmp_path):
    source = record_file(tmp_path)
    store = tmp_path / "lockdown"
    result = bypass.Record(ACTION="plant", RECORD=source, DIR=str(store),
                           UDID=UDID).execute()
    planted = store / f"{UDID}.plist"
    assert planted.is_file() and result["planted"] == str(planted)


def test_discover_parses_bonjour_hits(monkeypatch, stub):
    payload = '[{"udid": "%s", "hostname": "10.0.0.9", "port": 62078}]' % UDID
    monkeypatch.setattr(stub, "raw", lambda *a, timeout=None: type(
        "R", (), {"ok": True, "out": payload, "err": "", "text": payload})())
    monkeypatch.setattr(stub, "have_pmd3", lambda: True, raising=False)
    monkeypatch.setattr(bypass, "Ios", lambda udid=None: stub)
    monkeypatch.setattr(bypass, "_port_open",
                        lambda host, port=62078, timeout=1.5: True)
    result = bypass.Discover(SECONDS="1").execute()
    assert result["devices"] and result["devices"][0][3] == "yes"


def test_checkm8_marks_an_a15_patched(stub):
    assert bypass.Bootrom().execute()["bootrom"] == "patched"


def test_checkm8_offers_the_tool_for_an_a11(monkeypatch):
    client = RecordingClient({"ProductType": "iPhone10,3",
                              "ProductVersion": "16.7"})
    monkeypatch.setattr(IosModule, "client", lambda self: client)
    monkeypatch.setattr(bypass.proc, "has", lambda binary: binary == "palera1n")
    assert bypass.Bootrom()._argv("palera1n")[-2:] == ["-f", "-c"]


def test_takeover_reports_control(monkeypatch, stub):
    monkeypatch.setattr(trust, "scan_records", lambda dirs=None: [])
    monkeypatch.setattr(bypass, "_prove_control", lambda client: (True, "ok"))
    result = bypass.Takeover(AUTO="false").execute()
    assert result["controlled"] is True and result["route"]


# -- trust census -----------------------------------------------------------

def test_parse_host_ids_dedupes_and_ignores_noise():
    text = '["%s", "%s", "%s"]' % (HOST_ID, HOST_ID.lower(), OTHER_HOST)
    assert trust.parse_host_ids(text) == [HOST_ID, OTHER_HOST]


def test_hosts_marks_our_own_record(stub, capsys):
    result = bypass.Hosts(ACTION="list").execute()
    assert result["ours"] == HOST_ID
    assert OTHER_HOST in result["hosts"]
    assert "this host" in capsys.readouterr().out


def test_hosts_keep_only_revokes_the_others(stub):
    result = bypass.Hosts(ACTION="keep-only").execute()
    assert result["revoked"] == [OTHER_HOST]
    assert (("unpair", OTHER_HOST), 120) in stub.calls


def test_heartbeat_reports_the_session_held(stub):
    assert bypass.Heartbeat(SECONDS="3").execute()["held"] is True


def test_ssh_argv_prefers_sshpass(monkeypatch):
    monkeypatch.setattr(bypass.proc, "has", lambda binary: binary == "sshpass")
    argv = bypass._ssh_argv("root", "127.0.0.1", 2222, "alpine", "id")
    assert argv[0] == "sshpass" and argv[-1] == "id"
    assert "root@127.0.0.1" in argv


def test_ssh_argv_without_sshpass_still_targets_the_device(monkeypatch):
    monkeypatch.setattr(bypass.proc, "has", lambda binary: False)
    argv = bypass._ssh_argv("root", "127.0.0.1", 2222, "alpine", "id")
    assert argv[0] == "ssh" and argv[-1] == "id"


def test_steal_needs_a_host(stub):
    with pytest.raises(ValueError, match="USERHOST"):
        bypass.Record(ACTION="steal").execute()


def test_steal_writes_and_parses_a_record(monkeypatch, tmp_path):
    import base64

    payload = plistlib.dumps({"UDID": UDID, "HostPrivateKey": b"k",
                              "HostCertificate": b"c"})
    monkeypatch.setattr(
        bypass.proc, "run",
        lambda argv, timeout=None: type(
            "R", (), {"ok": True, "out": base64.b64encode(payload).decode(),
                      "err": "", "text": ""})())
    monkeypatch.setattr(bypass, "_plant_dirs",
                        lambda: [str(tmp_path / "store")])
    monkeypatch.setattr(bypass.Record, "_udid_hint", lambda self: UDID)
    result = bypass.Record(ACTION="steal",
                           USERHOST="root@backup-box").execute()
    assert result["udid"] == UDID
    assert (tmp_path / "store" / f"{UDID}.plist").is_file()


def test_record_steal_route_needs_another_host(tmp_path):
    records = [trust.load_record(record_file(tmp_path))]
    assert next(r for r in trust.assess(posture(records=records))
                if r.key == "record-steal").applicable is False
    assert next(r for r in trust.assess(
        posture(other_hosts=[OTHER_HOST]))
        if r.key == "record-steal").applicable is True


def test_ssh_root_route_closes_without_sshd():
    assert next(r for r in trust.assess(posture(jailbroken=True))
                if r.key == "ssh-root").applicable is True
    assert next(r for r in trust.assess(posture())
                if r.key == "ssh-root").applicable is False


# -- the connection ladder ---------------------------------------------------

class LinkClient:
    """Fake transport: controlled untrusted/trusted/dialog behaviour."""

    def __init__(self, presence=("USB",), untrusted=False, trust_on_pair=False):
        self.have_pmd3 = lambda: True
        self.udid = UDID
        self.presence = presence
        self.untrusted = untrusted
        self.trust_on_pair = trust_on_pair
        self.calls: list[tuple] = []

    def devices(self):
        return [type("D", (), {"udid": UDID})()] if "USB" in self.presence \
            else []

    def raw(self, *args, timeout=None):
        out = UDID if "Network" in self.presence else ""
        return type("R", (), {"ok": True, "out": out, "err": "", "text": out})()

    def info(self):
        return {"UniqueDeviceID": UDID}

    def run(self, *args, timeout=None):
        self.calls.append(tuple(args))
        if args[:2] == ("lockdown", "pair"):
            if self.trust_on_pair:
                self.untrusted = False
            return type("R", (), {"ok": True, "out": "", "err": "",
                                  "text": "PairingDialogResponsePending"})()
        text = "NotTrustedError: device does not trust" if self.untrusted \
            else '{"HostID": "%s"}' % HOST_ID
        return type("R", (), {"ok": not self.untrusted, "out": text,
                              "err": text, "text": text})()


@pytest.mark.parametrize("text,state", [
    ("NotTrustedError: not trusted", "untrusted"),
    ("PairingDialogResponsePendingError", "dialog"),
    ("NoDeviceConnectedError: no device", "no-device"),
    ("something else entirely", "error"),
])
def test_classify_states(text, state):
    assert link.classify(text) == state


def test_reach_prefers_usb_and_dedupes_the_same_device():
    assert link.reach(LinkClient(presence=("USB", "Network"))) == [
        ("USB", UDID)]
    assert link.reach(LinkClient(presence=("Network",))) == [("Network", UDID)]
    assert link.reach(LinkClient(presence=())) == []


def test_ladder_stops_on_no_device():
    report = link.ladder(LinkClient(presence=()))
    assert report.state == "no-device"
    assert "nothing visible" in link.verdict(report)


def test_ladder_reports_untrusted_and_stops_probing():
    client = LinkClient(untrusted=True)
    report = link.ladder(client)
    assert report.state == "untrusted"
    assert report.visible and not report.connected
    # the first probe failed untrusted, so later probes are not attempted
    assert len(client.calls) == 1


def test_ladder_ok_when_trusted():
    report = link.ladder(LinkClient())
    assert report.connected and report.state == "ok"


def test_visibility_alone_is_not_a_connection():
    report = link.Report([link.Attempt(link.VISIBLE_STEP, "ok", "USB")])
    assert report.visible and not report.connected
    assert report.state == "untrusted"


def test_connect_without_promptless_does_not_pair():
    client = LinkClient(untrusted=True)
    report = link.connect(client, promptless=False)
    assert report.state == "untrusted"
    assert ("lockdown", "pair") not in client.calls


def test_connect_pairs_and_polls_until_trusted():
    client = LinkClient(untrusted=True, trust_on_pair=True)
    ticks = iter(range(1000))
    report = link.connect(client, promptless=True, wait=5, pause=0,
                          clock=lambda: next(ticks))
    assert ("lockdown", "pair") in client.calls
    assert report.connected and report.state == "ok"


def test_connect_gives_up_after_the_wait():
    client = LinkClient(untrusted=True)
    ticks = iter(range(1000))
    report = link.connect(client, promptless=True, wait=2, pause=0,
                          clock=lambda: next(ticks))
    assert not report.connected
    assert any(a.step == "pair-verify" for a in report.attempts)


def test_probe_module_surfaces_the_ladder(monkeypatch, stub):
    monkeypatch.setattr(link, "ladder",
                        lambda client: link.Report(
                            [link.Attempt("lockdown info", "ok", "trusted")]))
    result = bypass.Probe().execute()
    assert result["state"] == "ok" and result["attempts"]


def test_connect_module_saves_the_device(monkeypatch, stub):
    monkeypatch.setattr(link, "connect",
                        lambda client, promptless=True, wait=25:
                        link.Report([link.Attempt("pair-verify", "ok", "x")]))
    saved = {}
    monkeypatch.setattr(bypass.config, "set_value",
                        lambda key, value: saved.update({key: value}))
    monkeypatch.setattr(bypass.Ios, "__init__",
                        lambda self, udid=None, **kw: None)
    monkeypatch.setattr(bypass.Ios, "have_pmd3", lambda self: True,
                        raising=False)
    monkeypatch.setattr(bypass.Ios, "udid", UDID, raising=False)
    result = bypass.Connect().execute()
    assert result["state"] == "ok"
    assert saved["ios.udid"] == UDID


def test_supervised_connect_needs_the_keybag(monkeypatch, stub, tmp_path):
    monkeypatch.setattr(bypass.Ios, "have_pmd3", lambda self: True,
                        raising=False)
    mod = bypass.Connect(KEYBAG=str(tmp_path / "missing.plist"))
    with pytest.raises(FileNotFoundError, match="no such keybag"):
        mod.execute()
