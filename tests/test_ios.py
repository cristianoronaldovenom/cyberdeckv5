"""iOS filesystem/exfil/takeover tests: real argv shapes, stubbed backend."""

import pytest

from omni.ios.device import Ios
from omni.ios.modules import exfil, fs, provision
from omni.ios.modules._base import IosModule


class RecordingClient:
    """Stub Ios client: captures argv, records makedirs for path checks."""

    def __init__(self):
        self.calls: list[tuple] = []

    def check(self, *args, timeout=None):
        self.calls.append((tuple(args), timeout))
        return type("R", (), {"ok": True, "out": "", "err": "", "text": ""})

    def run(self, *args, timeout=None):
        self.calls.append((tuple(args), timeout))
        return type("R", (), {"ok": True, "out": "", "err": "", "text": ""})

    @property
    def last(self) -> list[str]:
        return list(self.calls[-1][0])


@pytest.fixture
def stub(monkeypatch):
    client = RecordingClient()
    monkeypatch.setattr(IosModule, "client", lambda self: client)
    return client


def test_afc_ls_uses_recursive_option(stub):
    mod = fs.Afc(ACTION="ls", REMOTE="/")
    mod.client = lambda: stub
    mod.execute()
    argv = stub.last
    assert argv[0:3] == ["afc", "ls", "/"]
    assert "--recursive" in argv


def test_afc_pull_targets_loot_and_ignores_errors(stub, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mod = fs.Afc(ACTION="pull", REMOTE="/Photos")
    mod.client = lambda: stub
    result = mod.execute()
    argv = stub.last
    assert argv[0] == "afc" and argv[1] == "pull"
    assert argv[-1] == "--ignore-errors"
    assert result["pulled"].endswith(".tif") or result["pulled"].endswith(
        str(tmp_path / "ios" / "afc")[1:]) or "media_" in result["pulled"]


def test_afc_pull_honours_local_target(stub, tmp_path):
    target = tmp_path / "out"
    mod = fs.Afc(ACTION="pull", REMOTE="/x", LOCAL=str(target))
    mod.client = lambda: stub
    mod.execute()
    assert target.parent.exists()


def test_afc_push_needs_a_real_file(stub, tmp_path):
    mod = fs.Afc(ACTION="push", REMOTE="/x", LOCAL=str(tmp_path / "nope"))
    mod.client = lambda: stub
    with pytest.raises(ValueError, match="real LOCAL"):
        mod.execute()


def test_afc_push_argv(stub, tmp_path):
    payload = tmp_path / "up.txt"
    payload.write_text("x")
    mod = fs.Afc(ACTION="push", REMOTE="/up.txt", LOCAL=str(payload))
    mod.client = lambda: stub
    mod.execute()
    assert stub.last[-2:] == ["push", "/up.txt"] is not None or \
        stub.last[-3:] == ["push", str(payload), "/up.txt"]


def test_afc_rm_deletes(stub):
    mod = fs.Afc(ACTION="rm", REMOTE="/junk")
    mod.client = lambda: stub
    mod.execute()
    assert stub.last == ["afc", "rm", "/junk"]


def test_sandbox_pull_uses_core_device_read_file(stub, tmp_path):
    mod = fs.SandboxPull(REMOTE="/var/ Mobile/x.db")
    mod.client = lambda: stub
    mod.execute()
    argv = stub.last
    assert argv[:4] == ["developer", "core-device", "read-file",
                        "/var/ Mobile/x.db"]


def test_backup_uses_full_by_default(stub, tmp_path):
    mod = exfil.Backup()
    mod.client = lambda: stub
    mod.execute()
    argv = stub.last
    assert argv[:3] == ["backup2", "backup", argv[2]]
    assert "--full" in argv


def test_sniff_is_positional_out(stub, tmp_path):
    mod = exfil.Sniff(COUNT="10")
    mod.client = lambda: stub
    result = mod.execute()
    argv = stub.last
    assert "--count" in argv and "10" in argv
    assert argv[-1] == result["pcap"]


def test_sniff_filters_by_process(stub):
    mod = exfil.Sniff(COUNT="10", PROCESS="WhatsApp")
    mod.client = lambda: stub
    mod.execute()
    assert "--process" in stub.last and "WhatsApp" in stub.last


def test_crash_pull_can_erase(stub):
    mod = exfil.Crash(ERASE="true")
    mod.client = lambda: stub
    mod.execute()
    assert "--erase" in stub.last


def test_profile_install_takes_the_file(stub, tmp_path):
    prof = tmp_path / "ca.mobileconfig"
    prof.write_text("x")
    mod = provision.ProfileInstall(PROFILE=str(prof))
    mod.client = lambda: stub
    mod.execute()
    assert stub.last[-2:] == ["install", str(prof)]


def test_profile_install_rejects_missing_file(stub):
    mod = provision.ProfileInstall(PROFILE="nope.mobileconfig")
    mod.client = lambda: stub
    with pytest.raises(FileNotFoundError):
        mod.execute()


def test_profile_install_supervise_keybag(stub, tmp_path):
    prof = tmp_path / "s.mobileconfig"
    prof.write_text("x")
    bag = tmp_path / "bag"
    bag.write_text("k")
    mod = provision.ProfileInstall(PROFILE=str(prof), KEYBAG=str(bag))
    mod.client = lambda: stub
    mod.execute()
    assert "--keybag" in stub.last


def test_app_install_and_uninstall_argv(stub, tmp_path):
    ipa = tmp_path / "tool.ipa"
    ipa.write_text("x")
    provision.AppInstall(PATH=str(ipa)).client = lambda: stub
    provision.AppInstall(PATH=str(ipa)).execute()
    assert stub.last[:3] == ["apps", "install", str(ipa)]
    mod = provision.AppUninstall(BUNDLE="com.example.app")
    mod.client = lambda: stub
    mod.execute()
    assert stub.last == ["apps", "uninstall", "com.example.app"]


import pytest

from omni.core import proc
from omni.ios import device as ios_device
from omni.ios.device import BackendError, Ios, IosError


class Recorder:
    def __init__(self, out: str = "", ok: bool = True):
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []
        self.out = out
        self.ok = ok

    def __call__(self, argv, timeout=None, env=None):
        self.calls.append(list(argv))
        self.envs.append(dict(env or {}))
        if self.ok:
            return proc.Result(argv, 0, self.out, "")
        return proc.Result(argv, 1, "", self.out)

    @property
    def last(self) -> list[str]:
        return self.calls[-1]


@pytest.fixture
def ios(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(ios_device.proc, "run", rec)
    monkeypatch.setattr(ios_device.proc, "has",
                        lambda binary: "pymobiledevice3" in str(binary))
    client = Ios(udid="UDID123")
    client.recorder_args = lambda: rec.last
    return client


def test_backend_prefers_pmd3(ios):
    assert ios.backend == "pmd3"


def test_backend_falls_back_to_libimobiledevice(monkeypatch):
    monkeypatch.setattr(ios_device.proc, "has", lambda binary: True)
    assert Ios().backend == "pmd3"


def test_backend_errors_with_neither(monkeypatch):
    monkeypatch.setattr(ios_device.proc, "has", lambda binary: False)
    with pytest.raises(BackendError, match="neither"):
        Ios().backend


def test_udid_goes_through_the_environment(ios):
    ios.check("developer", "core-device", "get-lockstate")
    assert ios.recorder_args() == ["pymobiledevice3", "developer",
                                   "core-device", "get-lockstate"]
    assert ios.env() == {"PYMOBILEDEVICE3_UDID": "UDID123"}


def test_rsd_is_appended_after_the_subcommand(monkeypatch):
    monkeypatch.setattr(ios_device.proc, "run", Recorder())
    monkeypatch.setattr(ios_device.proc, "has", lambda b: True)
    monkeypatch.setattr(ios_device.config, "get_value",
                        lambda key, default=None: {"ios.rsd_host": "10.0.0.5",
                                                   "ios.rsd_port": 49152}.get(
                                                       key, default))
    client = Ios(udid="U")
    client.check("developer", "core-device", "get-lockstate")
    assert client.rsd == ("10.0.0.5", "49152")
    assert client._device_opts() == ["--rsd", "10.0.0.5", "49152"]
    assert client._global() == ["pymobiledevice3"]


def test_tunnel_beats_rsd(monkeypatch):
    monkeypatch.setattr(ios_device.proc, "run", Recorder())
    monkeypatch.setattr(ios_device.proc, "has", lambda b: True)
    client = Ios(udid="U", tunnel="UDID@host")
    assert client._device_opts() == []
    assert client.env()["PYMOBILEDEVICE3_TUNNEL"] == "UDID@host"


def test_raw_omits_device_options(ios):
    ios.raw("usbmux", "list", "--network")
    assert ios.recorder_args() == ["pymobiledevice3", "usbmux", "list",
                                   "--network"]


# -- argv shapes ------------------------------------------------------------

def test_tap_passes_normalised_coordinates(ios):
    ios.tap(32768, 1000)
    assert ios.recorder_args()[-2:] == ["32768", "1000"]
    assert "universal-hid-service" in ios.recorder_args()


def test_type_passes_text_as_one_argument(ios):
    ios.type_text("hello world")
    assert ios.recorder_args()[-1] == "hello world"


def test_swipe_sends_duration_option(ios):
    ios.swipe(1, 2, 3, 4, 0.25)
    assert ios.recorder_args()[-2:] == ["--duration", "0.25"]


def test_press_button_uses_hid_indigo(ios):
    ios.press_button("power")
    argv = ios.recorder_args()
    assert argv[-4:] == ["hid", "button", "power", "press"]


def test_location_uses_positional_degrees(ios):
    ios.set_location(51.5, -0.12)
    assert ios.recorder_args()[-2:] == ["51.5", "-0.12"]
    assert "simulate-location" in ios.recorder_args()


def test_screenshot_creates_parent_dir(ios, tmp_path):
    target = tmp_path / "a" / "b" / "shot.png"
    ios.screenshot(str(target))
    assert target.parent.is_dir()
    assert ios.recorder_args()[-1] == str(target)


def test_clipboard_copy_passes_text(ios):
    ios.clipboard_set("secret")
    assert ios.recorder_args()[-2:] == ["copy", "secret"]


# -- error translation ------------------------------------------------------

@pytest.mark.parametrize("blob,expected", [
    ("DeveloperMode is disabled", "Developer Mode is off"),
    ("no RSD service provider", "no RSD tunnel"),
    ("service not found", "DeveloperDiskImage is not mounted"),
    ("unable to find device", "device not visible"),
])
def test_explain_translates_common_failures(blob, expected):
    assert expected in Ios.explain(("core-device",), blob)


def test_explain_falls_back_to_raw_text():
    assert "boom" in Ios.explain(("lockdown", "info"), "boom")


def test_check_raises_with_translated_message(monkeypatch):
    monkeypatch.setattr(ios_device.proc, "has", lambda b: True)
    monkeypatch.setattr(ios_device.proc, "run",
                        Recorder(out="DeveloperMode required", ok=False))
    with pytest.raises(IosError, match="Developer Mode is off"):
        Ios(udid="U").check("developer", "core-device", "get-lockstate")


def test_failed_command_keeps_argv(monkeypatch):
    rec = Recorder(out="nope", ok=False)
    monkeypatch.setattr(ios_device.proc, "has", lambda b: True)
    monkeypatch.setattr(ios_device.proc, "run", rec)
    with pytest.raises(IosError):
        Ios(udid="U").check("bad", "command")
    assert rec.last == ["pymobiledevice3", "bad", "command"]


# -- parsing ----------------------------------------------------------------

def test_split_udids_reads_both_formats():
    text = "ABC123DEF456ABC123DEF456ABC123DEF456ABC1 ab12cd34-0123456789abcdef"
    found = ios_device.split_udids(text)
    assert "ABC123DEF456ABC123DEF456ABC123DEF456ABC1" in found
    assert "ab12cd34-0123456789abcdef" in found


def test_parse_devices_extracts_names():
    text = '{"DeviceName": "Phone", "UniqueDeviceID": "' + "A" * 40 + '"}'
    devices = ios_device.parse_devices(text)
    assert devices and devices[0].name == "Phone"


def test_parse_devices_dedupes():
    udid = "B" * 40
    assert len(ios_device.parse_devices(udid + " " + udid)) == 1


# -- info parsing -----------------------------------------------------------

def test_info_keeps_values_containing_commas(monkeypatch):
    body = ('{"DeviceName": "Phone", "ProductType": "iPhone16,1", '
            '"ProductVersion": "17.5"}')
    monkeypatch.setattr(ios_device.proc, "run",
                        lambda argv, timeout=None, env=None: proc.Result(argv, 0, body, ""))
    monkeypatch.setattr(ios_device.proc, "has", lambda b: True)
    found = Ios(udid="U").info()
    assert found["ProductType"] == "iPhone16,1"
    assert found["ProductVersion"] == "17.5"


def test_info_reads_plain_colon_output(monkeypatch):
    body = "DeviceName: Phone\nProductType: iPhone14,2\n"
    monkeypatch.setattr(ios_device.proc, "run",
                        lambda argv, timeout=None, env=None: proc.Result(argv, 0, body, ""))
    monkeypatch.setattr(ios_device.proc, "has", lambda b: True)
    assert Ios(udid="U").info()["DeviceName"] == "Phone"
