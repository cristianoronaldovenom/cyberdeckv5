"""iOS filesystem/interception tests: real argv shapes, stubbed client."""

import pytest

from omni.ios.modules import devfs, intercept
from omni.ios.modules._base import IosModule


class Stub:
    def __init__(self, out=""):
        self.calls: list[list[str]] = []
        self.out = out

    def _r(self):
        return type("R", (), {"ok": True, "out": self.out, "err": "",
                              "text": self.out})

    def check(self, *args, timeout=None):
        self.calls.append(list(args))
        return self._r()

    def run(self, *args, timeout=None):
        self.calls.append(list(args))
        return self._r()

    def apps(self):
        return ["com.apple.mobilesafari", "com.whatsapp.WhatsApp"]

    @property
    def last(self) -> list[str]:
        return self.calls[-1]


@pytest.fixture
def stub():
    return Stub()


def wire(mod, stub):
    mod.client = lambda: stub
    return mod


# -- domains ----------------------------------------------------------------

def test_domains_are_exposed_as_choices():
    assert "appData" in devfs.DOMAINS and "root" in devfs.DOMAINS


def test_ls_passes_domain_and_path(stub):
    wire(devfs.Ls(DOMAIN="appData", PATH="Documents"), stub).execute()
    assert stub.last == ["developer", "core-device", "list-directory",
                         "appData", "Documents"]


def test_ls_can_scope_to_a_bundle(stub):
    wire(devfs.Ls(DOMAIN="appData", PATH=".", BUNDLE="com.x"), stub).execute()
    assert stub.last[-2:] == ["--identifier", "com.x"]


def test_ls_returns_entries(stub):
    stub.out = "Documents\nLibrary\n"
    wire(devfs.Ls(DOMAIN="appData", PATH="."), stub)
    assert stub_out_entries(stub) == ["Documents", "Library"]


def stub_out_entries(stub):
    mod = wire(devfs.Ls(DOMAIN="appData", PATH="."), stub)
    return mod.execute()["entries"]


def test_pull_uses_output_flag(stub, tmp_path):
    target = tmp_path / "out.db"
    wire(devfs.Pull(DOMAIN="appData", PATH="Documents/x.db",
                    OUT=str(target)), stub).execute()
    argv = stub.last
    assert argv[:4] == ["developer", "core-device", "read-file", "appData"]
    assert "--output" in argv and argv[-1] == str(target)


def test_pull_creates_the_parent_dir(stub, tmp_path):
    target = tmp_path / "a" / "b" / "f.db"
    wire(devfs.Pull(DOMAIN="appData", PATH="x.db", OUT=str(target)),
         stub).execute()
    assert target.parent.is_dir()


def test_pull_warns_on_an_empty_result(stub, tmp_path, capsys):
    wire(devfs.Pull(DOMAIN="appData", PATH="x.db",
                    OUT=str(tmp_path / "e.db")), stub).execute()
    assert "empty file" in capsys.readouterr().out


def test_push_requires_a_local_file(stub, tmp_path):
    mod = wire(devfs.Push(DOMAIN="temporary", PATH="/t.bin",
                          LOCAL=str(tmp_path / "missing")), stub)
    with pytest.raises(FileNotFoundError):
        mod.execute()


def test_push_sends_the_local_path(stub, tmp_path):
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"x")
    wire(devfs.Push(DOMAIN="temporary", PATH="/p.bin", LOCAL=str(payload)),
         stub).execute()
    assert stub.last[:3] == ["developer", "core-device", "write-file"]
    assert stub.last[-1] == str(payload)


def test_rm_and_mkdir_argv(stub):
    wire(devfs.Rm(DOMAIN="temporary", PATH="/junk"), stub).execute()
    assert stub.last == ["developer", "core-device", "remove-file",
                         "temporary", "/junk"]
    wire(devfs.Mkdir(DOMAIN="temporary", PATH="/new"), stub).execute()
    assert stub.last == ["developer", "core-device", "create-directory",
                         "temporary", "/new"]


def test_app_containers_lists_bundles(stub):
    stub.out = "Documents\nLibrary\n"
    result = wire(devfs.Apps(), stub).execute()
    assert result["apps"] == ["com.apple.mobilesafari",
                             "com.whatsapp.WhatsApp"]


# -- interception -----------------------------------------------------------

def test_proxy_sets_host_and_port(stub):
    wire(intercept.Proxy(SERVER="10.0.0.5", PORT="8080"), stub).execute()
    assert stub.last == ["profile", "install-http-proxy", "10.0.0.5", "8080"]


def test_proxy_rejects_a_bad_port(stub):
    mod = wire(intercept.Proxy(SERVER="h", PORT="99999"), stub)
    with pytest.raises(ValueError, match="out of range"):
        mod.execute()


def test_proxy_off_removes_it(stub):
    wire(intercept.ProxyOff(), stub).execute()
    assert stub.last == ["profile", "remove-http-proxy"]


def test_backup_extract_unpacks_in_place(stub, tmp_path):
    (tmp_path / "f").write_bytes(b"x")
    wire(intercept.BackupExtract(DIR=str(tmp_path)), stub).execute()
    assert stub.last == ["backup2", "unback", str(tmp_path)]


def test_backup_file_uses_positional_domain_path(stub, tmp_path):
    wire(intercept.BackupFile(DIR=str(tmp_path), DOMAIN="AppDomain-com.x",
                              PATH="Documents/a.db"), stub).execute()
    assert stub.last[:2] == ["backup2", "extract"]
    assert stub.last[2:4] == ["AppDomain-com.x", "Documents/a.db"]


def test_backup_modules_need_a_real_directory(stub, tmp_path):
    mod = wire(intercept.BackupFile(DIR=str(tmp_path / "nope"),
                                    DOMAIN="d", PATH="p"), stub)
    with pytest.raises(FileNotFoundError):
        mod.execute()


def test_backup_list_filters(stub, tmp_path):
    stub.out = "AppDomain-com.x/Documents/a.db\nAppDomain-com.y/b.txt\n"
    result = wire(intercept.BackupList(DIR=str(tmp_path), GREP="com.x"),
                  stub).execute()
    assert len(result["entries"]) == 1


def test_new_modules_subclass_iosmodule():
    for cls in (devfs.Ls, devfs.Pull, devfs.Push, devfs.Rm, devfs.Mkdir,
                devfs.Apps, intercept.Proxy, intercept.ProxyOff,
                intercept.BackupExtract, intercept.BackupFile,
                intercept.BackupList):
        assert issubclass(cls, IosModule)
