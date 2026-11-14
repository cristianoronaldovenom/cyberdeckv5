"""iOS device control over pymobiledevice3, with a libimobiledevice fallback.

Two backends, both argv-list driven and both optional:

* ``pmd3`` — ``pymobiledevice3``. Screen/HID/location work goes through the
  DeveloperDiskImage services (``developer core-device …``), which need a
  **Developer Mode** device and an RSD tunnel. We pass ``--rsd HOST PORT`` when
  it is configured and let pymobiledevice3 establish its own tunnel otherwise.
* ``limd`` — ``ideviceinfo`` / ``idevicesyslog`` / ``idevicescreenshot`` from
  libimobiledevice. Read-only, but works on a stock device with no Developer
  Mode, so it is the graceful degradation path.

Target selection rides the environment (``PYMOBILEDEVICE3_UDID`` /
``PYMOBILEDEVICE3_TUNNEL``) because current pymobiledevice3 declares ``--udid``
per subcommand instead of globally; ``--rsd`` is appended after the subcommand
for the same reason.

The RSD tunnel has to be started outside the toolkit (root on the host):

    pymobiledevice3 lockdown start-tunnel        # prints HOST PORT
    omni config set ios.rsd_host 127.0.0.1
    omni config set ios.rsd_port 49152

Without it, ``core-device`` commands fail on iOS 17+ and the module says so
instead of hanging.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from omni.core import config, proc

__all__ = ["IosError", "IosDevice", "split_udids", "parse_devices",
           "BackendError"]


class IosError(RuntimeError):
    """An iOS command failed, or no usable backend is installed."""


class BackendError(IosError):
    """No backend binary is available at all."""


@dataclass
class IosDevice:
    udid: str
    name: str = ""
    state: str = ""
    ios: str = ""
    connection: str = "usb"

    @property
    def label(self) -> str:
        bits = [self.udid]
        if self.name:
            bits.append(f'"{self.name}"')
        if self.ios:
            bits.append(f"iOS {self.ios}")
        bits.append(self.state or self.connection)
        return "  ".join(bits)


def split_udids(text: str) -> list[str]:
    """Pull UDIDs out of ``usbmux list`` / ``idevice_id -l`` output."""
    return sorted({m.group(1) for m in re.finditer(
        r"\b([0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})\b", text)})


def parse_devices(text: str) -> list[IosDevice]:
    """Best-effort parse of ``usbmux list`` JSON-ish output."""
    devices = []
    for udid in split_udids(text):
        name = ""
        match = re.search(
            r'"DeviceName"\s*:\s*"([^"]*)".{0,400}?' + re.escape(udid),
            text, re.S)
        if match:
            name = match.group(1)
        devices.append(IosDevice(udid=udid, name=name))
    return devices


class Ios:
    """Device control with automatic backend selection and clear failures."""

    def __init__(self, udid: str | None = None, binary: str | None = None,
                 tunnel: str | None = None, timeout: int | None = None):
        self.binary = binary or config.get_value("ios.binary",
                                                 "pymobiledevice3")
        self.udid = udid or config.get_value("ios.udid") or ""
        self.tunnel = tunnel or config.get_value("ios.tunnel") or ""
        self.timeout = timeout or int(config.get_value("timeout", 120))
        host = str(config.get_value("ios.rsd_host") or "")
        port = str(config.get_value("ios.rsd_port") or "")
        self.rsd = (host, port) if host and port else None

    # -- plumbing ---------------------------------------------------------
    def _global(self) -> list[str]:
        """argv prefix — the binary alone.

        ``--udid``, ``--tunnel`` and ``--rsd`` are *per-subcommand* options in
        current pymobiledevice3, so none of them can be prefixed to the
        command. The two that have environment variables go there instead;
        ``--rsd`` is appended after the subcommand by :meth:`run`.
        """
        return [self.binary]

    def env(self) -> dict[str, str]:
        """Environment that pins the target without a CLI prefix."""
        out: dict[str, str] = {}
        if self.udid:
            out["PYMOBILEDEVICE3_UDID"] = self.udid
        if self.tunnel:
            out["PYMOBILEDEVICE3_TUNNEL"] = self.tunnel
        return out

    def _device_opts(self) -> list[str]:
        """Trailing options for the commands that take an RSD endpoint."""
        if self.tunnel or not self.rsd:
            return []
        return ["--rsd", self.rsd[0], self.rsd[1]]

    def run(self, *args: str, timeout: int | None = None) -> proc.Result:
        """Run a pymobiledevice3 subcommand, never through a shell."""
        return proc.run(self._global() + list(args) + self._device_opts(),
                        timeout=timeout or self.timeout, env=self.env())

    def raw(self, *args: str, timeout: int | None = None) -> proc.Result:
        """Run a subcommand with no device endpoint (``bonjour``, ``usbmux``)."""
        return proc.run([self.binary, *args], timeout=timeout or self.timeout,
                        env=self.env())


    def check(self, *args: str, timeout: int | None = None) -> proc.Result:
        res = self.run(*args, timeout=timeout)
        if not res.ok:
            raise IosError(self.explain(args, res.text))
        return res

    @staticmethod
    def explain(args: tuple[str, ...], text: str) -> str:
        """Turn pymobiledevice3 noise into the action that fixes it."""
        blob = f"{' '.join(args)} {text}".lower()
        if "developer mode" in blob or "developermode" in blob:
            return ("Developer Mode is off — enable Settings > Privacy & "
                    "Security > Developer Mode on the device, reboot, confirm")
        if "rsd" in blob or "tunnel" in blob or "remotediscovery" in blob:
            return ("no RSD tunnel — run 'pymobiledevice3 lockdown "
                    "start-tunnel' as root, then set ios.rsd_host/ios.rsd_port "
                    "(or pass TUNNEL)")
        if "not found" in blob and "service" in blob:
            return "the DeveloperDiskImage is not mounted — see ios.mount"
        if "no device" in blob or "unable to find" in blob:
            return ("device not visible — unlock it, tap Trust, and check "
                    "'omni run ios.devices'")
        return f"pymobiledevice3 {' '.join(args)}: {text.strip()[:300]}"

    # -- availability -----------------------------------------------------
    def have_pmd3(self) -> bool:
        return proc.has(self.binary)

    def have_limd(self) -> bool:
        return proc.has(config.get_value("ios.limd_binary", "ideviceinfo"))

    @property
    def backend(self) -> str:
        if self.have_pmd3():
            return "pmd3"
        if self.have_limd():
            return "limd"
        raise BackendError("neither pymobiledevice3 nor libimobiledevice "
                           "found — see install.sh (ios packages)")

    def require_developer(self) -> None:
        """Fail early and usefully when a core-device command is needed."""
        if self.backend != "pmd3":
            raise IosError("DeveloperDiskImage commands need pymobiledevice3")

    # -- inventory --------------------------------------------------------
    def devices(self) -> list[IosDevice]:
        if self.have_pmd3():
            return parse_devices(self.raw("usbmux", "list").out)
        names = proc.run([config.get_value("ios.limd_binary", "ideviceinfo"),
                          "-k", "UniqueDeviceID"], timeout=30).out
        return [IosDevice(udid=udid) for udid in split_udids(names)]

    def info(self) -> dict:
        """Device identity from lockdown (works without Developer Mode)."""
        if self.backend == "pmd3":
            out = self.check("lockdown", "info").out
        else:
            binary = config.get_value("ios.limd_binary", "ideviceinfo")
            out = proc.run([binary], timeout=30).out
        text = out.strip()
        if text.startswith("{"):
            try:
                loaded = json.loads(text)
                if isinstance(loaded, dict):
                    return {str(k): str(v) for k, v in loaded.items()}
            except ValueError:
                pass
        values: dict[str, str] = {}
        for line in out.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            # keys/values may be quoted and values may contain a comma
            # (ProductType is "iPhone16,1"), so only strip the edges
            cleaned = value.strip().rstrip(",").strip().strip('"')
            key = key.strip().lstrip("{").strip().strip('"')
            if key and cleaned:
                values[key] = cleaned
        return values

    def is_paired(self) -> bool:
        res = self.run("lockdown", "info")
        return res.ok and "DeviceName" in res.out

    def pair(self) -> str:
        return self.check("lockdown", "pair", timeout=120).out

    def pair_supervised(self, keybag: str) -> str:
        """Pair a supervised device against its keybag — no Trust alert."""
        return self.check("lockdown", "pair-supervised", keybag,
                          timeout=180).out

    def save_pair_record(self, path: str) -> str:
        """Write this host's pair record out so it can be replayed elsewhere."""
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.check("lockdown", "save-pair-record", path, timeout=120)
        return path

    def wifi_connections(self, state: str | None = None) -> str:
        """Get (or set ``on``/``off``) sync-over-Wi-Fi."""
        args = ["lockdown", "wifi-connections"] + ([state] if state else [])
        return self.check(*args, timeout=60).out

    def remotepairing(self, pair: bool = True) -> str:
        """RemotePairing handshake; ``pair`` bootstraps it promptlessly."""
        args = ["lockdown", "remotepairing"] + (["--pair"] if pair else [])
        return self.check(*args, timeout=180).out

    def trusted_hosts(self) -> str:
        """Raw ``PairedDevicesArray`` — every host this device still trusts."""
        return self.check("lockdown", "get", "com.apple.mobile.lockdown",
                          "PairedDevicesArray", timeout=60).out

    def unpair(self, host_id: str = "") -> None:
        """Revoke one host's record (or our own when ``host_id`` is empty)."""
        args = ["lockdown", "unpair"] + ([host_id] if host_id else [])
        self.check(*args, timeout=120)

    def heartbeat(self, seconds: int = 30) -> bool:
        """Hold the trusted session open; True if it was still alive at the cut.

        ``pymobiledevice3 lockdown heartbeat`` runs until killed, so a timeout
        is the success case here, not a failure.
        """
        res = self.run("lockdown", "heartbeat", timeout=max(3, seconds))
        return bool(res.ok or res.timed_out)


    # -- state ------------------------------------------------------------
    def lock_state(self) -> str:
        self.require_developer()
        return self.check("developer", "core-device",
                          "get-lockstate").out.strip()

    def device_info(self) -> str:
        self.require_developer()
        return self.check("developer", "core-device", "get-device-info").out

    def press_button(self, name: str = "home") -> None:
        """Hardware buttons via the Indigo HID service."""
        self.require_developer()
        self.check("developer", "core-device", "hid", "button", name, "press")

    def lock(self) -> None:
        self.press_button("power")

    def unlock(self) -> None:
        """Wake, then swipe up — an unlocked phone needs no passcode."""
        self.press_button("power")
        self.swipe(32768, 60000, 32768, 20000, 0.25)

    # -- input (coordinates are 0..65535, screen-normalised) --------------
    def tap(self, x: int, y: int) -> None:
        self.require_developer()
        self.check("developer", "core-device", "universal-hid-service",
                   "tap", str(x), str(y))

    def swipe(self, x1: int, y1: int, x2: int, y2: int,
              duration: float = 0.3) -> None:
        self.require_developer()
        self.check("developer", "core-device", "universal-hid-service",
                   "swipe", str(x1), str(y1), str(x2), str(y2),
                   "--duration", f"{duration:.2f}")

    def drag(self, x1: int, y1: int, x2: int, y2: int,
             duration: float = 0.6) -> None:
        self.require_developer()
        self.check("developer", "core-device", "universal-hid-service",
                   "drag", str(x1), str(y1), str(x2), str(y2),
                   "--duration", f"{duration:.2f}")

    def type_text(self, text: str) -> None:
        self.require_developer()
        self.check("developer", "core-device", "universal-hid-service",
                   "type", text)

    def key(self, name: str, count: int = 1) -> None:
        self.require_developer()
        self.check("developer", "core-device", "universal-hid-service",
                   "key", name, "--count", str(max(1, count)))

    def press_hold(self, x: int, y: int, ms: int = 800) -> None:
        """Press and hold without moving (a zero-length drag)."""
        self.require_developer()
        self.check("developer", "core-device", "universal-hid-service",
                   "drag", str(x), str(y), str(x), str(y),
                   "--duration", f"{max(200, ms) / 1000.0:.2f}")

    def scroll(self, direction: str = "down", steps: int = 1,
               span: int = 30_000) -> int:
        """Flick the screen `steps` times; scrolling down drags content up."""
        if direction not in ("down", "up", "left", "right"):
            raise ValueError(f"direction must be down/up/left/right, got "
                             f"{direction!r}")
        dy = -span if direction == "down" else span
        dx = -span if direction == "left" else span
        if direction in ("down", "up"):
            points = (32768, 60_000 if direction == "down" else 5_000,
                      32768, (60_000 if direction == "down" else 5_000) + dy)
        else:
            points = (5_000 if direction == "right" else 60_000, 32768,
                      (5_000 if direction == "right" else 60_000) + dx, 32768)
        for _ in range(max(1, steps)):
            self.swipe(*points, duration=0.15)
        return max(1, steps)

    def wake(self) -> None:
        """Press the power button (toggles keyguard)."""
        self.press_button("power")

    # -- clipboard --------------------------------------------------------
    def clipboard_get(self) -> str:
        self.require_developer()
        return self.check("developer", "core-device", "paste").out.strip()

    def clipboard_set(self, text: str) -> None:
        self.require_developer()
        self.check("developer", "core-device", "copy", text)

    # -- screen / apps ----------------------------------------------------
    def screenshot(self, path: str) -> str:
        if self.backend == "limd":
            binary = config.get_value("ios.limd_binary", "idevicescreenshot")
            binary = binary.replace("ideviceinfo", "idevicescreenshot")
            proc.run([binary, path], timeout=90)
            return path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.check("developer", "core-device", "screen-capture",
                   "screenshot", path, timeout=90)
        return path

    def apps(self) -> list[str]:
        self.require_developer()
        out = self.check("developer", "core-device", "list-apps").out
        return sorted({m for m in re.findall(
            r"[\w-]+(?:\.[\w-]+)+", out)})

    def launch(self, bundle_id: str) -> None:
        self.require_developer()
        self.check("developer", "core-device", "launch-application", bundle_id)

    def uninstall_app(self, bundle_id: str) -> None:
        self.require_developer()
        self.check("developer", "core-device", "uninstall", bundle_id)

    def processes(self) -> list[tuple[int, str]]:
        """(pid, name) pairs from the device process list."""
        self.require_developer()
        out = self.check("developer", "core-device", "list-processes").out
        return sorted({(int(pid), name) for pid, name in re.findall(
            r'"?pid"?\s*[:=]\s*(\d+)[^}]*?"?(?:name|executable)"?\s*[:=]\s*"([^"]+)"',
            out)})

    def signal(self, pid: int, sig: int = 9) -> None:
        self.require_developer()
        self.check("developer", "core-device", "send-signal-to-process",
                   str(pid), str(sig))

    def kill(self, name: str) -> list[int]:
        """SIGKILL every process whose executable matches `name`."""
        hits = [pid for pid, proc_name in self.processes() if name in proc_name]
        for pid in hits:
            self.signal(pid, 9)
        return hits

    # -- location ---------------------------------------------------------
    def set_location(self, lat: float, lon: float) -> None:
        self.check("developer", "dvt", "simulate-location", "set",
                   str(lat), str(lon))

    def clear_location(self) -> None:
        self.check("developer", "dvt", "simulate-location", "clear")

    # -- syslog -----------------------------------------------------------
    def syslog(self, seconds: int = 10, out: str | None = None,
               process: str | None = None) -> str:
        """Collect syslog lines for a bounded window (tee'd to `out`)."""
        args = ["syslog", "live"]
        if out:
            parent = os.path.dirname(out)
            if parent:
                os.makedirs(parent, exist_ok=True)
            args += ["--out", out]
        if process:
            args += ["--process-name", process]
        try:
            res = self.run(*args, timeout=max(5, seconds))
            text = res.out
        except Exception:                       # noqa: BLE001 - killed by timeout
            text = ""
        if out and os.path.exists(out):
            with open(out, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        return text
