"""ADB wrapper: device discovery, shells, transfer, media, power, state.

Mirrors the command surface of PhoneSploit-Pro (AzeemIdrisi, GPL-3.0) but with
explicit argv lists instead of shell strings, so paths with spaces and quoted
text are handled correctly.
"""

from __future__ import annotations

import os
import re
import tempfile
import time
from dataclasses import dataclass

from omni.core import config, console, proc

__all__ = ["Adb", "AdbError", "Device"]


class AdbError(RuntimeError):
    """ADB invocation failed or no device is selected."""


@dataclass
class Device:
    serial: str
    state: str
    model: str = ""
    product: str = ""
    transport: str = "usb"

    @property
    def usable(self) -> bool:
        return self.state == "device"

    @property
    def label(self) -> str:
        name = self.model or self.product or "unknown"
        return f"{self.serial}  [{name}] {self.state}"


class Adb:
    """Thin, stateful wrapper around the adb binary."""

    def __init__(self, binary: str | None = None, serial: str | None = None,
                 timeout: int | None = None):
        self.binary = binary or config.adb()
        self.serial = serial or config.get_value("android.serial")
        self.timeout = timeout or int(config.get_value("timeout", 120))

    # -- plumbing ---------------------------------------------------------
    def _argv(self, *args: str, serial: str | None = None) -> list[str]:
        argv = [self.binary]
        target = serial or self.serial
        if target:
            argv += ["-s", target]
        argv += list(args)
        return argv

    def raw(self, *args: str, serial: str | None = None,
            timeout: int | None = None) -> proc.Result:
        return proc.run(self._argv(*args, serial=serial),
                        timeout=timeout or self.timeout)

    def check(self, *args: str, serial: str | None = None,
              timeout: int | None = None) -> proc.Result:
        res = self.raw(*args, serial=serial, timeout=timeout)
        if not res.ok:
            raise AdbError(f"adb {' '.join(args)}: {res.text[:300]}")
        return res

    def shell(self, *args: str) -> str:
        return self.check("shell", *args).out

    def shell_result(self, *args: str, timeout: int | None = None) -> proc.Result:
        return self.raw("shell", *args, timeout=timeout)

    # -- availability -----------------------------------------------------
    def available(self) -> bool:
        return proc.has(self.binary)

    def version(self) -> str:
        res = proc.run([self.binary, "version"], timeout=20)
        return res.out.splitlines()[0] if res.ok and res.out else "unknown"

    def start_server(self) -> None:
        proc.run([self.binary, "start-server"], timeout=30)

    def kill_server(self) -> None:
        proc.run([self.binary, "kill-server"], timeout=30)

    # -- discovery --------------------------------------------------------
    def devices(self) -> list[Device]:
        res = proc.run([self.binary, "devices", "-l"], timeout=30)
        found: list[Device] = []
        for line in res.out.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            meta: dict[str, str] = {}
            for chunk in parts[2:]:
                if ":" in chunk:
                    key, _, val = chunk.partition(":")
                    meta[key] = val
            found.append(Device(serial=parts[0], state=parts[1],
                                model=meta.get("model", "").replace("_", " "),
                                product=meta.get("product", ""),
                                transport="tcp" if ":" in parts[0] else "usb"))
        return found

    def select(self, serial: str) -> bool:
        dev = next((d for d in self.devices() if d.serial == serial), None)
        if dev is None or not dev.usable:
            return False
        self.serial = serial
        config.set_value("android.serial", serial)
        return True

    def device(self) -> Device | None:
        """The selected device, or the only attached one."""
        devices = self.devices()
        if self.serial:
            return next((d for d in devices if d.serial == self.serial), None)
        usable = [d for d in devices if d.usable]
        if len(usable) == 1:
            self.serial = usable[0].serial
            return usable[0]
        return None

    def pick(self) -> Device | None:
        """Interactive device chooser; persists the choice."""
        devices = [d for d in self.devices() if d.usable]
        if not devices:
            console.err("no authorized device attached "
                        "(enable USB debugging, accept the RSA prompt)")
            return None
        if len(devices) == 1:
            self.select(devices[0].serial)
            return devices[0]
        idx = console.choose("device", [d.label for d in devices])
        if idx is None:
            return None
        self.select(devices[idx].serial)
        return devices[idx]

    # -- connection -------------------------------------------------------
    def connect(self, address: str) -> proc.Result:
        return proc.run([self.binary, "connect", address], timeout=30)

    def disconnect(self, address: str | None = None) -> proc.Result:
        argv = [self.binary, "disconnect"]
        if address:
            argv.append(address)
        return proc.run(argv, timeout=30)

    def pair(self, address: str, code: str) -> proc.Result:
        return proc.run([self.binary, "pair", address, code], timeout=60)

    def enable_tcpip(self, port: int = 5555) -> proc.Result:
        return self.check("tcpip", str(port))

    def back_to_usb(self) -> proc.Result:
        return self.raw("usb")

    @staticmethod
    def _local_subnet() -> str:
        res = proc.run(["ip", "-4", "-o", "addr", "show"], timeout=15)
        for line in res.out.splitlines():
            m = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/\d+ .*scope global", line)
            if m:
                return m.group(1) + ".0/24"
        return ""

    def scan_network(self, subnet: str | None = None) -> list[str]:
        """Find hosts advertising the ADB port (needs nmap)."""
        subnet = subnet or self._local_subnet()
        if not subnet or not proc.has("nmap"):
            return []
        res = proc.run(["nmap", "-p", "5555", "--open", "-T4", "-Pn", subnet],
                       timeout=600)
        return sorted({m[2] or m[1] for m in re.findall(
            r"Nmap scan report for (?:(\S+) \(([\d.]+)\)|([\d.]+))", res.out)})

    # -- device info ------------------------------------------------------
    def prop(self, key: str) -> str:
        return self.shell_result("getprop", key).out.strip()

    def model(self) -> str:
        return self.prop("ro.product.model") or "unknown"

    def android_version(self) -> str:
        return self.prop("ro.build.version.release") or "unknown"

    def sdk(self) -> int:
        try:
            return int(self.prop("ro.build.version.sdk"))
        except ValueError:
            return 0

    def is_rooted(self) -> bool:
        return "uid=0" in self.shell_result("id").out

    def battery(self) -> dict:
        data = {}
        for line in self.shell_result("dumpsys", "battery").out.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                data[key.strip().lower()] = val.strip()
        return data

    def screen_state(self) -> str:
        out = self.shell_result("dumpsys", "power").out
        if "mWakefulness=Awake" in out or "Display Power: state=ON" in out:
            return "awake"
        if "mWakefulness=Asleep" in out:
            return "asleep"
        return "unknown"

    def ip_address(self) -> str:
        out = self.shell_result("ip", "-4", "addr", "show", "wlan0").out
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else ""

    def location(self) -> dict:
        out = self.shell_result("dumpsys", "location").out
        m = re.search(r"gps:\s*Location\[[^\]]*?(-?[\d.]+),(-?[\d.]+)", out)
        if m:
            return {"lat": m.group(1), "lon": m.group(2), "source": "gps"}
        m = re.search(r"last known location[^\n]*?(-?\d{1,3}\.[\d]+),\s*(-?\d{1,3}\.[\d]+)",
                      out)
        if m:
            return {"lat": m.group(1), "lon": m.group(2), "source": "network"}
        return {}

    # -- input ------------------------------------------------------------
    def key(self, code: int | str) -> proc.Result:
        return self.raw("shell", "input", "keyevent", str(code))

    def text(self, text: str) -> proc.Result:
        return self.raw("shell", "input", "text", str(text).replace(" ", "%s"))

    def tap(self, x: int, y: int) -> proc.Result:
        return self.raw("shell", "input", "tap", str(x), str(y))

    def swipe(self, x1: int, y1: int, x2: int, y2: int,
              ms: int = 300) -> proc.Result:
        return self.raw("shell", "input", "swipe", str(x1), str(y1),
                        str(x2), str(y2), str(ms))

    def long_press(self, x: int, y: int, ms: int = 800) -> proc.Result:
        """A press-and-hold is a swipe that never moves."""
        return self.swipe(x, y, x, y, max(400, ms))

    def drag(self, x1: int, y1: int, x2: int, y2: int,
             ms: int = 900) -> proc.Result:
        return self.swipe(x1, y1, x2, y2, max(300, ms))

    def scroll(self, direction: str = "down", steps: int = 1,
               x: int = 540, y: int = 1200, span: int = 600) -> list:
        """Flick `steps` times; `span` sets how far one flick travels."""
        self._check_direction(direction)
        results = []
        for _ in range(max(1, steps)):
            results.append(self._flick(direction, x, y, span))
        return results

    def fling(self, direction: str = "down", steps: int = 1,
              x: int = 540, y: int = 1200, span: int = 1100) -> list:
        """Like `scroll`, but a longer, faster throw for lists that paginate."""
        self._check_direction(direction)
        results = []
        for _ in range(max(1, steps)):
            results.append(self._flick(direction, x, y, span, ms=80))
        return results

    @staticmethod
    def _check_direction(direction: str) -> None:
        if direction not in ("down", "up", "left", "right"):
            raise ValueError(f"direction must be down/up/left/right, got "
                             f"{direction!r}")

    def _flick(self, direction: str, x: int, y: int, span: int,
               ms: int = 120) -> proc.Result:
        # scrolling "down" drags content upward, and vice versa
        dx, dy = {"down": (0, -span), "up": (0, span),
                  "left": (-span, 0), "right": (span, 0)}[direction]
        return self.swipe(x, y, x + dx, y + dy, ms)

    # -- raw touch stream (gestures that need intermediate moves) ---------
    def touch_down(self, x: int, y: int) -> proc.Result:
        return self.raw("shell", "input", "motionevent", "DOWN", str(x), str(y))

    def touch_move(self, x: int, y: int) -> proc.Result:
        return self.raw("shell", "input", "motionevent", "MOVE", str(x), str(y))

    def touch_up(self, x: int, y: int) -> proc.Result:
        return self.raw("shell", "input", "motionevent", "UP", str(x), str(y))

    def find_text_bounds(self, text: str) -> tuple[int, int]:
        """Centre of the first UI node whose text or content-desc matches."""
        out = self.shell_result("uiautomator", "dump", "/dev/tty").out
        match = re.search(
            r'text="' + re.escape(text) + r'"[^>]*bounds="\[(\d+),(\d+)\]'
            r'\[(\d+),(\d+)\]"', out)
        if not match:
            match = re.search(
                r'content-desc="' + re.escape(text) +
                r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', out)
        if not match:
            raise AdbError(f"no UI node matching {text!r} on screen")
        x1, y1, x2, y2 = (int(v) for v in match.groups())
        return (x1 + x2) // 2, (y1 + y2) // 2

    def tap_text(self, text: str) -> proc.Result:
        """Tap the first UI node whose text or content-desc matches."""
        return self.tap(*self.find_text_bounds(text))

    # -- files ------------------------------------------------------------
    def push(self, local: str, remote: str) -> proc.Result:
        return self.check("push", local, remote)

    def pull(self, remote: str, local: str, timeout: int | None = None) -> proc.Result:
        return self.check("pull", remote, local, timeout=timeout)

    def install(self, apk: str) -> proc.Result:
        return self.check("install", "-r", apk, timeout=900)

    def uninstall(self, package: str) -> proc.Result:
        return self.check("uninstall", package)

    def screenshot(self, path: str) -> str:
        """Grab a PNG locally via exec-out (no remote temp file)."""
        raw = proc.run(self._argv("exec-out", "screencap", "-p"), timeout=90)
        with open(path, "wb") as fh:
            fh.write(raw.out.encode("utf-8", "surrogateescape"))
        return path

    def screenrecord(self, path: str, seconds: int = 10) -> str:
        remote = self.temp_remote(".mp4")
        self.raw("shell", "screenrecord", "--time-limit", str(seconds), remote,
                 timeout=seconds + 60)
        self.pull(remote, path, timeout=300)
        self.raw("shell", "rm", "-f", remote)
        return path

    # -- packages ---------------------------------------------------------
    def packages(self, third_party_only: bool = True) -> list[str]:
        args = ("pm", "list", "packages", "-3") if third_party_only \
            else ("pm", "list", "packages")
        out = self.shell_result(*args).out
        return sorted(line.split(":", 1)[1].strip()
                      for line in out.splitlines() if line.startswith("package:"))

    def running_packages(self) -> list[str]:
        out = self.shell_result("dumpsys", "activity", "activities").out
        return sorted(set(re.findall(r"u0\s+([\w.]+)/", out)))

    def app_path(self, package: str) -> str:
        return self.shell_result("pm", "path", package).out.replace(
            "package:", "").strip()

    def start_app(self, package: str) -> proc.Result:
        return self.raw("shell", "monkey", "-p", package,
                        "-c", "android.intent.category.LAUNCHER", "1")

    def force_stop(self, package: str) -> proc.Result:
        return self.raw("shell", "am", "force-stop", package)

    def clear_data(self, package: str) -> proc.Result:
        return self.raw("shell", "pm", "clear", package)

    # -- permissions / package state --------------------------------------
    def grant(self, package: str, permission: str) -> proc.Result:
        return self.raw("shell", "pm", "grant", package, permission)

    def revoke(self, package: str, permission: str) -> proc.Result:
        return self.raw("shell", "pm", "revoke", package, permission)

    def permissions(self, package: str) -> list[str]:
        out = self.shell_result("dumpsys", "package", package).out
        return sorted({m for m in re.findall(
            r"(?:android\.permission|com\.\w+\.permission)\.[\w.]+",
            out)})

    def set_enabled(self, package: str, enabled: bool) -> proc.Result:
        verb = "enable" if enabled else "disable-user"
        return self.raw("shell", "pm", verb, "--user", "0", package)

    def is_enabled(self, package: str) -> bool:
        out = self.shell_result("pm", "list", "packages", "-d").out
        names = {line.split(":", 1)[1].strip()
                 for line in out.splitlines() if line.startswith("package:")}
        return package not in names

    # -- lock screen ------------------------------------------------------
    def screen_locked(self) -> bool:
        out = self.shell_result("dumpsys", "window").out
        return "mDreamingLockscreen=true" in out or \
            "isStatusBarKeyguard=true" in out

    def swipe_unlock(self) -> proc.Result:
        """Clear a keyguard with no PIN by swiping up from the bottom."""
        return self.swipe(540, 1800, 540, 700, 200)

    def apk_size(self, package: str) -> int:
        path = self.app_path(package)
        if not path:
            return 0
        out = self.shell_result("stat", "-c", "%s", path).out.strip()
        return int(out) if out.isdigit() else 0

    def extract_apk(self, package: str, directory: str) -> str | None:
        remote = self.app_path(package)
        if not remote:
            return None
        target = os.path.join(directory, f"{package}.apk")
        self.pull(remote, target)
        return target if os.path.isfile(target) else None

    # -- power / display --------------------------------------------------
    def power_key(self) -> proc.Result:
        return self.key(26)

    def power(self, action: str) -> proc.Result:
        return self.raw("shell", "input", "keyevent",
                        {"on": "224", "off": "223"}.get(action, "26"))

    def wake(self) -> proc.Result:
        return self.raw("shell", "input", "keyevent", "224")

    def sleep(self) -> proc.Result:
        return self.raw("shell", "input", "keyevent", "223")

    def reboot(self, mode: str = "") -> proc.Result:
        return self.raw(*(["reboot"] + ([mode] if mode else [])), timeout=90)

    def brightness(self, level: int) -> proc.Result:
        return self.raw("shell", "settings", "put", "system",
                        "screen_brightness", str(max(0, min(255, level))))

    def auto_brightness(self, on: bool) -> proc.Result:
        return self.raw("shell", "settings", "put", "system",
                        "screen_brightness_mode", "1" if on else "0")

    def stay_awake(self, on: bool) -> proc.Result:
        return self.raw("shell", "svc", "power", "stayon" if on else "stayoff")

    # -- sound ------------------------------------------------------------
    def volume(self, stream: str, level: int) -> proc.Result:
        return self.raw("shell", "media", "volume", "--stream", stream,
                        "--set", str(max(0, min(15, level))))

    def media(self, action: str) -> proc.Result:
        return self.raw("shell", "cmd", "media_session", "dispatch", action)

    # -- radios -----------------------------------------------------------
    def wifi(self, on: bool) -> proc.Result:
        return self.raw("shell", "svc", "wifi", "enable" if on else "disable")

    def data(self, on: bool) -> proc.Result:
        return self.raw("shell", "svc", "data", "enable" if on else "disable")

    def airplane(self, on: bool) -> proc.Result:
        return self.raw("shell", "cmd", "connectivity", "airplane-mode",
                        "enable" if on else "disable")

    def bluetooth(self, on: bool) -> proc.Result:
        return self.raw("shell", "svc", "bluetooth", "enable" if on else "disable")

    def nfc(self, on: bool) -> proc.Result:
        return self.raw("shell", "svc", "nfc", "enable" if on else "disable")

    # -- misc -------------------------------------------------------------
    def clipboard_get(self) -> str:
        return self.shell_result("cmd", "clipboard", "get").out.strip()

    def clipboard_set(self, text: str) -> proc.Result:
        return self.raw("shell", "cmd", "clipboard", "set", text)

    def open_url(self, url: str) -> proc.Result:
        return self.raw("shell", "am", "start", "-a",
                        "android.intent.action.VIEW", "-d", url)

    def notifications(self) -> str:
        return self.shell_result("dumpsys", "notification", "--noredact").out

    def dump_activities(self) -> str:
        return self.shell_result("dumpsys", "activity", "activities").out

    @staticmethod
    def temp_remote(suffix: str = ".png") -> str:
        return f"/sdcard/omni_{next(tempfile._get_candidate_names())}{suffix}"

# __END__
