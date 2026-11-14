"""Connect the host to a WiFi network, and read the link back.

The rest of the family attacks networks; this joins them — needed after a crack
to actually use the PSK, and for hopping onto a target network from the same
adapter. `nmcli` is used when present (clean, handles roaming) with a raw
`wpa_supplicant` + `dhcpcd` fallback so it works on a minimal Kali install.

The credential file is written 0600 because it holds the PSK in clear.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console, proc
from omni.core.module import Option
from omni.wifi.modules._base import WifiModule

__all__ = ["Connect", "WpaFile", "Link"]

PREFIX = "omni"
CONF_DIR = "/etc/wpa_supplicant"


def _which_nmcli() -> bool:
    return proc.has("nmcli")


class Connect(WifiModule):
    NAME = "wifi.connect"
    DESCRIPTION = "Join a network with a PSK (nmcli, else wpa_supplicant)"
    OPTIONS = (Option("SSID", "network name", "", required=True),
               Option("PSK", "passphrase (8..63 chars)", "", secret=True),
               Option("IFACE", "managed interface (auto)"),
               Option("HIDDEN", "SSID is hidden", "false",
                      choices=("true", "false")),
               Option("WAIT", "seconds to wait for an address", "25"))

    def execute(self) -> dict:
        ssid = self.get("SSID")
        psk = self.get("PSK")
        timeout = max(5, self.get_int("WAIT", 25))
        from omni.core import platform as host
        if host.is_windows() and not host.is_macos() and not _which_nmcli():
            return self._netsh(self.get("IFACE") or "", ssid, psk, timeout)

        iface = self.get("IFACE") or self._pick_managed()

        if _which_nmcli():
            argv = ["nmcli", "device", "wifi", "connect", ssid, "ifname", iface]
            if psk:
                argv += ["password", psk]
            if self.get_bool("HIDDEN"):
                argv += ["hidden", "yes"]
            console.info(f"nmcli: joining {ssid!r} on {iface}")
            res = proc.run(argv, timeout=timeout + 20)
            if res.ok:
                console.ok(f"connected to {ssid}")
                return self._verify(iface, ssid)
            console.warn(f"nmcli failed: {res.text.strip()[:140]} — trying "
                         "wpa_supplicant")

        return self._supplicant(iface, ssid, psk, timeout)

    @staticmethod
    def _pick_managed() -> str:
        from omni.wifi import iface as iface_mod
        base = iface_mod.pick(None)
        if iface_mod.current_mode(base) == "monitor":
            console.warn(f"{base} is in monitor mode — switching to managed")
            iface_mod.set_managed(base)
        return base

    def _supplicant(self, iface: str, ssid: str, psk: str, timeout: int) -> dict:
        conf = self._write_conf(ssid, psk, self.get_bool("HIDDEN"))
        console.info(f"associating {iface} via wpa_supplicant")
        proc.run(["ip", "link", "set", iface, "down"], timeout=15)
        proc.run(["ip", "link", "set", iface, "up"], timeout=15)
        proc.run(["wpa_supplicant", "-B", "-i", iface, "-c", conf], timeout=40)
        time.sleep(3)
        for client in ("dhcpcd", "dhclient", "udhcpc"):
            if proc.has(client):
                proc.run([client, iface], timeout=timeout)
                break
        else:
            console.warn("no DHCP client found — bring an address up manually")
        return self._verify(iface, ssid)

    def _netsh(self, iface: str, ssid: str, psk: str, timeout: int) -> dict:
        """Join on Windows with a throwaway WLAN profile (no extra tools)."""
        import tempfile
        from xml.sax.saxutils import escape

        auth = "WPA2PSK" if psk else "open"
        cipher = "AES" if psk else "none"
        key = (f'<sharedKey><keyType>passPhrase</keyType>'
               f'<protected>false</protected><keyMaterial>'
               f'{escape(psk)}</keyMaterial></sharedKey>') if psk else ""
        xml = ("<?xml version=\"1.0\"?>\n"
               "<WLANProfile xmlns=\"http://www.microsoft.com/networking/"
               "WLAN_profile/v1\"><name>" + escape(ssid) + "</name>"
               "<SSIDConfig><SSID><name>" + escape(ssid) + "</name></SSID>"
               + ("<nonBroadcast>true</nonBroadcast>"
                  if self.get_bool("HIDDEN") else "")
               + "</SSIDConfig><connectionType>ESS</connectionType>"
               "<connectionMode>auto</connectionMode><MSM><security>"
               "<authEncryption><authentication>" + auth + "</authentication>"
               "<encryption>" + cipher + "</encryption></authEncryption>" + key +
               "</security></MSM></WLANProfile>")
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(xml)
            path = fh.name
        try:
            add = proc.run(["netsh", "wlan", "add", "profile",
                            f"filename={path}", "user=current"], timeout=30)
            if not add.ok:
                console.warn(add.text.strip()[:160])
            argv = ["netsh", "wlan", "connect", f"name={ssid}",
                    f"ssid={ssid}"]
            if iface:
                argv.append(f"interface={iface}")
            proc.run(argv, timeout=timeout + 15)
            console.info(f"netsh: joining {ssid!r}" + (f" on {iface}" if iface else ""))
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        return self._verify(iface or "Wi-Fi", ssid)

    @staticmethod
    def _write_conf(ssid: str, psk: str, hidden: bool) -> str:
        os.makedirs(CONF_DIR, exist_ok=True)
        path = os.path.join(CONF_DIR, f"{PREFIX}-{os.getpid()}.conf")
        lines = ["ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev",
                 "update_config=1", "", "network={",
                 f'\tssid="{ssid}"']
        if psk:
            lines.append(f'\tpsk="{psk}"')
        else:
            lines.append("\tkey_mgmt=NONE")
        if hidden:
            lines.append("\tscan_ssid=1")
        lines.append("}")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            console.warn(f"could not chmod 600 {path} — it holds the PSK")
        console.info(f"config: {path}")
        return path

    @staticmethod
    def _verify(iface: str, ssid: str) -> dict:
        from omni.wifi import iface as iface_mod
        link = iface_mod.link_info(iface)
        if link.get("ip"):
            console.ok(f"{iface} has {link['ip']} on {ssid}")
        else:
            console.warn("associated but no address yet — check `omni run "
                         "wifi.link`")
        return {"ssid": ssid, "iface": iface, **link}


class WpaFile(WifiModule):
    NAME = "wifi.wpa_file"
    DESCRIPTION = "Write a wpa_supplicant config for later manual use"
    OPTIONS = (Option("SSID", "network name", "", required=True),
               Option("PSK", "passphrase (blank = open network)", "",
                      secret=True),
               Option("PATH", "output path"),
               Option("HIDDEN", "SSID is hidden", "false",
                      choices=("true", "false")))

    def execute(self) -> dict:
        path = os.path.expanduser(
            self.get("PATH") or
            os.path.join(config.output_dir("wifi"),
                         f"wpa_{int(time.time())}.conf"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lines = ["ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev",
                 "update_config=1", "", "network={",
                 f'\tssid="{self.get("SSID")}"']
        lines.append(f'\tpsk="{self.get("PSK")}"' if self.get("PSK")
                     else "\tkey_mgmt=NONE")
        if self.get_bool("HIDDEN"):
            lines.append("\tscan_ssid=1")
        lines.append("}")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        console.ok(f"{path} (mode 600)")
        console.info(f"use it with: sudo wpa_supplicant -i wlan0 -c {path}")
        return {"path": path}


class Link(WifiModule):
    NAME = "wifi.link"
    DESCRIPTION = "Show the current link: SSID, address, signal and counters"
    OPTIONS = (Option("IFACE", "interface (auto)"),)

    def execute(self) -> dict:
        from omni.wifi import iface as iface_mod
        target = self.get("IFACE") or iface_mod.pick(None)
        info = iface_mod.link_info(target)
        console.kv([("interface", target), ("ssid", str(info.get("ssid", "-"))),
                    ("ip", str(info.get("ip", "-"))),
                    ("signal", f"{info.get('signal_dbm', '-')} dBm"),
                    ("rx bytes", str(info.get("rx_bytes", 0))),
                    ("tx bytes", str(info.get("tx_bytes", 0)))])
        if not info.get("ip"):
            console.warn("no address — not associated, or DHCP failed")
        return {"iface": target, **info}

