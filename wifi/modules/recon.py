"""Adapter inventory, monitor-mode toggling and AP scanning."""

from __future__ import annotations

from omni.core import console, platform as host
from omni.core.module import Option
from omni.wifi import iface as iface_mod
from omni.wifi import scan as scan_mod
from omni.wifi.modules._base import WifiModule


class Adapters(WifiModule):
    NAME = "wifi.adapters"
    DESCRIPTION = "List wireless interfaces with mode and driver"

    def execute(self) -> list[dict]:
        rows = []
        for name in iface_mod.wireless_interfaces():
            rows.append({"iface": name, "mode": iface_mod.current_mode(name),
                         "wireless": iface_mod.is_wireless(name)})
        console.table(["iface", "mode", "wireless"],
                      [[r["iface"], r["mode"], str(r["wireless"])] for r in rows])
        return rows


class Monitor(WifiModule):
    NAME = "wifi.monitor"
    DESCRIPTION = "Enable or disable monitor mode on an adapter"
    OPTIONS = (Option("IFACE", "wireless interface (blank = auto)"),
               Option("ACTION", "start|stop", "start",
                      choices=("start", "stop")),
               Option("NAME", "monitor vif name (blank = <iface>mon)"))

    def execute(self) -> dict:
        base = iface_mod.pick(self.get("IFACE") or None)
        if self.get("ACTION") == "stop":
            iface_mod.set_managed(base)
            console.ok(f"{base} back in managed mode")
            return {"iface": base, "mode": iface_mod.current_mode(base)}
        if host.is_windows():
            mon = iface_mod.set_monitor(base)
            console.ok(f"{mon}: managed mode (Windows has no monitor vif)")
            return {"iface": mon, "mode": iface_mod.current_mode(mon)}
        mon = iface_mod.set_monitor(base)
        if self.get("NAME") and mon != self.get("NAME"):
            iface_mod.set_managed(mon)
            mon = iface_mod.set_monitor(base)
        from omni.core import config
        config.set_value("wifi.monitor_interface", mon)
        console.ok(f"{mon} is in monitor mode")
        return {"iface": mon, "mode": iface_mod.current_mode(mon)}


class Scan(WifiModule):
    NAME = "wifi.scan"
    DESCRIPTION = "Discover access points (iw active or airodump passive)"
    OPTIONS = (Option("IFACE", "interface (auto)"),
               Option("METHOD", "iw|airodump", "iw", choices=("iw", "airodump")),
               Option("SECONDS", "how long to listen (airodump)", "25"),
               Option("BAND", "airodump band string", "abg"))

    def execute(self) -> list[dict]:
        from omni.core import config
        if self.get("METHOD") == "airodump":
            mon = config.get_value("wifi.monitor_interface") or self.monitor()
            aps = scan_mod.scan_airodump(mon, self.get_int("SECONDS", 25),
                                         self.get("BAND"))
        else:
            try:
                base = iface_mod.pick(self.get("IFACE") or None)
            except RuntimeError:
                if not host.is_windows():
                    raise
                base = ""
                console.warn("no wireless interface — trying the netsh scan")
            aps = scan_mod.scan_any(base)
        aps = scan_mod.ranked(aps)
        console.table(["bssid", "ssid", "ch", "sig", "sec"],
                      [[a["bssid"], a["ssid"] or "<hidden>", str(a["channel"] or "-"),
                        str(a["signal"] or "-"), a["security"]] for a in aps])
        if aps:
            console.info(f"saved: {scan_mod.save_targets(aps)}")
        return aps
