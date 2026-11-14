"""Turn on wireless ADB and connect to it."""

from __future__ import annotations

from omni.android.modules._base import AndroidModule
from omni.core import console
from omni.core.module import Option


class Connect(AndroidModule):
    NAME = "android.connect"
    DESCRIPTION = "Enable TCP/IP ADB over Wi-Fi and connect to it"
    OPTIONS = (
        Option("PORT", "TCP port for the adb daemon", "5555"),
        Option("ADDRESS", "host:port to connect to (blank = this device's Wi-Fi IP)",
               required=False),
    )

    def execute(self) -> dict:
        client = self.adb()
        port = self.get_int("PORT", 5555)
        target = self.get("ADDRESS")

        if target:
            res = client.connect(target)
            if not res.ok:
                raise RuntimeError(res.text[:300])
            console.ok(f"connected to {target}")
            client.serial = target
            return {"connected": target}

        ip = client.ip_address()
        if not ip:
            raise RuntimeError("device has no Wi-Fi address; pass ADDRESS instead")
        client.enable_tcpip(port)
        endpoint = f"{ip}:{port}"
        console.info(f"connecting to {endpoint}")
        res = client.connect(endpoint)
        if not res.ok:
            raise RuntimeError(res.text[:300])
        console.ok(f"wireless adb ready — {endpoint}")
        return {"connected": endpoint, "usb_serial": client.serial}
