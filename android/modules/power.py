"""Power, display, volume and radio toggles."""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.android.modules._base import AndroidModule


class Power(AndroidModule):
    NAME = "android.power"
    DESCRIPTION = "Screen on / off / toggle / reboot"
    OPTIONS = (Option("ACTION", "on|off|toggle|reboot|recovery|bootloader",
                      "toggle", choices=("on", "off", "toggle", "reboot",
                                         "recovery", "bootloader")),)

    def execute(self) -> str:
        client, action = self.adb(), self.get("ACTION")
        if action == "toggle":
            client.power_key()
        elif action in ("on", "off"):
            client.power(action)
        else:
            console.info("rebooting" if action == "reboot"
                         else f"rebooting into {action}")
            client.reboot("" if action == "reboot" else action)
        return action


class Brightness(AndroidModule):
    NAME = "android.brightness"
    DESCRIPTION = "Set screen brightness"
    OPTIONS = (Option("LEVEL", "0-255", "128", required=True),
               Option("AUTO", "enable adaptive brightness too", "false",
                      choices=("true", "false")))

    def execute(self) -> int:
        client = self.adb()
        level = max(0, min(255, self.get_int("LEVEL", 128)))
        if self.get_bool("AUTO"):
            client.auto_brightness(True)
        client.brightness(level)
        return level


class StayAwake(AndroidModule):
    NAME = "android.stayawake"
    DESCRIPTION = "Keep the screen on while charging"
    OPTIONS = (Option("ON", "true|false", "true", choices=("true", "false")),)

    def execute(self) -> bool:
        value = self.get_bool("ON", True)
        self.adb().stay_awake(value)
        return value


class Volume(AndroidModule):
    NAME = "android.volume"
    DESCRIPTION = "Set a volume stream level"
    OPTIONS = (Option("STREAM", "music|ring|alarm|call", "music",
                      choices=("music", "ring", "alarm", "call")),
               Option("LEVEL", "0-15", "8", required=True))

    def execute(self) -> int:
        level = max(0, min(15, self.get_int("LEVEL", 8)))
        self.adb().volume(self.get("STREAM"), level)
        return level


class Radio(AndroidModule):
    NAME = "android.radio"
    DESCRIPTION = "Toggle a radio (wifi / data / airplane / bluetooth / nfc)"
    OPTIONS = (Option("RADIO", "radio name", "wifi",
                      choices=("wifi", "data", "airplane", "bluetooth", "nfc")),
               Option("ON", "true|false", "true", choices=("true", "false")))

    def execute(self) -> dict:
        client, radio, on = self.adb(), self.get("RADIO"), self.get_bool("ON", True)
        getattr(client, radio)(on)
        return {radio: on}
