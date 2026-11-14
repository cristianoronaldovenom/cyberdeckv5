"""Android trade — ADB-based device takeover (port of PhoneSploit-Pro).

The point of PhoneSploit-Pro was "one menu, then do everything ADB allows".
Here the ADB glue is a real library (:class:`Adb`) so modules, the menu and
scripts all share one code path.
"""

from __future__ import annotations

from omni.android.adb import Adb, AdbError, Device
from omni.android import extras, media, security

__all__ = ["Adb", "AdbError", "Device", "extras", "media", "security"]
