"""Hunt embedded endpoints/keys in an APK (apkleaks / strings)."""

import os

from omni.core import console
from omni.core.module import Option
from omni.mobile import apk
from omni.mobile.modules._base import MobileModule

__all__ = ["SecretsApk"]


class SecretsApk(MobileModule):
    NAME = "mobile.secrets"
    DESCRIPTION = "Extract URLs, keys and tokens baked into an APK"
    OPTIONS = (Option("APK", "path to the .apk", "", required=True),
               Option("OUT", "where to write findings", ""))

    def execute(self) -> list[str]:
        findings = apk.secrets(self.get("APK"), self.get("OUT") or None)
        for f in findings[:100]:
            console.info(f)
        if self.get("OUT"):
            os.makedirs(self.get("OUT"), exist_ok=True)
            path = os.path.join(self.get("OUT"), "apkleaks.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(findings))
            console.ok(f"findings -> {path}")
        return findings
