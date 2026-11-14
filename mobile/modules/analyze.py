"""Static APK analysis: manifest, permissions, native ABIs."""

import json
import os

from omni.core import console
from omni.core.module import Option
from omni.mobile import apk
from omni.mobile.modules._base import MobileModule

__all__ = ["Analyze"]


class Analyze(MobileModule):
    NAME = "mobile.analyze"
    DESCRIPTION = "Static analysis of an APK: entries, ABIs, permissions"
    OPTIONS = (Option("APK", "path to the .apk", "", required=True),
               Option("SAVE", "write mobile/analyze.json", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        info = apk.manifest_summary(self.get("APK"))
        console.table(["field", "value"],
                      [[k, str(v)[:70]] for k, v in info.items()])
        if self.get_bool("SAVE", True):
            out = os.path.join(self.out_dir(), "analyze.json")
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(info, fh, indent=2)
            console.ok(f"report -> {out}")
        return info
