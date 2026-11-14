"""Index Flipper captures on disk (.sub / .ir / .ibtn)."""

import os

from omni.core import console
from omni.core.module import Option
from omni.flip import files
from omni.flip.modules._base import FlipModule, capture_dir

__all__ = ["Index"]


class Index(FlipModule):
    NAME = "flip.index"
    DESCRIPTION = "Inventory every Flipper capture under a directory"
    OPTIONS = (Option("DIR", "directory to scan", "."),
               Option("SAVE", "write index.json to loot dir", "true",
                      choices=("true", "false")))

    def execute(self) -> list[dict]:
        rows = files.index_dir(self.get("DIR"))
        if not rows:
            console.warn("no .sub/.ir/.ibtn files found")
            return []
        console.table(
            ["kind", "summary", "path"],
            [[r["kind"], str(r["summary"])[:48], r["path"]] for r in rows])
        if self.get_bool("SAVE", True):
            import json
            out = os.path.join(capture_dir("index"), "index.json")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=2)
            console.ok(f"index -> {out}")
        return rows
