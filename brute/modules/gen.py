"""Keyspace inspection and wordlist mutation previews."""

from __future__ import annotations

from omni.brute import space, words
from omni.core import config, console
from omni.core.module import Option
from omni.brute.modules._base import BruteModule

__all__ = ["Space", "Mutate", "Masks"]


class Space(BruteModule):
    NAME = "brute.space"
    DESCRIPTION = "Size a mask and stream the first candidates"
    OPTIONS = (Option("MASK", "hashcat-style mask, e.g. ?d?d?d?d",
                      "?d?d?d?d"),
               Option("SHOW", "how many candidates to print", "20"))

    def execute(self) -> dict:
        spec = self.get("MASK")
        size = space.keyspace_size(spec)
        ceiling = int(config.get_value("brute.max_candidates", 200000))
        console.kv([("mask", spec), ("keyspace", f"{size:,}"),
                    ("ceiling", f"{ceiling:,}"),
                    ("fits", "yes" if size <= ceiling else "no — will truncate")])
        sample = []
        for candidate in space.cap(space.mask(spec), self.get_int("SHOW", 20)):
            sample.append(candidate)
            console.info(candidate)
        return {"mask": spec, "size": size, "sample": sample}


class Masks(BruteModule):
    NAME = "brute.masks"
    DESCRIPTION = "Common masks with their keyspace sizes"
    OPTIONS = (Option("LENGTH", "PIN length to include", "4"),)

    def execute(self) -> list[dict]:
        length = max(1, self.get_int("LENGTH", 4))
        presets = [
            ("PIN numeric", "?d" * length),
            ("hex", "?h" * length),
            ("lowercase", "?l" * min(6, length + 2)),
            ("alnum", "?u?l?l?l?d?d"),
            ("year+digits", "20?d?d"),
        ]
        rows = []
        for label, spec in presets:
            size = space.keyspace_size(spec)
            rows.append({"use": label, "mask": spec, "keyspace": size,
                         "fits": space.is_plausible(spec)})
        console.table(["use", "mask", "keyspace", "fits"],
                      [[r["use"], r["mask"], f"{r['keyspace']:,}",
                        "yes" if r["fits"] else "no"] for r in rows])
        return rows


class Mutate(BruteModule):
    NAME = "brute.mutate"
    DESCRIPTION = "Preview wordlist mutations (case, leet, suffixes)"
    OPTIONS = (Option("WORDS", "wordlist path or inline words",
                      "admin,password,letmein"),
               Option("LIMIT", "candidates to print", "25"),
               Option("NOLEET", "skip leet substitutions"))

    def execute(self) -> list[str]:
        stream = words.mutate(words.load(self.get("WORDS")),
                              leet=not self.get_bool("NOLEET"))
        out = []
        for candidate in space.cap(stream, self.get_int("LIMIT", 25)):
            out.append(candidate)
            console.info(candidate)
        return out
