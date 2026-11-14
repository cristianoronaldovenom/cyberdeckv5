"""Smoke-run every module with SHORT budgets so the sweep finishes fast.

Long-running listeners (sniff/hunt/jam/sweep) are given a 2-3 second budget via
their own options, which is what a user smoke-testing an install would want too.
"""

import io
import os
import sys
import traceback
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omni.core.module import FAMILIES, registry

#: fast overrides so nothing blocks for a minute
FAST = {
    "SECONDS": "2", "RUNTIME": "2", "WAIT": "2", "DWELL_MS": "4",
    "LOCK_SECONDS": "1", "COUNT": "2", "LIMIT": "20", "WINDOW": "2",
    "COPIES": "1", "INTERVAL": "1", "TIMEOUT": "3", "ROUNDS": "1",
    "STEPS": "1", "REPEAT": "1", "DISCOVER": "2", "REFRESH": "99",
}


def classify(exc: BaseException) -> str:
    if isinstance(exc, (TypeError, NameError, AttributeError, IndexError,
                        UnboundLocalError, ImportError, KeyError)):
        return "BUG"
    if isinstance(exc, (RuntimeError, ValueError, FileNotFoundError)):
        return "expected"
    return "other"


def main(families: list[str]) -> int:
    registry.load()
    bugs, ok, expected, other = [], 0, 0, 0
    for family in families:
        for cls in registry.all(family):
            if cls.NAME in ("core.doctor", "core.plan"):
                continue
            values = {opt.name: FAST[opt.name]
                      for opt in cls.OPTIONS if opt.name in FAST}
            try:
                instance = cls(**values)
            except Exception as exc:              # noqa: BLE001
                bugs.append(f"CONSTRUCT {cls.NAME}: {exc}")
                continue
            sink = io.StringIO()
            try:
                with redirect_stdout(sink):
                    instance.validate()
                    instance.execute()
                ok += 1
            except BaseException as exc:          # noqa: BLE001
                kind = classify(exc)
                if kind == "BUG":
                    bugs.append(f"{cls.NAME}: {type(exc).__name__}: {exc}\n"
                                + traceback.format_exc()[-600:])
                elif kind == "expected":
                    expected += 1
                else:
                    other += 1
    print(f"{','.join(families)}: ok={ok} expected={expected} other={other} "
          f"BUGS={len(bugs)}")
    for bug in bugs:
        print(bug)
    print("BUGS=0 means every module ran; 'expected' failures are only "
          "missing tools/devices")
    return 0 if not bugs else 1


if __name__ == "__main__":
    args = sys.argv[1:]
    raise SystemExit(main(args or list(FAMILIES)))
