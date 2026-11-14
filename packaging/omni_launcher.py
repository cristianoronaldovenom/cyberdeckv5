"""Entry point for the frozen OMNI binary (Windows .exe, macOS build).

The source tree has two doors, ``python -m omni.cli`` and the ``omni`` console
script. A frozen build has exactly one, and it has to survive a double-click:

* a Windows console starts on cp1252 and the toolkit prints box characters and
  em dashes, so both streams are re-encoded to UTF-8 first;
* with no arguments it opens the plain numbered goal menu (no curses needed)
  and waits for Enter before the window closes, so a double-click never just
  flashes;
* a crash on the way in stays readable because the traceback and the pause
  happen before the console disappears.
"""

from __future__ import annotations

import os
import sys
import traceback


def _safe_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _pause() -> None:
    try:
        input("\npress Enter to close ")
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> int:
    _safe_streams()
    interactive = len(sys.argv) <= 1
    try:
        if interactive:
            import os
            if os.name == "nt" and not os.environ.get("OMNI_NO_ELEVATE"):
                from omni.core import elevate
                if elevate.relaunch([sys.executable]):
                    return 0
            from omni.core import gui
            if gui.available():
                return gui.run()
            from omni.core import menu
            try:
                return menu.run()
            finally:
                _pause()
        from omni.cli import main as cli_main
        return cli_main()
    except KeyboardInterrupt:
        print()
        return 130
    except Exception:                             # noqa: BLE001 - show it
        traceback.print_exc()
        _pause()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
