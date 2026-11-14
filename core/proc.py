"""Subprocess helpers — everything the Android/Windows/mobile modules shell out to.

All helpers are Linux/macOS friendly, never use ``shell=True`` for user data,
and return a :class:`Result` instead of raising.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

__all__ = ["Result", "run", "run_live", "spawn", "has", "which", "ToolMissing",
           "require", "install_hint"]


class ToolMissing(RuntimeError):
    """Raised by :func:`require` when an external binary is not installed."""


@dataclass
class Result:
    argv: list[str]
    code: int = 0
    out: str = ""
    err: str = ""
    env: dict = field(default_factory=dict)
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0 and not self.timed_out

    @property
    def text(self) -> str:
        return (self.out + self.err).strip()

    def lines(self) -> list[str]:
        return [ln.rstrip() for ln in self.out.splitlines() if ln.strip()]

    def check(self) -> "Result":
        if not self.ok:
            raise RuntimeError(
                f"{' '.join(self.argv)} failed ({self.code}): {self.text[:400]}")
        return self

    def __str__(self) -> str:
        return self.text


def which(binary: str) -> str | None:
    if not binary:
        return None
    return shutil.which(binary) or (
        binary if os.path.isabs(binary) and os.access(binary, os.X_OK) else None)


def has(binary: str) -> bool:
    return which(binary) is not None


def clear_cache() -> None:
    """Compatibility hook: ``shutil.which`` has no cache, so this is a no-op."""
    return None


def install_hint(binary: str) -> str:
    """One-line, platform-appropriate way to get ``binary``, never raising."""
    if os.name == "nt":
        return (f"install it (winget) or run `omni setup {binary}`; "
                "Linux-only wireless tools also work inside WSL")
    if sys.platform == "darwin":
        return f"brew install {binary}  (or `omni setup {binary}`)"
    return f"sudo apt install {binary}  (or `omni setup {binary}`)"


def require(binary: str, hint: str = "") -> str:
    """Return the resolved path to ``binary`` or raise ToolMissing."""
    path = which(binary)
    if path is None:
        extra = f"  ({hint})" if hint else f"  ({install_hint(binary)})"
        raise ToolMissing(f"'{binary}' not found in PATH{extra}")
    return path


def run(argv: list[str], timeout: int = 120, cwd: str | None = None,
        env: dict | None = None, input_text: str | None = None) -> Result:
    """Run a command to completion and capture its output."""
    argv = [str(a) for a in argv]
    full_env = dict(os.environ)
    full_env.update({"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              cwd=cwd, env=full_env, input=input_text,
                              errors="replace")
        return Result(argv, proc.returncode, proc.stdout or "", proc.stderr or "", env or {})
    except FileNotFoundError:
        return Result(argv, 127, "", f"binary not found: {argv[0]}", env or {})
    except subprocess.TimeoutExpired:
        return Result(argv, 124, "", f"timed out after {timeout}s", env or {}, True)
    except OSError as exc:
        return Result(argv, 126, "", str(exc), env or {})


def spawn(argv: list[str], cwd: str | None = None,
          env: dict | None = None) -> subprocess.Popen:
    """Start a long-running command (airodump, hostapd) without waiting.

    ``start_new_session`` puts the child in its own process group, so killing
    the launcher on POSIX takes the whole tree with it instead of leaving an
    orphaned airodump-ng holding the monitor interface.
    """
    argv = [str(a) for a in argv]
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.Popen(argv, cwd=cwd, env=full_env, text=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)


def run_live(argv: list[str], timeout: int | None = None, cwd: str | None = None,
             env: dict | None = None) -> int:
    """Run a command attached to the terminal (interactive tools, scrcpy...)."""
    argv = [str(a) for a in argv]
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        return subprocess.call(argv, cwd=cwd, env=full_env, timeout=timeout)
    except FileNotFoundError:
        return 127
    except KeyboardInterrupt:
        return 130
