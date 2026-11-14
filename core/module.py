"""Module contract + registry.

Ported from the unbekannt-framework module model (metadata + option list +
``MAIN()`` loop), but re-implemented as declarative classes so the same module
is reachable from the interactive console, from ``omni run <name>``, and from
pytest.

A module is any subclass of :class:`Module` living in a registered module
package (``omni.<trade>.modules``) or in the user drop-in directory
``~/.config/omni/modules/``.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import sys
import traceback
from dataclasses import dataclass

from omni.core import config, console, proc

__all__ = ["Option", "Module", "registry", "FAMILIES"]

#: trade families — order matters, it drives the menu
FAMILIES = {
    "rf": "Sub-GHz radio (CC1101 / Flipper stack)",
    "wifi": "Wireless: monitor mode, capture, WPS/PMKID, cracking",
    "radio": "Universal radio: SDR, RFID, NFC, Bluetooth, IR",
    "car": "Car key RKE: KeeLoq analysis, counter sweep, replay",
    "brute": "Brute force: PIN/mask, wordlists, HTTP, SSH, hashes",
    "android": "Android device takeover (ADB)",
    "ios": "iPhone/iPad takeover (pymobiledevice3, Developer Mode)",
    "pentest": "Network / pentest modules",
    "mobile": "Mobile app reversing (Frida / MobSF)",
    "windows": "Windows credential & persistence tradecraft",
    "news": "Hacker News client",
    "flip": "Flipper Zero files & firmware",
    "core": "Toolkit housekeeping",
}


@dataclass
class Option:
    """One settable module parameter."""

    name: str
    description: str
    default: str = ""
    required: bool = False
    choices: tuple[str, ...] = ()
    secret: bool = False
    value: str = ""

    def resolve(self) -> str:
        return self.value or self.default or ""

    def shown(self) -> str:
        val = self.resolve()
        if not val:
            return ""
        return "********" if self.secret else val


class Module:
    """Base class for every OMNI module."""

    NAME = "base"
    DESCRIPTION = "abstract module"
    AUTHOR = "OMNI"
    FAMILY = "core"
    NEEDS: tuple[str, ...] = ()          # required external binaries
    OPTIONS: tuple[Option, ...] = ()

    def __init__(self, **values: str):
        self.opts: dict[str, Option] = {o.name: Option(**o.__dict__)
                                        for o in self.OPTIONS}
        for key, val in values.items():
            self.set(key, val)
        self.result: object = None

    # -- options ----------------------------------------------------------
    def get(self, name: str) -> str:
        opt = self.opts.get(name.upper())
        return opt.resolve() if opt else ""

    def get_int(self, name: str, default: int = 0) -> int:
        try:
            return int(self.get(name))
        except (TypeError, ValueError):
            return default

    def get_bool(self, name: str, default: bool = False) -> bool:
        raw = self.get(name).strip().lower()
        if not raw:
            return default
        return raw in ("1", "true", "yes", "y", "on")

    def set(self, name: str, value) -> Option:
        key = name.upper()
        if key not in self.opts:
            raise KeyError(f"unknown option '{name}' for module {self.NAME}")
        opt = self.opts[key]
        value = "" if value is None else str(value)
        if opt.choices and value and value not in opt.choices:
            raise ValueError(f"{name} must be one of {', '.join(opt.choices)}")
        opt.value = value
        return opt

    def missing(self) -> list[str]:
        return [o.name for o in self.opts.values() if o.required and not o.resolve()]

    def tools_missing(self) -> list[str]:
        return [t for t in self.NEEDS if not proc.has(t)]

    def validate(self) -> None:
        gaps = self.missing()
        if gaps:
            raise ValueError("missing required option(s): " + ", ".join(gaps))
        absent = self.tools_missing()
        if absent:
            hint = ", ".join(f"{t} ({proc.install_hint(t)})" for t in absent)
            console.warn("missing tool(s), continuing in fallback mode: " + hint)

    # -- presentation -----------------------------------------------------
    def help(self) -> None:
        console.section(f"{self.NAME} — {self.DESCRIPTION}")
        console.kv([("author", self.AUTHOR), ("family", self.FAMILY),
                    ("needs", ", ".join(self.NEEDS) or "nothing")])
        print()
        if self.opts:
            console.table(
                ["option", "description", "current", "required"],
                [[o.name, o.description, o.shown() or "-",
                  "yes" if o.required else ""] for o in self.opts.values()])
        else:
            console.info("no options")
        print()
        console.info("run with:  run        |  leave with:  back")

    # -- execution --------------------------------------------------------
    def usage(self) -> str:
        """Short reminder of the options a run still needs."""
        gaps = self.missing()
        if not gaps:
            return ""
        lines = [f"{self.NAME} needs: " + ", ".join(gaps), "options:"]
        for opt in self.opts.values():
            choices = f" [{('|'.join(opt.choices))}]" if opt.choices else ""
            lines.append(f"  {opt.name}=<value>{choices}  {opt.description}")
        return "\n".join(lines)

    def run(self) -> object:
        self.validate()
        try:
            self.result = self.execute()
            return self.result
        except KeyboardInterrupt:
            console.warn("interrupted")
            raise
        except Exception as exc:  # noqa: BLE001
            console.err(f"{type(exc).__name__}: {exc}")
            if config.get_value("verbose"):
                traceback.print_exc()
            raise

    def execute(self) -> object:  # pragma: no cover - abstract
        raise NotImplementedError


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

class _Registry:
    def __init__(self) -> None:
        self._modules: dict[str, type[Module]] = {}
        self._loaded = False

    # -- discovery --------------------------------------------------------
    def user_dir(self) -> str:
        return os.path.expanduser("~/.config/omni/modules")

    def _load_package(self, pkg_name: str) -> None:
        # a frozen one-file build has no files to list: use the manifest
        if getattr(sys, "frozen", False) or not self._source_tree(pkg_name):
            self._load_manifest(pkg_name)
            return
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError:
            return
        pkg_file = getattr(pkg, "__file__", "") or ""
        if not pkg_file:
            return
        folder = os.path.dirname(pkg_file)
        for entry in sorted(os.listdir(folder)):
            if entry.endswith(".py") and not entry.startswith("_"):
                self._load_file(os.path.join(folder, entry),
                                f"{pkg_name}.{entry[:-3]}")

    @staticmethod
    def _source_tree(pkg_name: str) -> bool:
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError:
            return False
        folder = os.path.dirname(getattr(pkg, "__file__", "") or "")
        return bool(folder) and os.path.isdir(folder)

    def _load_manifest(self, pkg_name: str) -> None:
        from omni.core._manifest import MODULES

        for full in MODULES:
            if not full.startswith(pkg_name + "."):
                continue
            try:
                mod = importlib.import_module(full)
            except Exception as exc:  # noqa: BLE001
                console.debug(f"module load failed {full}: {exc}")
                continue
            self._register(mod)

    def _load_file(self, path: str, mod_name: str | None = None) -> None:
        mod_name = mod_name or f"omni_user_{os.path.basename(path)[:-3]}"
        try:
            spec = importlib.util.spec_from_file_location(mod_name, path)
            if spec is None or spec.loader is None:
                return
            mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)
        except Exception as exc:  # noqa: BLE001
            console.debug(f"module load failed {path}: {exc}")
            return
        self._register(mod)

    def _register(self, mod) -> None:
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if (issubclass(obj, Module) and obj is not Module
                    and obj.__module__ == mod.__name__ and obj.NAME != "base"):
                self._modules[obj.NAME] = obj

    def load(self, force: bool = False) -> None:
        if self._loaded and not force:
            return
        self._modules.clear()
        for fam in FAMILIES:
            self._load_package(f"omni.{fam}.modules")
        user = self.user_dir()
        if os.path.isdir(user):
            for entry in sorted(os.listdir(user)):
                if entry.endswith(".py") and not entry.startswith("_"):
                    self._load_file(os.path.join(user, entry))
        self._loaded = True

    # -- access -----------------------------------------------------------
    def all(self, family: str | None = None) -> list[type[Module]]:
        self.load()
        mods = [m for m in self._modules.values() if family in (None, m.FAMILY)]
        return sorted(mods, key=lambda m: (m.FAMILY, m.NAME))

    def get(self, name: str) -> type[Module] | None:
        self.load()
        return self._modules.get(name.lower())

    def build(self, name: str, **values: str) -> Module:
        cls = self.get(name)
        if cls is None:
            raise KeyError(f"no such module: {name}")
        return cls(**values)

    def families(self) -> dict[str, list[type[Module]]]:
        out: dict[str, list[type[Module]]] = {}
        for mod in self.all():
            out.setdefault(mod.FAMILY, []).append(mod)
        return out

    def search(self, query: str) -> list[type[Module]]:
        q = query.lower()
        return [m for m in self.all()
                if q in m.NAME or q in m.DESCRIPTION.lower()
                or any(q in o.name.lower() for o in m.OPTIONS)]


registry = _Registry()
