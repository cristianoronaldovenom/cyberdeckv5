"""Batch decryption: throw captures and keys at it, take the loot out.

``wifi.decrypt`` handles one capture and one PSK. This feeds the whole pile
through :mod:`omni.wifi.extract`: several captures (globs and directories are
fine), several keys, every matching handshake decrypted, TCP reassembled, and
the results pulled apart into URLs, DNS, TLS SNI, credentials and files.

Keys come from wherever you already have them — the ``psk_<bssid>.txt`` files
``wifi.crack_pure`` writes, a ``ssid:psk`` list, or ``AUTO=true`` which sweeps
the loot directory for both. Captures without a key are reported, not fatal.
"""

from __future__ import annotations

import glob
import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.wifi import extract as extract_mod
from omni.wifi.modules._base import WifiModule

__all__ = ["Extract"]


class Extract(WifiModule):
    NAME = "wifi.extract"
    DESCRIPTION = "Decrypt many captures at once and extract creds, URLs, files"
    OPTIONS = (Option("INPUT", "captures: paths, globs or a directory", "",
                      required=True),
               Option("PSK", "passphrase, or a file of 'ssid:psk' lines"),
               Option("AUTO", "also use solved psk_*.txt files from loot",
                      "true", choices=("true", "false")),
               Option("OUT", "output directory"),
               Option("PRINT", "echo what was found", "true",
                      choices=("true", "false")),
               Option("MAX_FILES", "stop after N written files", "200"))

    def execute(self) -> dict:
        paths = extract_mod.expand_inputs(self.get("INPUT"))
        if not paths:
            raise FileNotFoundError(f"no captures matched {self.get('INPUT')!r}")

        keys = self._keys()
        if not keys:
            raise ValueError("no keys — give PSK=passphrase, PSK=keys.txt, or "
                             "leave AUTO on next to solved psk_*.txt files")
        out = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("wifi"), "extract",
                         time.strftime("%Y%m%d_%H%M%S")))
        console.kv([("captures", str(len(paths))), ("keys", str(len(keys) // 2)),
                    ("out", out)])

        report = extract_mod.extract(paths, keys, out,
                                     self.get_int("MAX_FILES", 200))
        for path, reason in report.skipped[:10]:
            console.warn(f"{os.path.basename(path)}: {reason}")
        self._show(report)
        console.ok(f"{report.frames} frame(s) decrypted, "
                   f"{len(report.streams)} stream(s) -> {out}")
        if not report.frames:
            console.warn("nothing decrypted — check the key really belongs to "
                         "these handshakes (wifi.handshakes lists them)")
        return report.as_dict()

    def _keys(self) -> dict[str, str]:
        """Keys from PSK (literal or file) plus any solved psk_*.txt on disk."""
        keys: dict[str, str] = {}
        given = self.get("PSK")
        if given:
            path = os.path.expanduser(given)
            if os.path.isfile(path):
                keys.update(extract_mod.load_keys(extract_mod.read_text(path)))
            else:
                # bare passphrase: it applies to whatever SSID the capture has
                for item in extract_mod.expand_inputs(self.get("INPUT")):
                    for line in _ssids(item):
                        keys[line] = given
        if self.get_bool("AUTO", True):
            for solved in glob.glob(os.path.join(config.output_dir("wifi"),
                                                 "psk_*.txt")):
                keys.update(extract_mod.load_keys(
                    extract_mod.read_text(solved)))
        return keys

    def _show(self, report) -> None:
        """Print the findings in the order a human wants them."""
        if not self.get_bool("PRINT", True):
            return
        for source, user, pwd in report.creds[:40]:
            console.ok(f"cred ({source}) {user or '-'}:{pwd or '-'}")
        for url in report.urls[:25]:
            console.info(f"url  {url}")
        for name in report.dns[:25]:
            console.info(f"dns  {name}")
        for name in report.sni[:25]:
            console.info(f"sni  {name}")
        for path, size in report.files[:20]:
            console.info(f"file {size}B {path}")


def _ssids(path: str) -> list[str]:
    """Every SSID an AP in this capture advertises."""
    from omni.wifi import pcapread

    try:
        return [ssid.decode("utf-8", "replace")
                for ssid in pcapread.ssid_map(path).values() if ssid]
    except Exception:                            # noqa: BLE001 - best effort
        return []
