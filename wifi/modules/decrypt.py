"""Pure-Python WPA2 attack and decryption — no aircrack, no hashcat.

* ``wifi.crack_pure`` — wordlist/mask attack proven against the captured MIC.
* ``wifi.handshakes`` — list usable handshakes in a capture (and the SSIDs).
* ``wifi.decrypt`` — with the PSK, decrypt CCMP frames and dump the plaintext.

These exist because the aircrack/hashcat path needs binaries installed; this
one only needs Python. It is far slower (thousands/s vs millions/s), so it is
for small, targeted attacks — but it cannot be blocked by a missing package.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.wifi import ccmp, pcapread, pskcrack, wpa
from omni.wifi.modules._base import WifiModule

__all__ = ["CrackPure", "Handshakes", "Decrypt"]


class Handshakes(WifiModule):
    NAME = "wifi.handshakes"
    DESCRIPTION = "List testable handshakes in a capture (pure stdlib parser)"
    OPTIONS = (Option("PCAP", "capture file", "", required=True),)

    def execute(self) -> dict:
        found = pcapread.find_handshakes(self.get("PCAP"))
        if not found:
            console.warn("no complete handshake (need message 1/3 + message 2)")
            return {"handshakes": []}
        rows = [[h.describe(), "yes" if h.ssid else "no"] for h in found]
        console.table(["handshake", "ssid known"], rows)
        console.info("crack with: omni run wifi.crack_pure")
        return {"handshakes": [h.describe() for h in found]}


class CrackPure(WifiModule):
    NAME = "wifi.crack_pure"
    DESCRIPTION = "Offline WPA2 PSK attack in pure Python (wordlist/mask + rules)"
    OPTIONS = (Option("PCAP", "capture with a handshake", "", required=True),
               Option("BSSID", "only this AP"),
               Option("WORDLIST", "wordlist path"),
               Option("MASK", "mask to exhaust, e.g. ?u?l?l?l?d?d"),
               Option("RULES", "apply mutation rules to the wordlist", "true",
                      choices=("true", "false")),
               Option("WORKERS", "processes to use (blank = cores - 1)"),
               Option("LIMIT", "stop after N candidates"))

    def execute(self) -> dict:
        found = pcapread.find_handshakes(self.get("PCAP"))
        if self.get("BSSID"):
            wanted = self.get("BSSID").upper()
            found = [h for h in found if h.bssid == wanted]
        if not found:
            raise ValueError("no usable handshake in the capture")
        target = found[0]
        if not target.ssid:
            raise ValueError("SSID unknown — capture a beacon for this AP first")
        if not self.get("WORDLIST") and not self.get("MASK"):
            raise ValueError("give WORDLIST and/or MASK")

        words = None
        if self.get("WORDLIST"):
            path = os.path.expanduser(self.get("WORDLIST"))
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                words = [line.rstrip("\n") for line in fh]

        console.kv([("target", target.describe())])
        workers = self.get_int("WORKERS", 0) or None
        console.info(f"pure-python, {workers or 'auto'} process(es): expect a "
                     "few hundred tries/s per core")
        limit = self.get_int("LIMIT", 0) or None

        def progress(tried: int, elapsed: float) -> None:
            console.info(f"{tried} tried ({tried / max(elapsed, 0.001):.0f}/s)")

        result = pskcrack.crack_parallel(target, words, self.get("MASK"),
                                         self.get_bool("RULES", True), limit,
                                         workers, progress)
        if result.found:
            console.ok(result.summary())
            out = os.path.join(config.output_dir("wifi"),
                              f"psk_{target.bssid.replace(':', '')}.txt")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(f"ssid={target.ssid.decode('utf-8', 'replace')}\n"
                         f"psk={result.passphrase}\n")
            console.info(f"written: {out}")
        else:
            console.warn(result.summary())
        return {"passphrase": result.passphrase, "tried": result.tried,
                "complete": result.complete}


class Decrypt(WifiModule):
    NAME = "wifi.decrypt"
    DESCRIPTION = "Decrypt CCMP traffic with a known PSK and dump the plaintext"
    OPTIONS = (Option("PCAP", "capture file", "", required=True),
               Option("PSK", "the passphrase", "", required=True),
               Option("BSSID", "AP the PSK belongs to (picks the handshake)"),
               Option("OUT", "plaintext output path"),
               Option("PRINT", "echo recovered payloads", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        found = pcapread.find_handshakes(self.get("PCAP"))
        if self.get("BSSID"):
            found = [h for h in found
                     if h.bssid == self.get("BSSID").upper()]
        if not found:
            raise ValueError("no handshake in the capture — the PTK needs one")
        target = found[0]
        if not target.verify(self.get("PSK")):
            raise ValueError("that PSK does not match this handshake")
        console.ok("PSK verified against the handshake")

        key = wpa.ptk(wpa.pmk(self.get("PSK"), target.ssid), target.ap,
                      target.sta, target.a_nonce, target.s_nonce, 512)
        tk = key[32:48]                       # KCK 16 | KEK 16 | TK 16
        out = os.path.expanduser(
            self.get("OUT") or
            os.path.join(config.output_dir("wifi"),
                         f"plain_{time.strftime('%Y%m%d_%H%M%S')}.txt"))
        os.makedirs(os.path.dirname(out), exist_ok=True)

        opened = failed = 0
        with open(out, "wb") as fh:
            for frame, body in pcapread.data_frames(self.get("PCAP")):
                try:
                    pn, cipher, _key_id = ccmp.split_ccmp_body(body)
                    plain = ccmp.ccmp_decrypt(cipher, tk,
                                              ccmp.ccmp_nonce(0, frame[10:16],
                                                              pn),
                                              ccmp.ccmp_aad(frame))
                except Exception:                # noqa: BLE001 - wrong dir/key
                    failed += 1
                    continue
                opened += 1
                fh.write(frame[10:16] + b" " + plain + b"\n")
                if self.get_bool("PRINT", True):
                    console.info(plain[:120].decode("utf-8", "replace")
                                 .replace("\r", "").replace("\n", " "))

        console.ok(f"{opened} frame(s) decrypted, {failed} skipped -> {out}")
        return {"decrypted": opened, "skipped": failed, "path": out}

