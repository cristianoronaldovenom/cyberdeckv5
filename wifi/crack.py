"""WPA handshake cracking: aircrack-ng and hashcat mode 22000.

``aircrack_parse`` and ``mask_candidates`` are pure so they can be tested
without hardware or wordlists.
"""

from __future__ import annotations

import os
import re

from omni.core import config, proc

__all__ = ["aircrack", "to_22000", "hashcat", "aircrack_parse", "mask_candidates"]


def aircrack_parse(text: str) -> dict | None:
    """Extract ``KEY FOUND! [ secret ]`` from aircrack-ng output."""
    m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", text)
    if not m:
        return None
    key = m.group(1)
    return {"key": key, "length": len(key),
            "printable": all(32 <= ord(c) < 127 for c in key)}


def aircrack(pcap: str, wordlist: str | None = None, bssid: str | None = None,
             essid: str | None = None,
             extra: list[str] | None = None) -> dict:
    """Run aircrack-ng against a capture; returns parsed hit or diagnostics."""
    proc.require("aircrack-ng")
    wordlist = wordlist or str(config.get_value("wifi.wordlist", ""))
    argv = ["aircrack-ng", pcap, "-w", wordlist] if wordlist else ["aircrack-ng", pcap]
    if bssid:
        argv += ["-b", bssid]
    if essid:
        argv += ["-e", essid]
    if extra:
        argv += list(extra)
    res = proc.run(argv, timeout=3600)
    hit = aircrack_parse(res.text)
    return {"found": hit is not None, "key": (hit or {}).get("key"),
            "pcap": pcap, "wordlist": wordlist, "tail": res.lines()[-6:]}


def to_22000(pcap: str, out: str | None = None) -> str | None:
    """Convert a pcap/pcapng into hashcat's 22000 format."""
    proc.require("hcxpcapngtool")
    out = out or os.path.splitext(pcap)[0] + ".22000"
    res = proc.run(["hcxpcapngtool", "-o", out, pcap], timeout=600)
    if res.ok and os.path.exists(out) and os.path.getsize(out) > 0:
        return out
    return None


def hashcat(hashfile: str, wordlist: str | None = None, mode: str = "22000",
            extra: list[str] | None = None) -> dict:
    """Crack a hashfile with hashcat; captures the recovered key."""
    binary = str(config.get_value("brute.hashcat_binary", "hashcat"))
    proc.require(binary)
    outdir = config.output_dir("wifi/hashcat")
    argv = [binary, "-m", mode, "-a", "0", hashfile,
            wordlist or str(config.get_value("wifi.wordlist", "")),
            "--potfile-path", os.path.join(outdir, "omni.pot"),
            "--outfile", os.path.join(outdir, "recovered.txt"),
            "--outfile-format", "2", "--status", "--status-timer", "5"]
    if extra:
        argv += list(extra)
    res = proc.run(argv, timeout=7200)
    recovered = []
    rec_path = os.path.join(outdir, "recovered.txt")
    if os.path.exists(rec_path):
        with open(rec_path, "r", encoding="utf-8", errors="replace") as fh:
            recovered = [ln.strip().split("\t")[-1] for ln in fh
                         if ln.strip()]
    return {"found": bool(recovered), "keys": recovered,
            "hashfile": hashfile, "status": res.lines()[-4:]}


def mask_candidates(mask: str, limit: int | None = None) -> int:
    """Size of the keyspace a hashcat-style mask describes."""
    charsets = {
        "?d": 10, "?l": 26, "?u": 26, "?a": 95, "?h": 16, "?H": 16,
        "?s": 33, "?b": 256,
    }
    total = 1
    i = 0
    while i < len(mask):
        pair = mask[i:i + 2]
        if pair in charsets:
            total *= charsets[pair]
            i += 2
        elif pair == "??":
            i += 2          # literal '?'
        else:
            i += 1
        if limit is not None and total > limit:
            return total
    return total
