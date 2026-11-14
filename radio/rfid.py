"""RFID / NFC operations: Proxmark3 batch mode and PN532 via libnfc."""

from __future__ import annotations

import os
import re

from omni.core import config, proc

__all__ = ["pm3_available", "pm3", "search", "read_lf", "read_hf", "dump_mifare",
           "nfc_list", "parse_pm3_tags", "parse_nfc_list", "HID_FORMATS"]

#: Proxmark3 command templates for the common low-frequency credential families
HID_FORMATS = {
    "em4100": ["lf", "em", "410x_read"],
    "hidprox": ["lf", "hid", "read"],
    "indala": ["lf", "indala", "read"],
    "awid": ["lf", "awid", "read"],
    "pyramid": ["lf", "pyramid", "read"],
    "visa2000": ["lf", "visa2000", "read"],
    "gallagher": ["lf", "gallagher", "read"],
    "securicor": ["lf", "securicor", "read"],
    "nexwatch": ["lf", "nexwatch", "read"],
}


def pm3_binary() -> str:
    return str(config.get_value("radio.proxmark3", "pm3"))


def pm3_available() -> bool:
    return proc.has(pm3_binary())


def pm3(command: list[str] | str, timeout: int = 120) -> proc.Result:
    """Run a Proxmark3 command in batch mode (``pm3 -c "<cmd>"``)."""
    proc.require(pm3_binary(), "apt install proxmark3")
    cmd = command if isinstance(command, str) else " ".join(command)
    return proc.run([pm3_binary(), "-c", cmd], timeout=timeout)


_PM3_PROTOCOLS = (
    ("EM410", r"em[\s-]?410"),
    ("HID Prox", r"hid\s*prox"),
    ("Indala", r"indala"),
    ("Mifare", r"mifare"),
    ("iCLASS", r"iclass"),
    ("AWID", r"awid"),
    ("Gallagher", r"gallagher"),
    ("NexWatch", r"nexwatch"),
    ("Visa2000", r"visa2000"),
)


def parse_pm3_tags(text: str) -> list[dict]:
    """Pull UID + protocol from Proxmark3 search output.

    Handles both layouts seen in the wild: the UID inline after the family
    name (``EM 410x ID 3A0F2B1C4D``) and a following ``UID: ...`` line.
    """
    tags: list[dict] = []
    pending: str | None = None
    for line in text.splitlines():
        low = line.lower()
        proto = next((canon for canon, pattern in _PM3_PROTOCOLS
                      if re.search(pattern, low)), None)
        m = re.search(r"\b(?:UID|ID)\s*:?\s*([0-9a-fA-F ]{4,})",
                      line.rstrip("."))
        uid = re.sub(r"\s+", "", m.group(1)) if m else ""
        if proto and uid:
            tags.append({"uid": uid.upper(), "protocol": proto})
            pending = None
            continue
        if proto:
            pending = proto
            continue
        if pending and uid:
            tags.append({"uid": uid.upper(), "protocol": pending})
            pending = None
    return tags


def search(timeout: int = 60) -> dict:
    """Combined LF + HF search."""
    out = pm3(["lf", "search"], timeout=timeout)
    out2 = pm3(["hf", "search"], timeout=timeout)
    tags = parse_pm3_tags(out.text) + parse_pm3_tags(out2.text)
    return {"tags": tags, "raw": out.text + out2.text}


def read_lf(fmt: str = "em4100", timeout: int = 90) -> proc.Result:
    """Read a low-frequency credential of a given family (``HID_FORMATS``)."""
    if fmt not in HID_FORMATS:
        raise ValueError(f"unknown LF format {fmt!r}; have: "
                         f"{', '.join(HID_FORMATS)}")
    return pm3(HID_FORMATS[fmt], timeout=timeout)


def read_hf(timeout: int = 90) -> proc.Result:
    """HF identification (Mifare / DESFire / iCLASS)."""
    return pm3(["hf", "search"], timeout=timeout)


def dump_mifare(outdir: str | None = None, timeout: int = 600) -> dict:
    """Dump a Mifare Classic card: mfoc first (nested), mfcuk as fallback."""
    outdir = outdir or config.output_dir("radio/rfid")
    dump = os.path.join(outdir, "mifare.mfd")
    tool = "mfoc" if proc.has("mfoc") else ("mfcuk" if proc.has("mfcuk")
                                            else None)
    if tool is None:
        raise proc.ToolMissing("need mfoc or mfcuk — "
                               + proc.install_hint("mfoc"))
    if tool == "mfoc":
        res = proc.run(["mfoc", "-P", "500", "-O", dump], timeout=timeout)
    else:
        res = proc.run(["mfcuk", "-R", "0:A0A1A2A3A4A5", "-O", dump],
                       timeout=timeout)
    ok = res.ok and os.path.exists(dump)
    return {"ok": ok, "dump": dump if ok else None, "tool": tool,
            "tail": res.lines()[-5:]}


def nfc_list() -> list[dict]:
    """Poll a PN532/libnfc reader for one tag."""
    proc.require("nfc-list", "apt install libnfc-bin")
    res = proc.run(["nfc-list"], timeout=30)
    return parse_nfc_list(res.out)


def parse_nfc_list(text: str) -> list[dict]:
    """Parse ``nfc-list`` output; the UID sits on the line after the device."""
    tags: list[dict] = []
    for line in text.splitlines():
        m = re.match(r"\s*NFC device:\s*(.+)", line)
        if m:
            tags.append({"uid": "", "description": m.group(1).strip()})
            continue
        u = re.search(r"UID \(\d+ bytes\):\s*([0-9a-zA-Z ]+)", line)
        if u and tags:
            tags[-1]["uid"] = u.group(1).strip().upper()
    return tags
