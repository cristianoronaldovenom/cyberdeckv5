"""Radio hardware capability probe.

OMNI treats every radio as optional. This module answers "what can this box
actually do right now" so the rest of the elite modules can pick a backend
instead of failing at call time.

Nothing here needs root: probes are ``--help``/``lsusb``/sysfs based.
"""

from __future__ import annotations

import os
import re

from omni.core import config, proc

__all__ = ["probe", "summary", "pick_sdr", "usb_devices", "HARDWARE"]

#: device-class -> (binary candidates, expected lsusb substring)
HARDWARE: dict[str, tuple[tuple[str, ...], str]] = {
    "cc1101": ((), "cc1101"),
    "hackrf": (("hackrf_info",), "hackrf"),
    "rtlsdr": (("rtl_test", "rtl_sdr"), "realtek"),
    "proxmark3": (("pm3", "proxmark3"), "proxmark"),
    "pn532": (("nfc-list",), "pn532"),
    "flipper": (("flipper", "ufbt"), "flipper"),
    "gps": (("gpspipe",), "gps"),
    "bluetooth": (("hciconfig", "bluetoothctl"), "bluetooth"),
    "airspy": (("airspy_info",), "airspy"),
    "plutosdr": (("iio_info",), "pluto"),
    "limesdr": (("lime", "LimeSuite"), "lime"),
}

_SDR_BINARIES = ("hackrf_transfer", "rtl_sdr", "airspy_rx", "lime",
                 "SoapySDRUtil")


def usb_devices() -> list[str]:
    """Raw ``lsusb`` lines (empty when lsusb is absent)."""
    if not proc.has("lsusb"):
        return []
    return proc.run(["lsusb"], timeout=15).lines()


def probe() -> dict:
    """Report per-device readiness: binaries present + USB match + notes."""
    usb = [ln.lower() for ln in usb_devices()]
    cc1101 = os.path.exists("/dev/spidev0.0") or os.path.exists("/dev/spidev0.1")
    out: dict[str, dict] = {}
    for kind, (bins, usb_hint) in HARDWARE.items():
        found_bin = [b for b in bins if proc.has(b)]
        present_usb = any(usb_hint in ln for ln in usb)
        if kind == "cc1101":
            ready = found_bin or cc1101
            note = "spidev present" if cc1101 else "no /dev/spidev*"
        else:
            ready = bool(found_bin) or present_usb
            note = ("usb device seen" if present_usb else
                    "tools ok" if found_bin else "not detected")
        out[kind] = {"binaries": found_bin, "usb": present_usb,
                     "ready": ready, "note": note}
    return out


def summary() -> list[dict]:
    """Flatten :func:`probe` into table rows."""
    return [{"device": k, "ready": v["ready"],
             "binaries": ",".join(v["binaries"]) or "-",
             "note": v["note"]} for k, v in probe().items()]


def available() -> list[str]:
    return [k for k, v in probe().items() if v["ready"]]


def pick_sdr() -> str | None:
    """Choose an SDR TX/RX backend: config override, then real presence."""
    configured = config.get_value("radio.sdr_binary")
    if configured and proc.has(str(configured)):
        return str(configured)
    for binary in _SDR_BINARIES:
        if proc.has(binary):
            return binary
    return None


def band_table() -> list[dict]:
    """Named ISM/utility bands used by the spectrum and RF modules."""
    from omni.radio.spectrum import BANDS
    return [{"name": k, "low": v[0], "high": v[1], "label": v[2]}
            for k, v in BANDS.items()]


def parse_hexdump(text: str) -> str:
    """Join ``rtl_433 -a`` style hexdump lines into one hex string."""
    chunks = re.findall(r"^(?:[0-9a-fA-F]{2}\s+)+", text, re.MULTILINE)
    return "".join(re.sub(r"[^0-9a-fA-F]", "", c) for c in chunks)
