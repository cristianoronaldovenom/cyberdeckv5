"""Radio modules: capability matrix and spectrum/sensor work."""

from __future__ import annotations

import os
import time

from omni.core import config, console, proc
from omni.core.module import Option
from omni.radio import capability, spectrum
from omni.radio.modules._base import RadioModule


class Hardware(RadioModule):
    NAME = "radio.hardware"
    DESCRIPTION = "Probe attached radios and report what this box can do"

    def execute(self) -> dict:
        probed = capability.probe()
        console.table(["device", "ready", "binaries", "note"],
                      [[r["device"], str(r["ready"]), r["binaries"], r["note"]]
                       for r in capability.summary()])
        ready = [k for k, v in probed.items() if v["ready"]]
        if ready:
            console.ok("usable: " + ", ".join(ready))
        else:
            console.warn("no radio hardware detected — modules will fall back")
        return probed


class Sweep(RadioModule):
    NAME = "radio.sweep"
    DESCRIPTION = "Wideband spectrum sweep (rtl_power) with peak ranking"
    NEEDS = ("rtl_power",)
    OPTIONS = (Option("BAND", "band name (see radio.bands)", "ism433"),
               Option("SECONDS", "integration time", "60"),
               Option("GAIN", "tuner gain", "40"),
               Option("TOP", "peaks to report", "10"),
               Option("FLOOR", "ignore bins below this dB", "-60"))

    def execute(self) -> list[dict]:
        rows = spectrum.sweep(self.get("BAND"), self.get_int("SECONDS", 60),
                              self.get_int("GAIN", 40))
        tops = spectrum.peaks(rows, self.get_int("TOP", 10),
                              float(self.get("FLOOR") or -60))
        console.table(["MHz", "dB"], [[f"{p['mhz']:.3f}", f"{p['db']:.1f}"]
                                      for p in tops])
        return tops


class Bands(RadioModule):
    NAME = "radio.bands"
    DESCRIPTION = "List named frequency bands used by the toolkit"

    def execute(self) -> list[dict]:
        rows = capability.band_table()
        console.table(["name", "low MHz", "high MHz", "label"],
                      [[r["name"], f"{r['low'] / 1e6:.3f}",
                        f"{r['high'] / 1e6:.3f}", r["label"]] for r in rows])
        return rows


class Sensors(RadioModule):
    NAME = "radio.sensors"
    DESCRIPTION = "Decode ISM sensor traffic: weather, TPMS, meters (rtl_433)"
    NEEDS = ("rtl_433",)
    OPTIONS = (Option("SECONDS", "listen time", "30"),
               Option("FREQ", "frequency in Hz (blank = rtl_433 hop)"),
               Option("MIN_RSSI", "minimum RSSI filter (dB)"))

    def execute(self) -> list[dict]:
        found = spectrum.sensors(self.get_int("SECONDS", 30),
                                 self.get("FREQ") or None,
                                 float(self.get("MIN_RSSI"))
                                 if self.get("MIN_RSSI") else None)
        for line in spectrum.sensor_lines(found):
            console.info(line)
        return found


class Captures(RadioModule):
    NAME = "radio.captures"
    DESCRIPTION = "Capture raw OOK/FSK from an RTL-SDR into IQ/AM files"
    NEEDS = ("rtl_fm",)
    OPTIONS = (Option("FREQ", "centre frequency in Hz", "433920000",
                      required=True),
               Option("SECONDS", "capture length", "10"),
               Option("OUT", "output wav (blank = loot dir)"))

    def execute(self) -> dict:
        out = self.get("OUT") or os.path.join(
            config.output_dir("radio/iq"),
            f"cap_{self.get('FREQ')}_{int(time.time())}.wav")
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        argv = ["rtl_fm", "-f", self.get("FREQ"), "-M", "am", "-s", "200000",
                "-r", "48k", out]
        res = proc.run(argv, timeout=self.get_int("SECONDS", 10) + 15)
        if os.path.exists(out):
            console.ok(f"wrote {out}")
        else:
            console.warn(res.text[:200])
        return {"file": out if os.path.exists(out) else None}

