"""SDR backends: wideband spectrum sweep with rtl_power, rtl_433 sensors."""

from __future__ import annotations

import csv
import io
import os

from omni.core import config, proc

__all__ = ["BANDS", "band", "sweep", "parse_rtl_power", "peaks", "sensors",
           "parse_rtl433_json", "sensor_lines"]

#: name -> (low Hz, high Hz, human label)
BANDS = {
    "ism315": (300_000_000, 320_000_000, "315 MHz remotes / car fobs"),
    "ism433": (430_000_000, 440_000_000, "EU ISM: fobs, weather, TPMS"),
    "ism868": (863_000_000, 870_000_000, "EU ISM: sensors, alarms"),
    "ism915": (902_000_000, 928_000_000, "US ISM: sensors, meters"),
    "pager": (137_000_000, 174_000_000, "VHF pager / utility"),
    "air": (118_000_000, 137_000_000, "airband AM"),
    "marine": (156_000_000, 163_000_000, "marine VHF"),
    "pmr": (446_000_000, 447_000_000, "PMR446 handhelds"),
    "ism2400": (2_400_000_000, 2_483_500_000, "2.4 GHz WiFi/BLE/Zigbee"),
    "gps": (1_574_000_000, 1_576_000_000, "GPS L1"),
}


def band(name: str) -> tuple[int, int]:
    if name not in BANDS:
        raise ValueError(f"unknown band {name!r}; have: {', '.join(BANDS)}")
    low, high, _ = BANDS[name]
    return low, high


def parse_rtl_power(text: str) -> list[dict]:
    """Parse rtl_power CSV: ``date,time,low,high,step,samples,db...``."""
    rows: list[dict] = []
    for line in text.splitlines():
        cells = next(csv.reader(io.StringIO(line)), [])
        if len(cells) < 7:
            continue
        try:
            low = float(cells[2])
            step = float(cells[4])
        except ValueError:
            continue
        for i, val in enumerate(cells[6:]):
            try:
                db = float(val)
            except ValueError:
                continue
            rows.append({"hz": int(low + i * step), "db": db})
    return rows


def peaks(rows: list[dict], count: int = 10, floor: float = -60.0) -> list[dict]:
    """Strongest bins above ``floor``, deduped to 25 kHz spacing."""
    strong = sorted((r for r in rows if r["db"] >= floor),
                    key=lambda r: -r["db"])
    out: list[dict] = []
    for row in strong:
        if all(abs(row["hz"] - o["hz"]) > 25_000 for o in out):
            out.append(dict(row, mhz=round(row["hz"] / 1e6, 3)))
            if len(out) >= count:
                break
    return out


def sweep(band_name: str = "ism433", seconds: int | None = None,
          gain: int | None = None) -> list[dict]:
    """Run rtl_power across a band and return parsed bins."""
    binary = str(config.get_value("radio.rtl_power", "rtl_power"))
    proc.require(binary, "apt install rtl-sdr")
    low, high = band(band_name)
    seconds = int(seconds or config.get_value("radio.sweep_sample_seconds", 60))
    gain = int(gain if gain is not None else config.get_value(
        "radio.sweep_gain", 40))
    step = max(1000, (high - low) // 2000)
    outdir = config.output_dir("radio/sweeps")
    out = os.path.join(outdir, f"sweep_{band_name}.csv")
    argv = [binary, "-f", f"{low}:{high}:{step}", "-g", str(gain),
            "-i", "1", "-1", out]
    res = proc.run(argv, timeout=max(30, seconds + 30))
    if not res.ok and not os.path.exists(out):
        raise RuntimeError(f"rtl_power failed: {res.text[:300]}")
    with open(out, "r", encoding="utf-8", errors="replace") as fh:
        return parse_rtl_power(fh.read())


def parse_rtl433_json(text: str) -> list[dict]:
    """Parse rtl_433 JSON lines into plain dicts (ignores junk lines)."""
    import json
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append({"model": obj.get("model", "?"),
                    "id": str(obj.get("id", "")),
                    "freq": obj.get("freq"),
                    "rssi": obj.get("rssi"),
                    "channel": obj.get("channel"),
                    "raw": obj})
    return out


def sensors(seconds: int = 30, freq: str | None = None,
            min_rssi: float | None = None) -> list[dict]:
    """Listen for ISM sensor traffic with rtl_433 (weather, TPMS, meters)."""
    binary = str(config.get_value("radio.rtl433", "rtl_433"))
    proc.require(binary, "apt install rtl-433")
    argv = [binary, "-F", "json"]
    if freq:
        argv += ["-f", str(freq)]
    if min_rssi is not None:
        argv += ["-Y", f"min_rssi={min_rssi}"]
    res = proc.run(argv, timeout=max(15, int(seconds) + 15))
    return parse_rtl433_json(res.out)


def sensor_lines(found: list[dict], limit: int = 20) -> list[str]:
    return [f"{f['model']} id={f['id']} ch={f['channel']} "
            f"rssi={f['rssi']} @{f['freq']}" for f in found[:limit]]
