"""RFID/NFC/IR/Bluetooth modules."""

from __future__ import annotations

from omni.core import console
from omni.core.module import Option
from omni.radio import bluetooth, ir, rfid
from omni.radio.modules._base import RadioModule


class RfidSearch(RadioModule):
    NAME = "radio.rfidsearch"
    DESCRIPTION = "Proxmark3 LF+HF tag search with UID/protocol extraction"
    NEEDS = ("pm3",)
    OPTIONS = (Option("TIMEOUT", "per-search timeout", "60"),)

    def execute(self) -> dict:
        out = rfid.search(self.get_int("TIMEOUT", 60))
        console.table(["uid", "protocol"],
                      [[t["uid"], t["protocol"]] for t in out["tags"]])
        return out["tags"]


class RfidRead(RadioModule):
    NAME = "radio.rfidread"
    DESCRIPTION = "Read a low-frequency credential family (EM4100, HID, Indala…)"
    NEEDS = ("pm3",)
    OPTIONS = (Option("FORMAT", "credential family", "em4100",
                      choices=tuple(sorted(rfid.HID_FORMATS))),
               Option("TIMEOUT", "command timeout", "90"))

    def execute(self) -> dict:
        res = rfid.read_lf(self.get("FORMAT"), self.get_int("TIMEOUT", 90))
        tags = rfid.parse_pm3_tags(res.text)
        for tag in tags:
            console.ok(f"{tag['protocol']} {tag['uid']}")
        if not tags:
            for line in res.lines()[-8:]:
                console.info(line)
        return {"format": self.get("FORMAT"), "tags": tags, "ok": res.ok}


class Mifare(RadioModule):
    NAME = "radio.mifare"
    DESCRIPTION = "Dump a Mifare Classic card (mfoc nested / mfcuk fallback)"
    OPTIONS = (Option("TIMEOUT", "dump timeout", "600"),)

    def execute(self) -> dict:
        out = rfid.dump_mifare(timeout=self.get_int("TIMEOUT", 600))
        if out["ok"]:
            console.ok(f"dump saved: {out['dump']}")
        else:
            console.warn("dump failed — " + " / ".join(out["tail"]))
        return out


class Nfc(RadioModule):
    NAME = "radio.nfc"
    DESCRIPTION = "Poll a PN532/libnfc reader for nearby tags"
    NEEDS = ("nfc-list",)

    def execute(self) -> list[dict]:
        tags = rfid.nfc_list()
        console.table(["uid", "description"],
                      [[t["uid"], t["description"]] for t in tags])
        return tags


class IrCapture(RadioModule):
    NAME = "radio.ir"
    DESCRIPTION = "Capture raw IR timings and write an ir-ctl answer file"
    NEEDS = ("mode2",)
    OPTIONS = (Option("SECONDS", "capture window", "10"),)

    def execute(self) -> dict:
        out = ir.capture(self.get_int("SECONDS", 10))
        if out["file"]:
            console.ok(f"{out['pairs']} edges -> {out['file']}")
        else:
            console.warn("nothing captured")
        return out


class IrSend(RadioModule):
    NAME = "radio.irsend"
    DESCRIPTION = "Replay an ir-ctl answer file at a carrier frequency"
    NEEDS = ("ir-ctl",)
    OPTIONS = (Option("FILE", "answer file", "", required=True),
               Option("CARRIER", "carrier Hz", "38000"))

    def execute(self) -> dict:
        res = ir.send_default(self.get("FILE"), self.get_int("CARRIER", 38000))
        console.ok("sent") if res.ok else console.warn(res.text[:200])
        return {"ok": res.ok, "file": self.get("FILE")}


class Bt(RadioModule):
    NAME = "radio.bluetooth"
    DESCRIPTION = "Bluetooth recon: adapters, classic inquiry, BLE scan"
    NEEDS = ("hciconfig",)
    OPTIONS = (Option("MODE", "adapters|inquiry|ble", "adapters",
                      choices=("adapters", "inquiry", "ble")),
               Option("SECONDS", "scan window", "12"))

    def execute(self) -> list[dict]:
        mode = self.get("MODE")
        if mode == "inquiry":
            rows = bluetooth.inquiry(self.get_int("SECONDS", 12))
        elif mode == "ble":
            rows = bluetooth.ble_scan(self.get_int("SECONDS", 12))
        else:
            rows = bluetooth.adapters()
        console.table(["address", "name/state"],
                      [[r.get("address", ""), r.get("name") or r.get("state", "")]
                       for r in rows])
        return rows


class BtRssi(RadioModule):
    NAME = "radio.btrssi"
    DESCRIPTION = "RSSI of a connected BT device + rough distance"
    NEEDS = ("hcitool",)
    OPTIONS = (Option("ADDRESS", "device MAC", "", required=True),
               Option("DEV", "local adapter", "hci0"))

    def execute(self) -> dict:
        out = bluetooth.rssi(self.get("ADDRESS"), self.get("DEV"))
        console.kv([("rssi", out["rssi"]), ("approx m", out["approx_metres"])])
        return out
