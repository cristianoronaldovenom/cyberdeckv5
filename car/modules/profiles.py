"""Vehicle profile lookup: brands, model frequencies, presets."""

from __future__ import annotations

from omni.car import vehicles
from omni.core import console
from omni.core.module import Option
from omni.car.modules._base import CarModule

__all__ = ["Brands", "Profiles", "Identify"]


class Brands(CarModule):
    NAME = "car.brands"
    DESCRIPTION = "List supported vehicle and gate brands with profile counts"

    def execute(self) -> list[dict]:
        rows = [{"brand": b, "profiles": len(vehicles.by_brand(b))}
                for b in vehicles.brands()]
        console.table(["brand", "profiles"],
                      [[r["brand"], str(r["profiles"])] for r in rows])
        return rows


class Profiles(CarModule):
    NAME = "car.profiles"
    DESCRIPTION = "Show carriers, presets and coding for a brand or search term"
    OPTIONS = (Option("BRAND", "brand or search term (blank = everything)"),)

    def execute(self) -> list[dict]:
        query = self.get("BRAND")
        hits = vehicles.by_brand(query) or vehicles.search(query) if query \
            else list(vehicles.PROFILES)
        if not hits:
            console.warn(f"no profile matches {query!r}")
            return []
        console.table(["brand", "model", "MHz", "preset", "protocol", "coding"],
                      [[p.brand, p.model, f"{p.freq / 1e6:.2f}", p.preset,
                        p.protocol, p.coding] for p in hits])
        for profile in hits:
            if profile.note:
                console.debug(f"{profile.label}: {profile.note}")
        return [p.to_row() for p in hits]


class Identify(CarModule):
    NAME = "car.identify"
    DESCRIPTION = "Guess which vehicles/gates a captured carrier belongs to"
    OPTIONS = (Option("FREQ", "captured frequency in Hz", "", required=True),)

    def execute(self) -> dict:
        out = vehicles.for_frequency(self.get_int("FREQ"))
        if not out:
            console.warn("no profile uses that frequency (±1 MHz)")
        else:
            console.table(["brand", "model", "MHz", "coding"],
                          [[p.brand, p.model, f"{p.freq / 1e6:.2f}", p.coding]
                           for p in out])
        return {"freq": self.get_int("FREQ"),
                "candidates": [p.to_row() for p in out]}
