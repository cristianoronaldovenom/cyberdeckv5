"""Vehicle RKE profile database and frequency lookup.

Each profile carries the carrier, the modem preset, the rolling-code protocol
family and whether the OEM remote uses a fixed code (replayable) or a hopping
code (needs a counter prediction / manufacturer key).

Profiles are grouped by brand so ``car.profiles BRAND`` gives the whole set.
The data is deliberately practical: it is what you tune to, not marketing copy.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Profile", "PROFILES", "brands", "by_brand", "get", "search",
           "for_frequency", "FREQUENCIES"]


@dataclass(frozen=True)
class Profile:
    brand: str
    model: str
    freq: int                  # carrier in Hz
    preset: str                # CC1101/flipper modem preset
    protocol: str              # keeloq | princeton | came | nice_flo | holtek
    coding: str                # hopping | fixed | ble
    buttons: tuple[str, ...] = ()
    region: str = "eu"
    note: str = ""

    @property
    def label(self) -> str:
        return f"{self.brand} {self.model}".strip()

    def to_row(self) -> dict:
        return {"brand": self.brand, "model": self.model,
                "freq": self.freq, "preset": self.preset,
                "protocol": self.protocol, "coding": self.coding,
                "buttons": ",".join(self.buttons), "region": self.region,
                "note": self.note}


def _p(brand, model, freq, preset, protocol, coding, buttons=(), region="eu",
       note=""):
    return Profile(brand, model, freq, preset, protocol, coding, tuple(buttons),
                   region, note)


#: carrier families actually used by OEM remotes
FREQUENCIES = {"us": 315_000_000, "eu": 433_920_000, "eu_alt": 434_420_000,
               "eu_wide": 868_350_000}
F_315 = FREQUENCIES["us"]
F_433 = FREQUENCIES["eu"]
F_434 = FREQUENCIES["eu_alt"]
F_868 = FREQUENCIES["eu_wide"]


#: every profile, grouped by brand
PROFILES: list[Profile] = [
    # --- German OEMs (KeeLoq hopping on 433/434; late models 868) ----------
    _p("Audi", "A3/A4/A6 (older)", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk", "panic"), note="HCS301-derived, 433.92"),
    _p("Audi", "A4/A6 (B8+)", F_434, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk"), note="434.42 variant of the above"),
    _p("BMW", "3/5 series (E46-E90)", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk", "panic"), note="HCS361, 433.92"),
    _p("BMW", "CAS4 / F-series", F_868, "FM476", "keeloq", "hopping",
       ("lock", "unlock", "trunk"), note="868 MHz, some models 315/433 US"),
    _p("Mercedes", "C/E class (W203-W211)", F_433, "AM650", "keeloq",
       "hopping", ("lock", "unlock", "trunk"), note="HCS361 rolling code"),
    _p("Mercedes", "W212+ / keyless", F_433, "FM476", "keeloq", "hopping",
       ("lock", "unlock", "trunk"), note="FSK variant, needs clock recovery"),
    _p("Volkswagen", "Golf IV/V, Passat B5", F_433, "AM650", "keeloq",
       "hopping", ("lock", "unlock", "trunk"), note="HCS301"),
    _p("Volkswagen", "MQB platform (Golf VII+)", F_433, "FM476", "keeloq",
       "hopping", ("lock", "unlock", "trunk"), note="FSK, 433.92"),
    _p("Porsche", "911 / Cayenne (996-997)", F_433, "AM650", "keeloq",
       "hopping", ("lock", "unlock", "trunk"), note="HCS361"),
    _p("Opel", "Astra H / Corsa D", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk")),
    _p("Skoda", "Octavia II / Fabia", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk")),
    # --- French / Italian ---------------------------------------------------
    _p("Renault", "Clio III / Megane II", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk"), note="VAC102 handshake on some keys"),
    _p("Peugeot", "206/307/407", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk")),
    _p("Citroen", "C3/C4/C5", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock")),
    _p("Fiat", "Punto / Stilo", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk")),
    _p("Alfa Romeo", "147/156/159", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk")),
    # --- US OEMs: mostly 315 MHz fixed/hopping ------------------------------
    _p("Ford", "Focus / Fiesta (pre-2011)", F_315, "AM650", "keeloq",
       "hopping", ("lock", "unlock", "trunk", "panic"), region="us"),
    _p("Ford", "Explorer / F-150 (older)", F_315, "AM650", "princeton",
       "fixed", ("lock", "unlock", "panic"), region="us",
       note="PT2262 clone remotes are common"),
    _p("Chevrolet", "Silverado / Malibu (older)", F_315, "AM650", "keeloq",
       "hopping", ("lock", "unlock", "trunk"), region="us"),
    _p("Dodge", "Ram / Charger (older)", F_315, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "panic"), region="us"),
    _p("Jeep", "Wrangler JK", F_315, "AM650", "keeloq", "hopping",
       ("lock", "unlock"), region="us"),
    _p("Toyota", "Corolla / Camry (older)", F_315, "AM650", "keeloq",
       "hopping", ("lock", "unlock", "trunk"), region="us"),
    _p("Honda", "Civic / Accord (older)", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk")),
    _p("Nissan", "Micra / Almera", F_433, "AM650", "keeloq", "hopping",
       ("lock", "unlock", "trunk")),
    # --- gates, garages, aftermarket ---------------------------------------
    _p("Came", "gate remotes (TOP/TO.P)", F_433, "AM650", "came", "fixed",
       ("open", "stop"), note="12/18-bit fixed code, trivially clonable"),
    _p("Nice", "FLO / One gate remotes", F_433, "AM650", "nice_flo", "fixed",
       ("open", "stop"), note="12-bit OOK"),
    _p("Generic", "PT2262 / EV1527 clone", F_433, "AM650", "princeton",
       "fixed", ("a", "b", "c", "d"), note="aftermarket fobs, brute-forceable"),
    _p("Generic", "Holtek HT6P20", F_433, "AM650", "holtek", "fixed",
       ("a", "b"), note="24-bit, avoid touch-to-clone counters"),
    _p("Tesla", "Model 3/Y", F_433, "FM476", "ble", "ble",
       ("lock", "unlock", "trunk"), note="BLE primary; 433 with relay"),
]


def brands() -> list[str]:
    return sorted({p.brand for p in PROFILES})


def by_brand(brand: str) -> list[Profile]:
    needle = brand.lower()
    return [p for p in PROFILES if p.brand.lower() == needle]


def get(brand: str) -> Profile | None:
    hits = by_brand(brand)
    return hits[0] if hits else None


def search(query: str) -> list[Profile]:
    q = query.lower()
    return [p for p in PROFILES
            if q in p.brand.lower() or q in p.model.lower()
            or q in p.protocol.lower() or q in p.note.lower()]


def for_frequency(freq: int) -> list[Profile]:
    """Profiles within 1 MHz of ``freq`` (what a captured signal could be)."""
    return [p for p in PROFILES if abs(p.freq - int(freq)) <= 1_000_000]

