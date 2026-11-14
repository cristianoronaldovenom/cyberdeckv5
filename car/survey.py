"""Multi-band fob survey: plan where to listen, then score what was heard.

An OEM remote is a needle in three bands, and a driveway is full of other
needles — tyre sensors on 315, weather stations on 433.92, doorbells on 868.
Rather than guess a carrier and hope, this plans a real sweep (which carriers,
how long on each), turns whatever the decoder found into a ``.sub`` the rest of
the car trade understands, and ranks the hits so the *fob press* is what gets
attacked instead of the neighbour's thermostat.

The planning and ranking are pure functions, which is what makes them testable
without a radio.
"""

from __future__ import annotations

from omni.rf.subfile import SubFile

__all__ = ["BANDS", "band_frequencies", "hop_plan", "sub_from_press", "score",
           "rank", "rows", "MIN_BITS"]

#: carriers RKE remotes actually use, by region
BANDS = {"us": 315_000_000, "eu": 433_920_000, "eu_alt": 434_420_000,
         "wide": 868_350_000}

#: the order a survey walks the bands (shortest range first, so 315 is caught
#: before a 433 press is missed)
ORDER = ("us", "eu", "eu_alt", "wide")

#: below this a decode is a thermostat, not a remote
MIN_BITS = 12


def band_frequencies(region: str = "all") -> list[int]:
    """Carriers to sweep for ``region``.

    Accepts a band name (``us``/``eu``/``eu_alt``/``wide``/``all``) or an
    explicit list in MHz — ``"433.92,868.35"`` — which is what a regional
    variant outside the table needs.
    """
    key = (region or "all").strip().lower()
    if key in ("all", ""):
        return [BANDS[name] for name in ORDER]
    if key in BANDS:
        return [BANDS[key]]
    out: list[int] = []
    for chunk in key.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            value = float(chunk)
        except ValueError:
            raise ValueError(f"unknown region {region!r} — use one of "
                             f"{', '.join(ORDER)}/all or MHz values") from None
        # anything below 1000 is MHz, above is already Hz
        out.append(int(value * 1_000_000) if value < 1000 else int(value))
    if not out:
        raise ValueError(f"unknown region {region!r}")
    return out


def hop_plan(freqs: list[int], seconds: float,
             dwell_ms: int = 250) -> list[tuple[int, float]]:
    """``(frequency, dwell_seconds)`` slots covering ``seconds`` of air.

    The last slot is clipped so the plan never overruns the requested window —
    a survey that quietly runs a minute long is worse than one that ends early.
    """
    carriers = [int(f) for f in freqs if f]
    if not carriers:
        raise ValueError("no carrier to hop — give a region or a frequency")
    total = max(0.1, float(seconds))
    dwell = max(0.05, int(dwell_ms) / 1000.0)
    plan: list[tuple[int, float]] = []
    spent = 0.0
    index = 0
    while spent < total - 1e-9:
        slot = min(dwell, total - spent)
        plan.append((carriers[index % len(carriers)], round(slot, 3)))
        spent += slot
        index += 1
    return plan


def sub_from_press(result, frequency: int, preset: str = "AM650",
                   guard: int = 30) -> SubFile | None:
    """A captured decode as a ``.sub`` (``None`` when it is too short).

    This is the same conversion ``car.unlock`` does inline; keeping it here
    means the survey, the unlock chain and the tests all agree on the frame.
    """
    if result is None:
        return None
    bits = int(getattr(result, "data_count_bit", 0) or 0)
    if bits < MIN_BITS:
        return None
    sub = SubFile()
    sub.protocol = getattr(result, "protocol_name", "") or "RAW"
    sub.bit = bits
    sub.te = int(getattr(result, "te", 0) or 400)
    sub.frequency = int(frequency)
    sub.preset_name = preset
    sub.key = int(getattr(result, "data", 0) or 0)
    sub.guard_time = guard
    return sub


def score(report: dict) -> int:
    """How promising a decoded press is, 0-120.

    A recoverable manufacturer key is worth everything, a decodable button
    second, and a raw capture almost nothing — but not nothing, because a
    fixed-code gate remote replays fine as raw.
    """
    if report.get("manufacturer"):
        total = 100
    elif report.get("button") is not None:
        total = 50
    elif report.get("protocol") and not report.get("raw"):
        total = 30
    else:
        total = 10
    if report.get("counter") is not None:
        total += 10
    if str(report.get("verdict", "")).startswith("fixed"):
        total += 5
    return total


def rank(reports: list[dict]) -> list[dict]:
    """Reports best-first; each gets a ``score`` when it has none."""
    scored = []
    for report in reports:
        row = dict(report)
        row.setdefault("score", score(report))
        scored.append(row)
    return sorted(scored, key=lambda row: (-row["score"],
                                           row.get("frequency", 0)))


def rows(reports: list[dict], limit: int = 20) -> list[list[str]]:
    """Table rows for the console (freq / protocol / verdict / score)."""
    out = []
    for report in reports[:max(1, limit)]:
        freq = int(report.get("frequency") or 0)
        out.append([f"{freq / 1e6:.3f}" if freq else "?",
                    str(report.get("protocol", ""))[:12],
                    str(report.get("verdict", ""))[:44],
                    str(report.get("score", 0))])
    return out
