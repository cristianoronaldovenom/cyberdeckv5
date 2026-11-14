"""Marquee injection: re-encode captured frames into one tight, timed train.

Blind RAW replay re-transmits whatever the antenna heard, jitter included, one
frame at a time, with the operator (or a loop) fumbling the gaps. A receiver
that wants a specific frame out of that stream has plenty of slack to reject
ours. A *marquee* fixes all three problems:

* frames are **re-synthesized** from their protocol fields, so the timing is
  exact instead of whatever the capture picked up;
* the whole train is **pre-built**, so the gap between frames is a constant we
  choose instead of process latency;
* every frame is sent **N times back-to-back** (the marquee burst) so at least
  one copy lands inside the receiver's sync window.

Timing model: a frame's own trailing guard (``TE * GuardTime``) is part of the
protocol and is kept verbatim. ``gap_ms`` is the *extra* dead air inserted
after a burst — cut it to nothing for maximum pressure, raise it for weak or
long-range links.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass

from omni.rf import keeloq_crypto as kq
from omni.rf.protocols import (CameEncoder, HoltekEncoder, NiceFloEncoder,
                               PrincetonEncoder, build_keeloq_upload)
from omni.rf.subfile import SubFile, levels_to_raw_durations

__all__ = [
    "Frame", "Slot", "PROTOCOLS", "ORDERS", "GAP_MAX_MS",
    "frames_from_sub", "frame_from_spec", "load_frames", "save_frames",
    "load_frames_file", "plan", "timing", "to_sub", "describe", "clamp_gap",
    "check_headroom",
]

#: protocol -> (encoder class, default bits, default TE)
PROTOCOLS = {
    "Princeton": (PrincetonEncoder, 24, 390),
    "CAME": (CameEncoder, 12, 320),
    "Nice FLO": (NiceFloEncoder, 12, 500),
    "Holtek": (HoltekEncoder, 40, 600),
}

#: orderings applied to a capture set before firing
ORDERS = ("head-first", "tail-first", "capture")

#: hard ceiling for the inter-burst dead air
GAP_MAX_MS = 2000

_DEFAULT_GUARD = 30


def clamp_gap(ms: int | float) -> int:
    """Clamp a gap into 0..GAP_MAX_MS ms."""
    try:
        value = int(ms)
    except (TypeError, ValueError):
        return 0
    return max(0, min(GAP_MAX_MS, value))


@dataclass
class Frame:
    """One frame, fully described by its protocol fields."""

    protocol: str
    data: int
    bits: int
    te: int = 390
    guard: int = _DEFAULT_GUARD
    frequency: int = 433_920_000
    preset: str = "AM650"
    source: str = ""

    def __post_init__(self) -> None:
        if self.protocol != "KeeLoq" and self.protocol not in PROTOCOLS:
            raise ValueError(f"unsupported protocol {self.protocol!r} — "
                             f"known: {', '.join(sorted(PROTOCOLS))}, KeeLoq")
        self.bits = int(self.bits)
        self.data = int(self.data)
        if self.protocol != "KeeLoq" and not 1 <= self.bits <= 64:
            raise ValueError(f"bit length {self.bits} out of range 1..64")
        if self.protocol != "KeeLoq" and self.data >= (1 << self.bits):
            raise ValueError(f"0x{self.data:X} does not fit in {self.bits} bit")
        default_te = PROTOCOLS.get(self.protocol, (None, 0, 400))[2]
        self.te = max(100, int(self.te or default_te or 400))
        self.guard = max(1, int(self.guard or _DEFAULT_GUARD))

    # -- shaping ---------------------------------------------------------
    def levels(self) -> list[tuple[bool, int]]:
        """Synthesized level train (exact timing, protocol-correct)."""
        if self.protocol == "KeeLoq":
            fix, hop = kq.split_frame(self.data)
            return build_keeloq_upload(fix, hop, self.te, self.guard)
        encoder_cls = PROTOCOLS[self.protocol][0]
        encoder = encoder_cls(data=self.data, data_count_bit=self.bits,
                              te=self.te, guard_time=self.guard)
        return encoder.build_upload()

    def frame_ms(self) -> float:
        """On-air length including the trailing guard."""
        return sum(d for _lvl, d in self.levels()) / 1000.0

    def label(self) -> str:
        width = max(1, (self.bits + 3) // 4)
        return f"{self.protocol} 0x{self.data:0{width}X} ({self.bits}b)"

    def fields(self) -> dict:
        return {"protocol": self.protocol, "bit": self.bits, "key": self.data,
                "te": self.te, "guard": self.guard,
                "frequency": self.frequency, "preset": self.preset}


@dataclass
class Slot:
    """One planned transmission (a frame plus which copy of it this is)."""

    frame: Frame
    copy: int = 1
    position: int = 0


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------

def frames_from_sub(sub: SubFile, source: str = "") -> list[Frame]:
    """Extract every decodable frame from a .sub (RAW files yield nothing)."""
    if sub.is_raw:
        return []
    bits = int(sub.bit or 0)
    if sub.protocol == "KeeLoq":
        bits = 64
    return [Frame(protocol=sub.protocol, data=int(sub.key), bits=bits,
                  te=int(sub.te or 0),
                  guard=int(sub.guard_time or _DEFAULT_GUARD),
                  frequency=int(sub.frequency), preset=sub.preset_short(),
                  source=source)]


def frame_from_spec(spec: str) -> Frame:
    """Parse ``PROTOCOL:BITS:HEX[:FREQ[:TE[:GUARD]]]`` into a Frame."""
    parts = spec.split(":")
    if len(parts) < 3:
        raise ValueError(f"bad frame spec {spec!r} — "
                         "want PROTOCOL:BITS:HEX[:FREQ[:TE[:GUARD]]]")
    protocol, bits, hexdata = parts[0], parts[1], parts[2]
    if protocol not in PROTOCOLS and protocol != "KeeLoq":
        raise ValueError(f"unknown protocol {protocol!r}")
    return Frame(protocol=protocol,
                 data=int((hexdata.replace(" ", "") or "0"), 16),
                 bits=int(bits),
                 frequency=int(parts[3]) if len(parts) > 3 and parts[3]
                 else 433_920_000,
                 te=int(parts[4]) if len(parts) > 4 and parts[4] else 0,
                 guard=int(parts[5]) if len(parts) > 5 and parts[5]
                 else _DEFAULT_GUARD,
                 source=spec)


def load_frames(sources: list[str] | str) -> list[Frame]:
    """Load frames from specs, .sub files, .marquee files or directories."""
    if isinstance(sources, str):
        sources = [s for s in sources.replace(",", " ").split() if s]
    frames: list[Frame] = []
    for raw in sources:
        target = os.path.expanduser(raw)
        if any(ch in target for ch in "*?["):
            matches = sorted(glob.glob(target))
            if not matches:
                raise FileNotFoundError(f"no match for {raw!r}")
            frames.extend(load_frames(matches))
            continue
        if os.path.isdir(target):
            names = sorted(n for n in os.listdir(target)
                           if n.endswith((".sub", ".marquee")))
            frames.extend(load_frames([os.path.join(target, n) for n in names]))
            continue
        if target.endswith(".marquee"):
            frames.extend(load_frames_file(target))
            continue
        if target.endswith(".sub"):
            sub = SubFile.load(target)
            found = frames_from_sub(sub, source=target)
            if not found:
                raise ValueError(f"{os.path.basename(target)} is a RAW capture "
                                 "— no protocol fields to re-synthesize")
            frames.extend(found)
            continue
        frames.append(frame_from_spec(raw))
    if not frames:
        raise ValueError("no frames loaded")
    return frames


# ---------------------------------------------------------------------------
# .marquee plan files
# ---------------------------------------------------------------------------

def save_frames(frames: list[Frame], path: str) -> str:
    """Persist frames as a replayable ``.marquee`` plan file."""
    lines: list[str] = []
    for frame in frames:
        lines += [f"Protocol: {frame.protocol}", f"Bit: {frame.bits}",
                  f"Key: {frame.data:X}", f"TE: {frame.te}",
                  f"Guard: {frame.guard}", f"Frequency: {frame.frequency}",
                  f"Preset: {frame.preset}", ""]
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    return path


def load_frames_file(path: str) -> list[Frame]:
    """Read a ``.marquee`` file back into frames."""
    frames: list[Frame] = []
    current: dict = {}

    def _flush() -> None:
        if not current:
            return
        frames.append(Frame(protocol=current["protocol"], data=current["key"],
                            bits=current["bit"],
                            te=current.get("te", 0),
                            guard=current.get("guard", _DEFAULT_GUARD),
                            frequency=current.get("frequency", 433_920_000),
                            preset=current.get("preset", "AM650"),
                            source=path))
        current.clear()

    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                _flush()
                continue
            if line.startswith("#") or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key == "protocol":
                current["protocol"] = value
            elif key == "bit":
                current["bit"] = int(value)
            elif key == "key":
                current["key"] = int(value, 16)
            elif key == "te":
                current["te"] = int(value)
            elif key == "guard":
                current["guard"] = int(value)
            elif key == "frequency":
                current["frequency"] = int(value)
            elif key == "preset":
                current["preset"] = value
    _flush()
    return frames


# ---------------------------------------------------------------------------
# planning
# ---------------------------------------------------------------------------

def plan(frames: list[Frame], order: str = "head-first",
         copies: int = 3) -> list[Slot]:
    """Order the frames and repeat each one ``copies`` times."""
    if order not in ORDERS:
        raise ValueError(f"order must be one of {', '.join(ORDERS)}")
    ordered = list(frames)
    if order == "head-first":
        ordered.reverse()          # newest capture (the tail) fires first
    copies = max(1, int(copies))
    return [Slot(frame=frame, copy=n + 1, position=pos)
            for pos, frame in enumerate(ordered) for n in range(copies)]


def timing(slots: list[Slot], gap_ms: int = 0) -> dict:
    """Exact on-air budget of a plan."""
    gap = clamp_gap(gap_ms)
    frame_ms = sum(s.frame.frame_ms() for s in slots)
    dead_ms = gap * len(slots)
    return {"frames": len({id(s.frame) for s in slots}), "copies": len(slots),
            "frame_ms": round(frame_ms, 1), "gap_ms": gap,
            "dead_ms": round(dead_ms, 1),
            "total_ms": round(frame_ms + dead_ms, 1)}


def check_headroom(frames: list[Frame]) -> dict:
    """Judge whether the capture set is tight enough to win the race."""
    widest = max((f.te * f.guard for f in frames), default=0) / 1000.0
    te_span = sorted({f.te for f in frames})
    notes = []
    if len(te_span) > 1:
        notes.append(f"mixed TE {te_span} — captures from different models")
    if len({f.protocol for f in frames}) > 1:
        notes.append("mixed protocols — the receiver may only accept its own")
    return {"verdict": "tight" if widest <= 20 else "loose",
            "widest_guard_ms": round(widest, 1), "notes": notes}


def describe(slots: list[Slot], budget: dict) -> list[list[str]]:
    """Rows for the operator table."""
    rows = []
    for slot in slots:
        rows.append([str(slot.position + 1), slot.frame.protocol,
                     slot.frame.label().split(" ", 1)[-1],
                     f"{slot.frame.te} us", str(slot.copy),
                     f"{slot.frame.frame_ms():.1f} ms"])
    rows.append(["", "", "", "", "", f"total {budget['total_ms']:.1f} ms"])
    return rows


def to_sub(slots: list[Slot], gap_ms: int = 0, *,
           frequency: int | None = None, preset: str | None = None) -> SubFile:
    """Flatten a plan into one RAW .sub (Flipper-playable single file)."""
    gap = clamp_gap(gap_ms)
    sub = SubFile()
    sub.filetype = "Flipper SubGhz RAW File"
    sub.protocol = "RAW"
    sub.frequency = int(frequency or (slots[0].frame.frequency if slots
                                      else 433_920_000))
    sub.preset_name = preset or (slots[0].frame.preset if slots else "AM650")
    levels: list[tuple[bool, int]] = []
    for slot in slots:
        levels.extend(slot.frame.levels())
        if gap:
            levels.append((False, gap * 1000))
    sub.raw_data = levels_to_raw_durations(levels)
    return sub
