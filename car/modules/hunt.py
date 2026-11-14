"""Listen across every regional band, then keep the press that matters.

``car.unlock`` needs a capture already in hand, and ``rf.hunt`` hunts *fixed*
codes on one carrier. This is the missing reconnaissance step for a car: sweep
315 / 433.92 / 434.42 / 868.35 MHz with the full decode stack live, convert
anything that looks like a remote into a ``.sub``, identify it against the
keystore, and rank the lot so the next command has a target.

Frequency attribution comes from the plan itself — the module owns the hop
loop, so a decode is always pinned to the carrier that was tuned when it
arrived (the RX engine's internal hopper cannot report that).
"""

from __future__ import annotations

import json
import os
import time

from omni.car import analysis, survey
from omni.car.modules._base import CarModule
from omni.core import config, console
from omni.core.module import Option
from omni.rf.presets import preset_by_name

__all__ = ["Hunt"]


class Hunt(CarModule):
    NAME = "car.hunt"
    DESCRIPTION = "Sweep the regional bands, capture fob presses, rank the hits"
    OPTIONS = (Option("SECONDS", "how long to listen", "30"),
               Option("REGION", "all|us|eu|eu_alt|wide, or MHz list", "all"),
               Option("PRESET", "modem preset", "AM650"),
               Option("DWELL_MS", "time on each carrier", "250"),
               Option("MIN_BITS", "ignore decodes shorter than this", "12"),
               Option("KEYSTORE", "manufacturer keystore path"),
               Option("SAVE", "keep every capture as a .sub", "true",
                      choices=("true", "false")),
               Option("OUT", "capture directory"),
               Option("REPORT", "also write the ranked report as JSON",
                      "true", choices=("true", "false")))

    def _listen(self, rig, preset, plan: list[tuple[int, float]],
                state: dict, presses: list) -> int:
        """Run the hop plan; returns the number of hops performed."""
        min_bits = max(survey.MIN_BITS, self.get_int("MIN_BITS",
                                                     survey.MIN_BITS))

        def _found(result) -> None:
            sub = survey.sub_from_press(result, state["freq"], preset.name)
            if sub is None:
                return
            presses.append((state["freq"], sub))
            console.ok(f"{state['freq'] / 1e6:.3f} MHz — {sub.protocol} "
                       f"0x{sub.key:X} ({sub.bit} bit)")

        rx = rig.rx()
        rx.on_found(_found)
        rx.start(preset, plan[0][0])
        hops = 0
        try:
            for frequency, dwell in plan:
                state["freq"] = frequency
                rig.radio.set_frequency(frequency)
                rig.radio.start_rx()
                time.sleep(dwell)
                hops += 1
        finally:
            rx.stop()
        console.debug(f"{hops} hop(s), {min_bits} bit minimum")
        return hops

    def execute(self) -> dict:
        freqs = survey.band_frequencies(self.get("REGION") or "all")
        preset = preset_by_name(self.get("PRESET") or "AM650")
        seconds = max(2, self.get_int("SECONDS", 30))
        plan = survey.hop_plan(freqs, seconds,
                               self.get_int("DWELL_MS", 250))
        console.kv([("carriers", ", ".join(f"{f / 1e6:.3f} MHz"
                                           for f in freqs)),
                    ("window", f"{seconds}s"),
                    ("hops", str(len(plan)))])
        presses: list = []
        state = {"freq": plan[0][0]}
        rig = self.rig()
        try:
            console.info("press the fob now — listening across the bands")
            hops = self._listen(rig, preset, plan, state, presses)
        finally:
            rig.close()

        if not presses:
            console.warn("nothing decoded — press again, move closer, or try "
                         "PRESET=FM476 for FSK remotes")
            return {"presses": 0, "hops": hops, "demo": rig.demo}

        store = self.keystore(self.get("KEYSTORE") or None)
        outdir = os.path.expanduser(self.get("OUT") or
                                    config.output_dir("car/hunt"))
        keep = self.get_bool("SAVE", True)
        reports: list[dict] = []
        for index, (frequency, sub) in enumerate(presses):
            report = analysis.analyze_sub(sub, store)
            report["frequency"] = frequency
            report["score"] = survey.score(report)
            if keep:
                os.makedirs(outdir, exist_ok=True)
                path = os.path.join(
                    outdir, f"hunt_{int(frequency / 1000)}_{index:02d}.sub")
                sub.save(path)
                report["path"] = path
            reports.append(report)

        ranked = survey.rank(reports)
        console.table(["MHz", "protocol", "verdict", "score"],
                      survey.rows(ranked, 20))
        best = ranked[0]
        console.ok(f"best: {best['frequency'] / 1e6:.3f} MHz — "
                   f"{best.get('verdict', 'raw capture')}")
        console.info("next: omni run car.unlock SUB=<that file>")

        saved = ""
        if self.get_bool("REPORT", True):
            saved = os.path.join(outdir, "hunt_report.json")
            os.makedirs(outdir, exist_ok=True)
            with open(saved, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps({"plan": plan, "reports": ranked},
                                    indent=2) + "\n")
            console.info(f"report: {saved}")
        return {"presses": len(ranked), "hops": hops, "best": best,
                "report": saved, "demo": rig.demo}
