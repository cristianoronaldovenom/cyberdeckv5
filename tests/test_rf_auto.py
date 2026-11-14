"""Auto-adjusting CC1101 front end: AFC, AGC, clipping, hysteresis.

No hardware: the fake radio models RSSI as a bell curve around a carrier,
attenuated by the gain register and lifted by the LNA, so the controller's
decisions can be checked the way a signal generator would show them.
"""

import json

from omni.rf import adapt
from omni.rf.adapt import AGCCTRL0, AGCCTRL2
from omni.rf.modules.auto import Auto

PEAK = 433_920_000

#: gain register -> dB of front-end attenuation
GAIN_DB = {0x00: 0.0, 0x02: -3.0, 0x04: -8.0, 0x07: -14.0}


class FakeSPI:
    def __init__(self):
        self.regs = {}

    def wreg(self, addr, value):
        self.regs[addr] = value

    def rreg(self, addr):
        return self.regs.get(addr, 0)

    def strobe(self, addr):
        pass

    def close(self):
        pass


class FakeRadio:
    """A CC1101 whose RSSI follows trim, gain and LNA."""

    def __init__(self, peak=PEAK, strength=-70.0, db_per_khz=0.2,
                 noise=-100.0, lna_db=6.0):
        self.spi = FakeSPI()
        self.frequency = 0
        self.peak = peak
        self.strength = strength
        self.db_per_khz = db_per_khz
        self.noise = noise
        self.lna_db = lna_db
        self.muted = False
        self.reads = 0

    def set_frequency(self, freq):
        self.frequency = int(freq)

    def start_rx(self):
        pass

    def idle(self):
        pass

    def get_rssi_dbm(self):
        self.reads += 1
        if self.muted:                      # nothing on the air yet
            return self.noise
        off = abs(self.frequency - self.peak) / 1000.0
        gain = GAIN_DB.get(self.spi.regs.get(AGCCTRL2, 0x00), -20.0)
        lna = 0.0 if self.spi.regs.get(AGCCTRL0, 0x00) == 0 else -self.lna_db
        level = self.strength - self.db_per_khz * off + gain + lna
        return max(level, self.noise)


def warm(front, radio):
    """Let the controller learn the noise floor the way a real run does."""
    radio.muted = True
    front.step()
    radio.muted = False
    return front


# -- pure helpers -----------------------------------------------------------

def test_noise_floor_is_a_median_so_one_carrier_cannot_move_it():
    assert adapt.noise_floor([-91.0, -90.0, -89.0, -40.0]) == -89.0
    assert adapt.noise_floor([]) == -200.0


def test_labels_come_from_the_register_tables():
    assert adapt.gain_label(0x00) == "max"
    assert adapt.gain_label(0x07) == "low"
    assert adapt.lna_label(0x00) == "lna-on"


# -- AFC ---------------------------------------------------------------------

def test_afc_walks_onto_the_real_peak():
    radio = FakeRadio(peak=PEAK + 40_000, strength=-60.0)
    front = warm(adapt.AutoFront(radio, PEAK, span_khz=120, step_khz=20), radio)
    for _ in range(6):
        front.step()
    assert front.offset_khz == 40
    assert radio.frequency == PEAK + 40_000
    assert [m.kind for m in front.adjustments] == ["afc", "afc"]


def test_afc_does_not_move_on_a_flat_signal():
    radio = FakeRadio(peak=PEAK, strength=-60.0, db_per_khz=0.0)
    front = warm(adapt.AutoFront(radio, PEAK, span_khz=120), radio)
    front.step()
    assert front.offset_khz == 0
    assert front.adjustments == []


def test_a_quiet_window_only_moves_the_floor():
    radio = FakeRadio(strength=-95.0, noise=-95.0)
    front = adapt.AutoFront(radio, PEAK)
    front.step()
    front.step()
    assert front.adjustments == []
    assert front.floor == -95.0


# -- AGC ---------------------------------------------------------------------

def test_agc_steps_up_to_maximum_gain():
    radio = FakeRadio(strength=-70.0, db_per_khz=0.0)
    front = adapt.AutoFront(radio, PEAK)
    front.gain = 0x04                                  # start under-driven
    warm(front, radio)
    for _ in range(4):
        front.step()
    assert front.gain == 0x00
    assert radio.spi.regs[AGCCTRL2] == 0x00
    assert front.adjustments and front.adjustments[0].kind == "gain"


def test_agc_attenuates_a_clipping_signal():
    radio = FakeRadio(strength=-5.0, db_per_khz=0.0)
    front = warm(adapt.AutoFront(radio, PEAK), radio)
    moves = front.step()
    assert [m.kind for m in moves] == ["gain"]
    assert "clipping" in moves[0].reason
    assert front.gain == 0x02


def test_lna_is_the_last_knob_and_needs_a_clear_win():
    radio = FakeRadio(strength=-70.0, db_per_khz=0.0)
    front = adapt.AutoFront(radio, PEAK)
    front.lna = 0x03                                   # LNA off
    warm(front, radio)
    front.step()
    assert front.lna == 0x00
    assert radio.spi.regs[AGCCTRL0] == 0x00
    assert front.adjustments[-1].kind == "lna"


# -- books -------------------------------------------------------------------

def test_restore_puts_the_stock_setting_back():
    radio = FakeRadio(peak=PEAK + 40_000, strength=-60.0)
    front = warm(adapt.AutoFront(radio, PEAK, span_khz=120, step_khz=20),
                 radio)
    front.step()
    assert front.offset_khz != 0
    front.restore()
    assert front.offset_khz == 0 and radio.frequency == PEAK


def test_state_reports_what_it_holds():
    front = adapt.AutoFront(FakeRadio(), PEAK)
    state = front.state()
    assert state["gain"] == "max" and state["lna"] == "lna-on"
    assert state["freq"] == PEAK and state["moves"] == 0


# -- the module --------------------------------------------------------------

def test_auto_module_reports_and_saves_the_trim():
    report = Auto(**{"seconds": "1", "cycles": "3", "interval": "0.05",
                     "save": "true"}).run()
    assert report["cycles"] >= 1 and report["freq"] == PEAK
    assert report["demo"] is True                      # no SPI bus in pytest
    saved = json.loads(open(report["saved"], encoding="utf-8").read())
    assert saved["state"]["freq"] == PEAK
    assert isinstance(saved["moves"], list)


def test_auto_module_is_registered():
    from omni.core.module import registry

    assert "rf.auto" in {mod.NAME for mod in registry.all("rf")}
