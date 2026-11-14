"""GPIO backends: lgpio (Pi 3/4/5), pigpio (Pi 3/4, DMA waves) and a mock.

All backends normalize RX into (pin, level, duration_us) events and TX into
a single send_wave(pin, [(level, duration_us), ...]) call.
"""

from __future__ import annotations

import time


class GpioBackend:
    name = "base"
    is_mock = False

    def __init__(self, pins=None):
        self._watches: dict[int, object] = {}

    # -- RX ---------------------------------------------------------------
    def set_watch(self, pin: int, callback) -> None:
        """callback(pin, level, duration_us) or None to clear."""
        if callback is None:
            self._watches.pop(pin, None)
        else:
            self._watches[pin] = callback

    def _fire(self, pin: int, level: int, duration_us: int) -> None:
        cb = self._watches.get(pin)
        if cb is not None:
            cb(pin, level, duration_us)

    # -- TX ---------------------------------------------------------------
    def send_wave(self, pin: int, levels) -> None:
        """Software-timed fallback: write each level and sleep its duration."""
        for level, duration in levels:
            self.write(pin, 1 if level else 0)
            if duration > 0:
                time.sleep(duration / 1e6)
        self.write(pin, 0)

    def write(self, pin: int, level: int) -> None:
        raise NotImplementedError

    def read(self, pin: int) -> int:
        raise NotImplementedError

    def close(self) -> None:
        self._watches.clear()


class _EdgeTimer:
    """Converts timestamped edges into (level, duration) events."""

    def __init__(self):
        self._last_ts: dict[int, int] = {}
        self._last_level: dict[int, int] = {}

    def edge(self, pin: int, level: int, timestamp: int) -> None:
        last = self._last_ts.get(pin)
        self._last_ts[pin] = timestamp
        prev = self._last_level.get(pin)
        self._last_level[pin] = level
        if last is None or prev is None:
            return
        duration = timestamp - last
        if duration < 0:  # tick wrap
            duration += 1 << 32
        if duration > 0:
            self._fire(pin, prev, duration)


class MockBackend(GpioBackend):
    """Loopback backend: records TX waves, replays them on demand."""

    name = "mock"
    is_mock = True

    def __init__(self, pins=None):
        super().__init__(pins)
        self.sent_waves: list[list] = []
        self._levels: dict[int, int] = {}

    def send_wave(self, pin: int, levels) -> None:
        self.sent_waves.append(list(levels))
        if levels:
            self._levels[pin] = 1 if levels[-1][0] else 0

    def feed_levels(self, pin: int, levels) -> None:
        """Feed a captured wave back into the RX path (test/demo loopback)."""
        for level, duration in levels:
            self._fire(pin, 1 if level else 0, int(duration))

    def write(self, pin: int, level: int) -> None:
        self._levels[pin] = level

    def read(self, pin: int) -> int:
        return self._levels.get(pin, 0)

class LgpioBackend(GpioBackend, _EdgeTimer):
    """lgpio: works on Pi 3/4 and Pi 5 (RP1 gpiochip)."""

    name = "lgpio"

    def __init__(self, pins=None, chip=None):
        GpioBackend.__init__(self, pins)
        _EdgeTimer.__init__(self)
        import lgpio  # type: ignore
        self._lgpio = lgpio
        self.chip = chip if chip is not None else lgpio.gpiochip_open(0)
        self._callbacks = []
        for pin in pins or []:
            lgpio.gpio_claim_alert(self.chip, pin, lgpio.BOTH_EDGES)
            self._callbacks.append(
                lgpio.callback(self.chip, pin, lgpio.BOTH_EDGES, self._cb))

    def _cb(self, chip, gpio, level, timestamp):
        self.edge(gpio, level, timestamp)

    def write(self, pin: int, level: int) -> None:
        lg = self._lgpio
        try:
            lg.gpio_claim_output(self.chip, pin)
        except Exception:
            pass
        lg.gpio_write(self.chip, pin, level)

    def read(self, pin: int) -> int:
        return self._lgpio.gpio_read(self.chip, pin)

    def close(self) -> None:
        try:
            for cb in self._callbacks:
                cb.cancel()
            self._lgpio.gpiochip_close(self.chip)
        except Exception:
            pass
        super().close()


class PigpioBackend(GpioBackend, _EdgeTimer):
    """pigpio: DMA-timed waves (most precise TX on Pi 3/4)."""

    name = "pigpio"

    def __init__(self, pins=None):
        GpioBackend.__init__(self, pins)
        _EdgeTimer.__init__(self)
        import pigpio  # type: ignore
        self._pigpio = pigpio
        self.pi = pigpio.pi()
        if not self.pi.connected:
            raise RuntimeError("pigpiod not running")
        self._callbacks = []
        for pin in pins or []:
            self.pi.set_mode(pin, pigpio.INPUT)
            self._callbacks.append(
                self.pi.callback(pin, pigpio.EITHER_EDGE, self._cb))

    def _cb(self, gpio, level, tick):
        self.edge(gpio, level, tick)

    def send_wave(self, pin: int, levels) -> None:
        pi, pigpio = self.pi, self._pigpio
        pi.set_mode(pin, pigpio.OUTPUT)
        pulses = []
        for level, duration in levels:
            mask = 1 << pin
            pulses.append(pigpio.pulse(mask if level else 0,
                                       0 if level else mask, int(duration)))
        pi.wave_clear()
        pi.wave_add_generic(pulses)
        wid = pi.wave_create()
        if wid >= 0:
            pi.wave_send_once(wid)
            while pi.wave_tx_busy():
                time.sleep(0.001)
            pi.wave_delete(wid)

    def write(self, pin: int, level: int) -> None:
        self.pi.write(pin, level)

    def read(self, pin: int) -> int:
        return self.pi.read(pin)

    def close(self) -> None:
        try:
            for cb in self._callbacks:
                cb.cancel()
            self.pi.stop()
        except Exception:
            pass
        super().close()


def detect_backend(pins=None, prefer: str | None = None,
                  chip_hint=None) -> GpioBackend:
    """Pick the best available GPIO backend; mock is the universal fallback."""
    pins = list(pins or [])
    order = []
    if prefer == "lgpio":
        order = [LgpioBackend]
    elif prefer == "pigpio":
        order = [PigpioBackend]
    elif prefer == "mock":
        order = []
    else:
        order = [LgpioBackend, PigpioBackend]
    for cls in order:
        try:
            if cls is LgpioBackend:
                return LgpioBackend(pins, chip=chip_hint)
            return cls(pins)
        except Exception:
            continue
    return MockBackend(pins)

