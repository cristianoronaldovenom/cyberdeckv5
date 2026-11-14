"""Radio rig: binds a CC1101 + GPIO backend, falling back to mocks.

Used by the sub-GHz and car-key modules so a missing SPI bus or GPIO daemon
never blocks a run — the same code path then runs in demo mode and reports it.
"""

from __future__ import annotations

from dataclasses import dataclass

from omni.core import config, console
from omni.rf.cc1101 import CC1101, MockSPI
from omni.rf.gpio_backend import detect_backend
from omni.rf.keystore import Keystore
from omni.rf.rx_engine import RxEngine
from omni.rf.tx_engine import TxEngine

__all__ = ["Rig", "open_rig"]


@dataclass
class Rig:
    radio: CC1101
    gpio: object
    gdo0: int
    real_radio: bool
    real_gpio: bool
    keystore: Keystore | None = None

    @property
    def demo(self) -> bool:
        return not (self.real_radio and self.real_gpio)

    def tx(self) -> TxEngine:
        return TxEngine(self.radio, self.gpio, self.gdo0,
                        allow_extended=bool(
                            config.get_value("rf.allow_extended_freq", True)),
                        keystore=self.keystore)

    def rx(self) -> RxEngine:
        return RxEngine(self.radio, self.gpio, self.gdo0, keystore=self.keystore)

    def close(self) -> None:
        for closer in (getattr(self.gpio, "close", None),
                       getattr(self.radio, "close", None)):
            if closer:
                try:
                    closer()
                except Exception:  # noqa: BLE001 - teardown only
                    pass


def _open_radio() -> tuple[CC1101, bool]:
    bus = int(config.get_value("rf.spi_bus", 0) or 0)
    cs = int(config.get_value("rf.spi_cs", 0) or 0)
    try:
        radio = CC1101(bus, cs)
        if radio.check_alive():
            return radio, True
    except Exception as exc:  # noqa: BLE001 - no spidev / no device
        console.debug(f"cc1101 unavailable: {exc}")
    return CC1101(spi=MockSPI()), False


def open_rig(keystore: Keystore | None = None) -> Rig:
    """Open a rig, degrading to mocks and warning on stderr when it does."""
    gdo0 = int(config.get_value("rf.gdo0_gpio", 27) or 27)
    prefer = config.get_value("rf.prefer_backend") or None
    chip = config.get_value("rf.gpio_chip")
    radio, real_radio = _open_radio()
    gpio = detect_backend([gdo0], prefer=prefer, chip_hint=chip)
    real_gpio = not getattr(gpio, "is_mock", False)
    if not (real_radio and real_gpio):
        console.warn("demo mode: "
                     f"radio={'real' if real_radio else 'mock'}, "
                     f"gpio={getattr(gpio, 'name', 'mock')}")
    return Rig(radio, gpio, gdo0, real_radio, real_gpio, keystore)
