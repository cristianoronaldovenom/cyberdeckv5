"""CC1101 SPI driver (register level) with a full mock for demo mode."""

from __future__ import annotations

from omni.rf.util import frequency_to_registers

# CC1101 register / strobe addresses
REG_PARTNUM = 0x30
REG_VERSION = 0xF1
REG_RSSI = 0x34
REG_FREQ2, REG_FREQ1, REG_FREQ0 = 0x0D, 0x0E, 0x0F
REG_PATABLE = 0x3E
STROBE_SRX = 0x34
STROBE_STX = 0x35
STROBE_SIDLE = 0x36

PARTNUM_CC1101 = 0x0E


class MockSPI:
    """In-memory SPI bus: the whole stack runs end-to-end without hardware."""

    def __init__(self):
        self.regs: dict[int, int] = {}
        self.strobes: list[int] = []
        self.rssi_raw = 150  # ~ +1 dBm by the formula below

    def wreg(self, addr: int, value: int) -> None:
        self.regs[addr & 0x3F] = value & 0xFF

    def rreg(self, addr: int) -> int:
        if addr == REG_PARTNUM:
            return PARTNUM_CC1101
        if addr == REG_VERSION:
            return 0x04
        if addr == REG_RSSI:
            return self.rssi_raw
        a = addr & 0x3F
        return self.regs.get(a, 0)

    def strobe(self, addr: int) -> None:
        self.strobes.append(addr)

    def close(self) -> None:
        pass


class SpiDevSPI:
    """Real SPI via spidev (Raspberry Pi)."""

    def __init__(self, bus: int = 0, cs: int = 0):
        import spidev  # type: ignore
        self._dev = spidev.SpiDev()
        self._dev.open(bus, cs)
        self._dev.max_speed_hz = 1_000_000
        self._dev.mode = 0

    def wreg(self, addr: int, value: int) -> None:
        self._dev.xfer2([addr & 0x3F, value & 0xFF])

    def rreg(self, addr: int) -> int:
        return self._dev.xfer2([(addr & 0x3F) | 0x80, 0])[1]

    def strobe(self, addr: int) -> None:
        self._dev.xfer2([addr & 0x3F])

    def close(self) -> None:
        try:
            self._dev.close()
        except Exception:
            pass


class CC1101:
    """Register-level CC1101 radio driver."""

    def __init__(self, spi_bus: int = 0, spi_cs: int = 0, spi=None):
        self.frequency = 433_920_000
        if spi is not None:
            self.spi = spi
        else:
            self.spi = SpiDevSPI(spi_bus, spi_cs)  # may raise -> caller falls back
        self._partnum = None
        self._version = None

    # -- identity -------------------------------------------------------
    def get_partnum(self) -> int:
        self._partnum = self.spi.rreg(REG_PARTNUM)
        return self._partnum

    def get_version(self) -> int:
        self._version = self.spi.rreg(REG_VERSION)
        return self._version

    def check_alive(self) -> bool:
        try:
            return self.get_partnum() == PARTNUM_CC1101
        except Exception:
            return False

    # -- configuration ----------------------------------------------------
    def load_preset(self, preset) -> None:
        for addr, value in preset.registers.items():
            self.spi.wreg(addr, value)
        for byte in preset.patable:
            self.spi.wreg(REG_PATABLE, byte)

    def set_frequency(self, freq: int) -> None:
        f2, f1, f0 = frequency_to_registers(freq)
        self.spi.wreg(REG_FREQ2, f2)
        self.spi.wreg(REG_FREQ1, f1)
        self.spi.wreg(REG_FREQ0, f0)
        self.frequency = int(freq)

    # -- state ------------------------------------------------------------
    def start_rx(self) -> None:
        self.spi.strobe(STROBE_SRX)

    def start_tx(self) -> None:
        self.spi.strobe(STROBE_STX)

    def idle(self) -> None:
        self.spi.strobe(STROBE_SIDLE)

    def get_rssi_dbm(self) -> float:
        raw = self.spi.rreg(REG_RSSI)
        return raw / 2.0 - 74.0

    def close(self) -> None:
        try:
            self.idle()
        finally:
            self.spi.close()
