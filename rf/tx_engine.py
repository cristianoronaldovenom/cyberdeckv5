"""TX engine: uploads level trains through the radio + GPIO wave output."""

from __future__ import annotations

import time

from omni.rf import keeloq_crypto as kq
from omni.rf.keystore import manufacturer_key, resolve_man
from omni.rf.protocols import (CameEncoder, KeeLoqEncoder, NiceFloEncoder,
                           PrincetonEncoder, build_keeloq_upload)
from omni.rf.subfile import raw_durations_to_levels
from omni.rf.util import is_tx_allowed


class TxEngine:
    def __init__(self, radio, gpio, gdo0: int, allow_extended: bool = True,
                 keystore=None):
        self.radio = radio
        self.gpio = gpio
        self.gdo0 = gdo0
        self.allow_extended = allow_extended
        self.keystore = keystore

    def send(self, preset, freq, upload, repeat: int = 1,
             gap_s: float = 0.0) -> int:
        """Radiate `upload` `repeat` times; returns the number of frames sent."""
        if not is_tx_allowed(freq, self.allow_extended):
            raise ValueError(f"frequency {freq} outside allowed TX ranges")
        self.radio.load_preset(preset)
        self.radio.set_frequency(freq)
        sent = 0
        for _ in range(max(1, repeat)):
            self.radio.start_tx()
            self.gpio.send_wave(self.gdo0, upload)
            self.radio.idle()
            sent += 1
            if gap_s:
                time.sleep(gap_s)
        return sent

    def send_subfile(self, sub) -> int:
        """Replay a .sub file (decoded or RAW) at its stored settings."""
        repeat = max(1, sub.repeat or 1)
        if sub.is_raw:
            levels = raw_durations_to_levels(sub.raw_data)
            return self.send(sub.preset(), sub.frequency, levels, repeat=repeat)
        proto = sub.protocol
        if proto == "KeeLoq":
            return self._send_keeloq(sub, repeat)
        if proto == "Princeton":
            enc = PrincetonEncoder(data=sub.key, data_count_bit=sub.bit,
                                  te=sub.te or 390,
                                  guard_time=sub.guard_time or 30)
        elif proto == "CAME":
            enc = CameEncoder(data=sub.key, data_count_bit=sub.bit,
                              te=sub.te or 320)
        elif proto == "Nice FLO":
            enc = NiceFloEncoder(data=sub.key, data_count_bit=sub.bit,
                                 te=sub.te or 500)
        else:
            raise ValueError(f"unknown protocol {proto!r}")
        return self.send(sub.preset(), sub.frequency, enc.build_upload(),
                         repeat=repeat)

    def _send_keeloq(self, sub, repeat: int) -> int:
        fix, hop = kq.split_frame(sub.key)
        entry = None
        if self.keystore and sub.manufacture:
            entry = self.keystore.get(sub.manufacture)
        if entry is None:
            # unknown manufacturer: replay the captured frame verbatim
            upload = build_keeloq_upload(fix, hop, sub.te or 400)
            return self.send(sub.preset(), sub.frequency, upload,
                             repeat=repeat)
        man, dec = resolve_man(entry, fix, hop, sub.seed)
        if man is None:
            man = manufacturer_key(entry, fix, sub.seed)
        cnt = (dec & 0xFFFF) if dec is not None else 0
        btn, serial = kq.parse_fix(fix)
        enc = KeeLoqEncoder(keystore=self.keystore, te=sub.te or 400,
                            repeat=repeat)
        # freeze the counter: send exactly the frame stored in the file
        enc.set_frame(serial=serial, btn=btn, cnt=cnt,
                      manufacture_name=sub.manufacture, counter_mode=6)
        upload, rep = enc.get_upload()
        return self.send(sub.preset(), sub.frequency, upload, repeat=rep)
