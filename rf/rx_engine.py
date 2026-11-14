"""Async RX engine: edge feed -> protocol decoders (+ RAW recorder).

Also drives frequency-hopping wideband RX — with a Pi-class CPU the radio
can rotate through every regional band while the full decode stack runs.
"""

from __future__ import annotations

import threading
import time

from omni.rf.keystore import Keystore
from omni.rf.protocols import (CameDecoder, HoltekDecoder, KeeLoqDecoder,
                           NiceFloDecoder, PrincetonDecoder)


class RxEngine:
    """Feeds GPIO edges into every protocol decoder and dispatches results."""

    def __init__(self, radio, gpio, gdo0: int, keystore=None):
        self.radio = radio
        self.gpio = gpio
        self.gdo0 = gdo0
        self.keystore = keystore if keystore is not None else Keystore()
        self._callbacks = []
        self._decoders = []
        self._recording = False
        self._recorded: list[tuple[bool, int]] = []
        self.recent: list[tuple[float, object]] = []  # (timestamp, result)
        self.running = False
        self.hop_freqs: list[int] = []  # non-empty while hopping
        self._hop = None  # (thread, stop-event)

    # -- lifecycle -------------------------------------------------------
    def start(self, preset, freq, on_found=None):
        self._stop_hopping()
        self._setup(preset, freq, on_found)

    def start_hopping(self, preset, freqs, hop_ms: int = 250,
                      on_found=None):
        """Rotate through `freqs` every hop_ms while decoding everything.

        The Pi re-tunes the CC1101 fast enough to cover all regional bands in
        seconds — something the Flipper's fixed-frequency apps can't do with
        the same decode stack running.
        """
        freqs = [int(f) for f in freqs if f]
        if not freqs:
            return
        self._stop_hopping()
        self._setup(preset, freqs[0], on_found)
        stop = threading.Event()
        self.hop_freqs = freqs

        def _hopper():
            i = 1
            # wait first so the initial frequency gets a full dwell
            while not stop.wait(max(0.0, hop_ms) / 1000.0):
                f = freqs[i % len(freqs)]
                try:
                    self.radio.load_preset(preset)
                    self.radio.set_frequency(f)
                    self.radio.start_rx()
                except Exception:
                    pass
                i += 1
            try:
                self.radio.idle()
            except Exception:
                pass

        thread = threading.Thread(target=_hopper, name="unleashed-hop",
                                 daemon=True)
        self._hop = (thread, stop)
        thread.start()

    def stop(self):
        self._stop_hopping()
        self.gpio.set_watch(self.gdo0, None)
        for decoder in self._decoders:
            close = getattr(decoder, "close", None)
            if close is not None:
                try:
                    close()
                except Exception:
                    pass
        try:
            self.radio.idle()
        except Exception:
            pass
        self.running = False

    def _setup(self, preset, freq, on_found=None):
        if on_found is not None:
            self.on_found(on_found)
        self._decoders = [
            PrincetonDecoder(),
            CameDecoder(),
            NiceFloDecoder(),
            HoltekDecoder(),
            KeeLoqDecoder(keystore=self.keystore),
        ]
        self.radio.load_preset(preset)
        self.radio.set_frequency(freq)
        self.radio.start_rx()
        self.gpio.set_watch(self.gdo0, self._on_edge)
        self.running = True

    def _stop_hopping(self):
        if self._hop is not None:
            thread, stop = self._hop
            stop.set()
            thread.join(timeout=2.0)
            self._hop = None
        self.hop_freqs = []

    def on_found(self, callback):
        self._callbacks.append(callback)

    # -- edge handling -----------------------------------------------------
    def _on_edge(self, pin, level, duration):
        if self._recording:
            self._recorded.append((bool(level), int(duration)))
        for decoder in self._decoders:
            result = decoder.feed(bool(level), int(duration))
            if result is not None:
                self._dispatch(result)

    def _dispatch(self, result):
        self.recent.append((time.time(), result))
        if len(self.recent) > 20:
            del self.recent[:-20]
        for cb in list(self._callbacks):
            try:
                cb(result)
            except Exception:
                pass

    # -- misc ---------------------------------------------------------------
    def rssi_dbm(self) -> float:
        return self.radio.get_rssi_dbm()

    def start_recording(self):
        self._recording = True
        self._recorded = []

    def stop_recording(self):
        levels = self._recorded
        self._recording = False
        self._recorded = []
        return levels
