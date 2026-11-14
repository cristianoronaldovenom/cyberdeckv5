"""Layered configuration: defaults <- config file <- environment <- CLI flags.

The persisted file lives at ``~/.config/omni/config.json`` (override with
``$OMNI_CONFIG``). Anything the tools need to remember — chosen ADB serial,
CC1101 pins, HN reader preferences — goes through :func:`set_value`.
"""

from __future__ import annotations

import copy
import json
import os

DEFAULTS: dict = {
    # --- general -----------------------------------------------------------
    "adb_binary": "adb",
    "editor": os.environ.get("EDITOR", "nano"),
    "output_dir": "~/omni-loot",
    "timeout": 120,
    "verbose": False,
    # --- sub-GHz (CC1101 on the Pi / SPI header) ---------------------------
    "rf": {
        "spi_bus": 0,
        "spi_cs": 0,
        "gdo0_gpio": 27,
        "gdo2_gpio": 17,
        "gpio_chip": None,
        "prefer_backend": None,
        "default_frequency": 433_920_000,
        "default_preset": "AM650",
        "allow_extended_freq": True,
        "tx_power_dbm": 12,
        "keeloq_keys": "assets/keeloq_keys.txt",
        "repeat": 3,
        "counter_mult": 1,
        "ir_led_pin": 17,
        "lfid_port": "/dev/ttyUSB0",
        "nfc_port": "/dev/ttyUSB0",
        "hid_device": "/dev/hidg0",
    },
    # --- android -----------------------------------------------------------
    "android": {
        "serial": None,
        "scrcpy_binary": "scrcpy",
        "download_dir": "~/omni-loot/android",
        "keep_screen_off": True,
    },
    "ios": {
        "udid": None,
        "binary": "pymobiledevice3",
        "limd_binary": "ideviceinfo",
        "rsd_host": None,
        "rsd_port": None,
        "tunnel": None,
    },
    # --- pentest shell -----------------------------------------------------
    "pentest": {
        "interface": None,
        "lhost": None,
        "lport": 4444,
        "wordlist": "/usr/share/wordlists/rockyou.txt",
    },
    # --- news --------------------------------------------------------------
    "news": {
        "feed": "top",
        "limit": 25,
        "reader_width": 88,
        "show_comments": True,
        "cache_minutes": 5,
        "user": None,
    },
    # --- flipper -----------------------------------------------------------
    "flipper": {
        "mount": None,
        "firmware_repo": "flipperc0d3r/Private-Unleashed-2.0-FlipperZero-Firmware",
    },
    # --- wifi (aircrack-ng suite, monitor-mode interface) ------------------
    "wifi": {
        "interface": None,
        "monitor_interface": None,
        "wordlist": "/usr/share/wordlists/rockyou.txt",
        "capture_dir": "~/omni-loot/wifi",
        "hop_channels": "1-13",
        "crack_tool": "aircrack-ng",
        "hashcat_binary": "hashcat",
        "deauth_count": 8,
        "wps_pin": None,
        "evil_ssid": "FreeWiFi",
        "evil_channel": 6,
    },
    # --- universal radio / SDR / RFID --------------------------------------
    "radio": {
        "sdr_binary": None,
        "rtl433": "rtl_433",
        "rtl_power": "rtl_power",
        "proxmark3": "pm3",
        "nfc_reader": None,
        "ir_device": "/dev/lirc0",
        "default_band": "ism433",
        "sweep_gain": 40,
        "sweep_sample_seconds": 60,
        "sensor_min_rssi": -30,
    },
    # --- car key (KeeLoq / RKE) -------------------------------------------
    "car": {
        "keeloq_keys": "assets/keeloq_keys.txt",
        "sweep_window": 4096,
        "sweep_step": 1,
        "replay_repeat": 3,
        "brand_hint": None,
    },
    # --- brute force -------------------------------------------------------
    "brute": {
        "threads": 8,
        "delay_ms": 0,
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) omni/1.0",
        "wordlist_dir": "/usr/share/wordlists",
        "max_candidates": 200000,
        "hydra_binary": "hydra",
        "john_binary": "john",
    },
}

ENV_MAP = {
    "OMNI_ADB": ("adb_binary",),
    "OMNI_OUTPUT_DIR": ("output_dir",),
    "OMNI_EDITOR": ("editor",),
    "OMNI_SERIAL": ("android", "serial"),
    "OMNI_UDID": ("ios", "udid"),
    "OMNI_IFACE": ("pentest", "interface"),
    "OMNI_LHOST": ("pentest", "lhost"),
    "OMNI_FLIPPER": ("flipper", "mount"),
    "OMNI_NEWS_USER": ("news", "user"),
    "OMNI_WIFI_IFACE": ("wifi", "interface"),
    "OMNI_WIFI_WORDLIST": ("wifi", "wordlist"),
    "OMNI_SDR": ("radio", "sdr_binary"),
    "OMNI_PM3": ("radio", "proxmark3"),
    "OMNI_WORDLIST": ("brute", "wordlist_dir"),
}


def config_path() -> str:
    return os.path.expanduser(
        os.environ.get("OMNI_CONFIG", "~/.config/omni/config.json"))


def _deep_merge(base: dict, overlay: dict) -> dict:
    for key, val in overlay.items():
        if isinstance(val, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
    return base


def load(path: str | None = None) -> dict:
    """Return the effective config (defaults + file + env)."""
    cfg = copy.deepcopy(DEFAULTS)
    path = path or config_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        if isinstance(user, dict):
            _deep_merge(cfg, user)
    except FileNotFoundError:
        pass
    except (OSError, json.JSONDecodeError):
        pass
    for env, keys in ENV_MAP.items():
        val = os.environ.get(env)
        if val is None:
            continue
        node = cfg
        for key in keys[:-1]:
            node = node.setdefault(key, {})
        node[keys[-1]] = val
    return cfg


_CFG: dict | None = None


def get() -> dict:
    global _CFG
    if _CFG is None:
        _CFG = load()
    return _CFG


def reload() -> dict:
    global _CFG
    _CFG = load()
    return _CFG


def get_value(dotted: str, default=None):
    node: object = get()
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def set_value(dotted: str, value) -> None:
    """Set and persist a config key (creates parent dicts as needed)."""
    node = get()
    parts = dotted.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
    save()


def save(path: str | None = None) -> str:
    path = path or config_path()
    os.makedirs(os.path.dirname(os.path.expanduser(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(get(), fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def output_dir(sub: str | None = None) -> str:
    """Loot directory, created on demand (``$OMNI_HOME/loot`` when set)."""
    home = os.environ.get("OMNI_HOME")
    if home:
        base = os.path.join(os.path.expanduser(home), "loot")
    else:
        base = os.path.expanduser(str(get_value("output_dir", "~/omni-loot")))
    path = os.path.join(base, sub) if sub else base
    os.makedirs(path, exist_ok=True)
    return path


def adb() -> str:
    return str(get_value("adb_binary", "adb"))
