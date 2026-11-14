"""Firebase API v0 client (item/user trees) — hacker-news.firebaseio.com."""

from __future__ import annotations

import json
import urllib.request

BASE = "https://hacker-news.firebaseio.com/v0"
__all__ = ["item", "user", "top_ids", "new_ids", "best_ids", "updates",
           "top_stories"]


def _get(path: str):
    req = urllib.request.Request(f"{BASE}/{path}.json",
                                 headers={"User-Agent": "omni/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def item(item_id: int) -> dict:
    return _get(f"item/{item_id}") or {}


def user(name: str) -> dict:
    return _get(f"user/{name}") or {}


def top_ids() -> list[int]:
    return _get("topstories") or []


def new_ids() -> list[int]:
    return _get("newstories") or []


def best_ids() -> list[int]:
    return _get("beststories") or []


def updates() -> dict:
    return _get("updates") or {}


def top_stories(limit: int = 20) -> list[dict]:
    return [item(i) for i in top_ids()[:limit] if item(i)]
