"""Algolia search client for Hacker News (hn.algolia.com/api/v1)."""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

__all__ = ["search", "search_by_date", "front_page", "item"]

BASE = "https://hn.algolia.com/api/v1"


def _get(path: str, **params) -> dict:
    url = f"{BASE}/{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "omni/1.0"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except Exception:  # noqa: BLE001
            if attempt == 2:
                raise
            time.sleep(1 + attempt)
    return {}


def search(query: str, tags: str | None = None, hits_per_page: int = 20) -> list[dict]:
    # the API parameter is hitsPerPage, not tagsPerQuery (that is a JS client option)
    params: dict = {"query": query, "hitsPerPage": hits_per_page}
    if tags:
        params["tags"] = tags
    data = _get("search", **params)
    return data.get("hits", [])


def search_by_date(query: str, since: int | None = None, tags: str | None = None,
                   hits_per_page: int = 20) -> list[dict]:
    params: dict = {"query": query, "hitsPerPage": hits_per_page}
    if since:
        params["numericFilters"] = f"created_at_i>{since}"
    if tags:
        params["tags"] = tags
    return _get("search_by_date", **params).get("hits", [])


def front_page() -> list[dict]:
    return _get("search", tags="front_page").get("hits", [])


def item(item_id: int | str) -> dict:
    return _get(f"items/{item_id}")


def parse_hit(hit: dict) -> dict:
    return {
        "id": hit.get("objectID"),
        "title": hit.get("title") or hit.get("story_title") or "(comment)",
        "author": hit.get("author"),
        "url": hit.get("url") or "",
        "points": hit.get("points"),
        "comments": hit.get("num_comments"),
        "age_h": round(time.time() - int(hit.get("created_at_i", time.time()))) // 3600,
    }
