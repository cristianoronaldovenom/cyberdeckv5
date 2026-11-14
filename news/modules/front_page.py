"""Front page of Hacker News via Algolia ``front_page`` tag."""

from omni.core import console
from omni.news import algolia
from omni.news.modules._base import NewsModule

__all__ = ["FrontPage"]


class FrontPage(NewsModule):
    NAME = "news.front"
    DESCRIPTION = "Show the current Hacker News front page"

    def execute(self) -> list[dict]:
        hits = algolia.front_page()
        rows = [algolia.parse_hit(h) for h in hits]
        console.table(
            ["id", "title", "points", "comments"],
            [[str(r["id"]), str(r["title"])[:60], str(r["points"] or "-"),
              str(r["comments"] or "-")] for r in rows])
        return rows
