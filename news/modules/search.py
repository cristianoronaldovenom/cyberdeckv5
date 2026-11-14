"""Search Hacker News (stories, comments) via Algolia."""

from omni.core import console
from omni.core.module import Option
from omni.news import algolia
from omni.news.modules._base import NewsModule

__all__ = ["Search"]


class Search(NewsModule):
    NAME = "news.search"
    DESCRIPTION = "Search Hacker News stories/comments (Algolia API)"
    OPTIONS = (
        Option("QUERY", "what to search for", "hacking", required=True),
        Option("SCOPE", "stories|comments", "stories",
               choices=("stories", "comments")),
        Option("COUNT", "max hits", "20"),
    )

    def execute(self) -> list[dict]:
        tags = "story" if self.get("SCOPE") == "stories" else "comment"
        hits = algolia.search(self.get("QUERY"), tags=tags,
                              hits_per_page=self.get_int("COUNT", 20))
        rows = [algolia.parse_hit(h) for h in hits]
        console.table(
            ["id", "title", "points", "comments"],
            [[str(r["id"]), str(r["title"])[:60], str(r["points"] or "-"),
              str(r["comments"] or "-")] for r in rows])
        return rows
