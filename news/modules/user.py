"""Hacker News user profile (Firebase API) plus item threads."""

from omni.core import console
from omni.core.module import Option
from omni.news import firebase
from omni.news.modules._base import NewsModule

__all__ = ["User"]


class User(NewsModule):
    NAME = "news.user"
    DESCRIPTION = "Inspect a Hacker News user (karma, since, submissions)"
    OPTIONS = (Option("NAME", "HN username", "", required=True),)

    def execute(self) -> dict:
        profile = firebase.user(self.get("NAME"))
        if not profile:
            console.warn("no such user")
            return {}
        console.kv([("id", profile.get("id")),
                    ("karma", profile.get("karma")),
                    ("created", profile.get("created")),
                    ("about", (profile.get("about") or "")[:200])])
        return profile
