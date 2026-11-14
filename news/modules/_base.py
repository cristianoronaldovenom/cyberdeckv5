"""Shared plumbing for news modules (HN over HTTP, no API key needed)."""

from omni.core.module import Module

__all__ = ["NewsModule"]


class NewsModule(Module):
    """Base class: no external tools, just the Algolia/Firebase HTTP APIs."""

    FAMILY = "news"
    NEEDS: tuple[str, ...] = ()
