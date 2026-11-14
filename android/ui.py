"""uiautomator dump: parse the view tree, search it, target one node.

Pixel coordinates are a guess that a different font size breaks. The dump the
device already produces (``uiautomator dump``) carries the real tree — labels,
content descriptions, resource ids and the exact bounds of every node — so a
tap can be aimed at a *node* instead of a screenshot.

The parsers are pure text functions, which is what makes a whole UI flow
testable without a phone attached.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from xml.etree import ElementTree

__all__ = ["Node", "parse_bounds", "parse_dump", "find", "pick", "select",
           "labels", "rows", "BOUNDS_RE"]

BOUNDS_RE = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")


@dataclass(frozen=True)
class Node:
    """One node of the dumped view hierarchy."""

    text: str = ""
    desc: str = ""
    resource_id: str = ""
    class_name: str = ""
    package: str = ""
    bounds: tuple[int, int, int, int] = (0, 0, 0, 0)
    clickable: bool = False
    enabled: bool = True
    selected: bool = False
    checked: bool = False
    scrollable: bool = False

    # -- geometry ----------------------------------------------------------
    @property
    def centre(self) -> tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return (x1 + x2) // 2, (y1 + y2) // 2

    @property
    def area(self) -> int:
        x1, y1, x2, y2 = self.bounds
        return max(0, x2 - x1) * max(0, y2 - y1)

    @property
    def label(self) -> str:
        """Best human label: visible text, else content-desc, else id name."""
        return (self.text or self.desc
                or self.resource_id.rsplit("/", 1)[-1] or self.class_name)

    # -- matching ----------------------------------------------------------
    def haystacks(self) -> tuple[str, ...]:
        return (self.text, self.desc, self.resource_id, self.class_name)

    def matches(self, needle: str, exact: bool = False) -> bool:
        if not needle:
            return True
        low = needle.lower()
        if exact:
            return any(field == needle for field in self.haystacks())
        return any(low in field.lower() for field in self.haystacks())

    def to_row(self) -> dict:
        x, y = self.centre
        return {"label": self.label, "class": self.class_name,
                "clickable": self.clickable, "x": x, "y": y,
                "package": self.package}


def parse_bounds(text: str) -> tuple[int, int, int, int]:
    """``[x1,y1][x2,y2]`` -> a 4-tuple; ``(0, 0, 0, 0)`` on junk."""
    match = BOUNDS_RE.search(text or "")
    if not match:
        return (0, 0, 0, 0)
    return tuple(int(v) for v in match.groups())     # type: ignore[return-value]


def _flag(attrs: dict, name: str, default: bool = False) -> bool:
    raw = (attrs.get(name) or "").strip().lower()
    return default if not raw else raw == "true"



def parse_dump(xml_text: str) -> list[Node]:
    """Every node of a ``uiautomator dump`` XML document.

    The dump is sometimes preceded by shell chatter (``UI hierchary dumped to
    ...``), so everything before the first ``<`` is discarded. A document with
    no nodes is a real outcome (a secure window) and returns an empty list
    rather than raising.
    """
    text = (xml_text or "").strip()
    start = text.find("<")
    if start < 0:
        return []
    text = text[start:]
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ValueError(f"not a uiautomator dump: {exc}") from None
    nodes: list[Node] = []
    for element in root.iter("node"):
        attrs = element.attrib
        nodes.append(Node(
            text=attrs.get("text", ""),
            desc=attrs.get("content-desc", ""),
            resource_id=attrs.get("resource-id", ""),
            class_name=attrs.get("class", ""),
            package=attrs.get("package", ""),
            bounds=parse_bounds(attrs.get("bounds", "")),
            clickable=_flag(attrs, "clickable"),
            enabled=_flag(attrs, "enabled", True),
            selected=_flag(attrs, "selected"),
            checked=_flag(attrs, "checked"),
            scrollable=_flag(attrs, "scrollable"),
        ))
    return nodes


def find(nodes: list[Node], text: str = "", *, desc: str = "", rid: str = "",
         cls: str = "", exact: bool = False,
         clickable: bool | None = None,
         enabled: bool | None = None,
         scrollable: bool | None = None) -> list[Node]:
    """Nodes matching every given constraint, in tree order."""
    out: list[Node] = []
    for node in nodes:
        if text and not node.matches(text, exact):
            continue
        if desc and not (node.desc == desc if exact
                          else desc.lower() in node.desc.lower()):
            continue
        if rid and rid.lower() not in node.resource_id.lower():
            continue
        if cls and cls.lower() not in node.class_name.lower():
            continue
        if clickable is not None and node.clickable != clickable:
            continue
        if enabled is not None and node.enabled != enabled:
            continue
        if scrollable is not None and node.scrollable != scrollable:
            continue
        out.append(node)
    return out


def pick(nodes: list[Node]) -> Node | None:
    """The node a human would have meant: clickable, smallest, highest up."""
    if not nodes:
        return None
    return sorted(nodes, key=lambda n: (not n.clickable, n.area,
                                        n.bounds[1], n.bounds[0]))[0]


def select(nodes: list[Node], **kwargs) -> Node | None:
    """``pick(find(nodes, **kwargs))`` — the common targeting call."""
    return pick(find(nodes, **kwargs))


def labels(nodes: list[Node]) -> list[str]:
    """Distinct non-empty labels, in tree order (what the screen *says*)."""
    seen: list[str] = []
    for node in nodes:
        label = node.label.strip()
        if label and label not in seen:
            seen.append(label)
    return seen


def rows(nodes: list[Node], limit: int = 40) -> list[list[str]]:
    """Table rows for the console (label / class / clickable / centre)."""
    out = []
    for node in nodes[:max(1, limit)]:
        x, y = node.centre
        out.append([node.label[:38], node.class_name.rsplit(".", 1)[-1][:18],
                    "yes" if node.clickable else "-", f"{x},{y}"])
    return out
