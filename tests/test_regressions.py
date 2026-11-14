"""Fixes for faults found by running every module.

Three real bugs, each reproduced here so they cannot regress:
  1. the dashboard needed curses just to build, so a curses-less Python crashed;
  2. `Model.rows()` blew up before `set_needs()` (undefined `_needs`);
  3. `windows.screenshot` did one ctypes call per pixel (10s per frame).
"""

import os

import pytest

from omni.core import dashboard, tui


# 1: building the dashboard must not require curses -------------------------

def test_dashboard_builds_without_curses(monkeypatch):
    monkeypatch.setattr(tui, "_curses", lambda: None)
    model = tui.Model({"wifi": [("wifi.x", "d")]})
    dash = tui.Dashboard(screen=object(), model=model)
    assert dash.curses is None
    assert dash._attr("A_BOLD") == 0


def test_run_dashboard_falls_back_without_curses(monkeypatch):
    monkeypatch.setattr(tui, "_curses", lambda: None)
    monkeypatch.setattr(tui.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(tui.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(tui, "run_plain_dashboard", lambda: 0)
    assert tui.run_dashboard() == 0


def test_attrs_fall_back_to_zero_without_curses(monkeypatch):
    monkeypatch.setattr(tui, "_curses", lambda: None)
    dash = tui.Dashboard(object(), tui.Model({}))
    assert dash._attr("A_DIM") == 0
    assert dash._attr("ANYTHING", 7) == 7


# 2: rows() must work before set_needs ------------------------------------

def test_model_rows_work_without_set_needs():
    model = dashboard.Model({"wifi": [("wifi.a", "first")]})
    model.tab = 1                   # Home is the first tab
    rows = model.rows()
    assert [r.name for r in rows] == ["wifi.a"]
    assert rows[0].ready            # no needs declared -> ready


def test_model_command_works_without_set_needs():
    model = dashboard.Model({"wifi": [("wifi.a", "first")]})
    model.tab = 1
    assert model.command() == ["run", "wifi.a"]


# 3: screenshot must use one bulk copy, not per-pixel calls ---------------

def test_screenshot_uses_getdibits():
    from omni.windows.modules import control
    source = open(control.__file__, encoding="utf-8").read()
    body = source.split("class Screenshot")[-1]
    assert "GetDIBits" in body
    assert "GetPixel" not in body


@pytest.mark.skipif(os.name != "nt", reason="GDI is Windows-only")
def test_screenshot_writes_a_valid_bmp(tmp_path):
    from omni.windows.modules import control
    target = tmp_path / "shot.bmp"
    result = control.Screenshot(OUT=str(target)).execute()
    assert target.is_file() and result["width"] > 0
    head = target.read_bytes()[:30]
    assert head[:2] == b"BM" and int.from_bytes(head[28:30], "little") == 32


def test_key_codes_are_stable():
    from omni.windows.modules import control
    assert control.KEY_CODES["enter"] == 0x0D
    assert control.KEY_CODES["f12"] == 0x7B
