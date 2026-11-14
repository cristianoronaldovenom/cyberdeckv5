"""Clickable dashboard: goal cards, readiness badges and the worker pipeline."""

from __future__ import annotations

import pytest

from omni.core import goals, gui


def test_gui_availability_is_a_bool():
    assert isinstance(gui.available(), bool)


def test_every_primary_goal_exists():
    for key in goals.PRIMARY:
        assert goals.get(key).title


def test_goal_steps_point_at_real_modules():
    from omni.core.module import registry
    for goal in goals.GOALS:
        for name, _options in goal.steps + goal.fallback:
            assert registry.get(name) is not None, (goal.key, name)


def test_readiness_is_cheap_and_safe():
    for goal in goals.GOALS:
        ready, note = goals.readiness(goal)
        assert isinstance(ready, bool) and isinstance(note, str)


def test_run_goal_with_no_target_reports_skip(monkeypatch):
    monkeypatch.setattr("omni.core.tasks.discover", lambda kind: [])
    goal = goals.get("android-attack")
    result = goals.run_goal(goal.key, log=lambda _m: None, install=False)
    assert result["outcome"] in ("skipped", "partial")
    assert result["note"]


@pytest.fixture()
def app():
    if not gui.available():
        pytest.skip("Tkinter unavailable")
    import tkinter as tk
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    instance = gui.App(root)
    root.update()
    try:
        yield instance, root
    finally:
        root.destroy()


def test_gui_builds_a_card_for_every_primary_goal(app):
    instance, _root = app
    assert len(instance.cards) == len(goals.PRIMARY)
    assert set(instance.cards) == set(goals.PRIMARY)
    for card in instance.cards.values():
        assert card.badge.cget("text").startswith(("READY", "NEEDS"))


def test_gui_runs_a_module_and_streams_output(app):
    instance, _root = app
    instance.run_module("core.devices", {})
    instance.worker.join(90)
    instance._pump()
    assert "finished" in instance.status.cget("text")
    body = instance.output.get("1.0", "end")
    assert "core.devices" in body


def test_card_click_runs_goal_without_tk_thread_error(app, monkeypatch):
    instance, _root = app
    seen: dict = {}

    def fake_run(key, log=None, progress=None, install=True):
        seen.update(key=key, install=install)
        return {"goal": key, "title": key, "outcome": "done", "steps": []}

    monkeypatch.setattr(gui.goals, "run_goal", fake_run)
    instance.run_goal("windows-takeover")
    instance.worker.join(20)
    instance._pump()
    body = instance.output.get("1.0", "end")
    assert seen["key"] == "windows-takeover"
    assert "main thread" not in body
    assert "done" in instance.status.cget("text")

def test_installer_uses_the_cyberdeck_name_and_new_icon():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    script = (root / "packaging" / "install_windows.ps1").read_text(
        encoding="utf-8", errors="replace")
    assert "Cyberdeck.lnk" in script
    assert "Cyberdeck Dashboard.lnk" in script
    assert (root / "packaging" / "cyberdeck.ico").is_file()
    spec = (root / "packaging" / "omni.spec").read_text(encoding="utf-8")
    assert "cyberdeck.ico" in spec


def test_goal_step_timeout_returns_quickly(monkeypatch):
    import time
    from omni.core import goals as goal_mod

    class Slow:
        def missing(self):
            return []

        def run(self):
            time.sleep(2)
            return ["late"]

    monkeypatch.setattr(goal_mod.registry, "build", lambda *a, **k: Slow())
    started = time.time()
    value, error = goal_mod._call("slow.module", {}, timeout=1)
    assert value is None and isinstance(error, TimeoutError)
    assert time.time() - started < 1.8
