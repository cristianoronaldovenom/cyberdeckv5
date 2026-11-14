"""Planner tests: chains resolve, blockers are reported, nothing is executed."""

import pytest

from omni.core.modules import plan as plan_mod


def test_every_trade_has_an_ordered_chain():
    for name, steps in plan_mod.TRADES.items():
        assert steps, name
        for label, argv, needs in steps:
            assert label and argv.startswith("omni run ")
            assert isinstance(needs, tuple)


def test_plan_covers_the_installable_trades():
    assert {"wifi", "car", "rf", "android", "ios"} <= set(plan_mod.TRADES)


def test_step_state_ready_when_tools_exist(monkeypatch):
    monkeypatch.setattr(plan_mod.proc, "has", lambda tool: True)
    ready, reason = plan_mod.step_state(("aireplay-ng",))
    assert ready and reason == ""


def test_step_state_names_the_missing_tool(monkeypatch):
    monkeypatch.setattr(plan_mod.proc, "has", lambda tool: tool != "nmap")
    ready, reason = plan_mod.step_state(("nmap",))
    assert not ready and "nmap" in reason


def test_step_state_marks_root_requirement(monkeypatch):
    monkeypatch.setattr(plan_mod.proc, "has", lambda tool: True)
    monkeypatch.setattr(plan_mod.os, "name", "posix")
    monkeypatch.setattr(plan_mod.os, "geteuid", lambda: 1000, raising=False)
    ready, reason = plan_mod.step_state((), root_needed=True)
    assert not ready and reason == "needs root"


def test_plan_module_reports_counts(monkeypatch, capsys):
    monkeypatch.setattr(plan_mod.proc, "has", lambda tool: False)
    result = plan_mod.Plan(TRADE="ios").execute()
    assert result["blocked"] + result["ready"] == result["total"] > 0
    # `ios.record` replays a local file, so it stays ready with no tools at all
    assert result["ready"] >= 1


def test_plan_all_trades_runs(monkeypatch):
    monkeypatch.setattr(plan_mod.proc, "has", lambda tool: True)
    result = plan_mod.Plan(TRADE="all").execute()
    assert result["total"] >= len(plan_mod.TRADES)


def test_plan_rejects_an_unknown_trade():
    with pytest.raises(ValueError):
        plan_mod.Plan(TRADE="nope").set("TRADE", "nope")


def test_plan_prints_commands_not_just_labels(monkeypatch, capsys):
    monkeypatch.setattr(plan_mod.proc, "has", lambda tool: True)
    plan_mod.Plan(TRADE="car").execute()
    out = capsys.readouterr().out
    assert "omni run car.unlock" in out
