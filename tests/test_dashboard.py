"""Dashboard model + tab tests: no terminal needed."""

import pytest

from omni.core import dashboard
from omni.core.dashboard import Model, TABS, parse_overrides


def make(monkeypatch, have=True):
    mods = {}
    for fam, _title, _hint in TABS:
        mods[fam] = [(f"{fam}.a", "first"), (f"{fam}.b", "second")]
    inst = Model(mods, have_tool=lambda tool: have)
    needs = {}
    for fam, _title, _hint in TABS:
        needs[f"{fam}.a"] = ("adir",)
        needs[f"{fam}.b"] = ()
    inst.set_needs(needs)
    inst.tab = 1                     # Home is the first tab; use a trade here
    return inst


def test_tabs_cover_the_asked_for_trades():
    families = {fam for fam, _t, _h in TABS}
    assert {"wifi", "rf", "car", "android", "ios", "windows", "brute"} <= families


def test_tabs_have_titles_and_hints():
    for family, title, hint in TABS:
        assert family and title and hint


def test_default_tab_is_home():
    inst = Model({}, have_tool=lambda tool: True)
    assert inst.family == TABS[0][0] == "home"
    assert inst.selected.action and inst.selected.name == "action.auto"


def test_home_actions_resolve_to_modules():
    inst = Model({}, have_tool=lambda tool: True)
    module, options = inst.target()
    assert module == "core.auto" and options["PROFILE"] == "safe"
    inst.cursor["home"] = 1
    assert inst.target()[1]["PROFILE"] == "full"


def test_tab_cycling_wraps_both_ways():
    inst = make(None)
    start = inst.tab
    for _ in range(len(TABS)):
        inst.next_tab()
    assert inst.tab == start
    inst.prev_tab()
    assert inst.tab == (start - 1) % len(TABS)


def test_rows_list_the_active_tab_only():
    inst = make(None)
    names = [row.name for row in inst.rows()]
    assert names == [f"{TABS[1][0]}.a", f"{TABS[1][0]}.b"]


def test_missing_tools_mark_a_row_not_ready():
    inst = make(None, have=False)
    rows = inst.rows()
    assert rows[0].missing == ["adir"]
    assert rows[0].mark == "!"
    assert rows[1].ready and rows[1].mark == "+"


def test_search_filters_both_fields():
    inst = make(None)
    inst.set_search("second")
    assert [r.name for r in inst.rows()] == [f"{TABS[1][0]}.b"]


def test_search_resets_the_cursor():
    inst = make(None)
    inst.move(1)
    inst.set_search("first")
    assert inst.cursor[inst.family] == 0


def test_move_wraps_and_keeps_per_tab_cursors():
    inst = make(None)
    inst.move(-1)
    assert inst.cursor[inst.family] == 1
    before = inst.cursor[inst.family]
    inst.next_tab()
    inst.move(1)
    assert inst.cursor[inst.family] == 1
    inst.prev_tab()
    assert inst.cursor[inst.family] == before


def test_command_includes_overrides():
    inst = make(None)
    inst.values.extend(["SSID=x", "COUNT=3"])
    assert inst.command() == ["run", f"{TABS[1][0]}.a", "SSID=x", "COUNT=3"]


def test_command_text_is_shell_quoted():
    inst = make(None)
    inst.values.append("SSID=two words")
    assert "'SSID=two words'" in inst.command_text()


def test_parse_overrides_normalises_case():
    assert parse_overrides(["ssid=x"]) == {"SSID": "x"}


@pytest.mark.parametrize("bad", ["novalue", "=x"])
def test_parse_overrides_rejects_junk(bad):
    with pytest.raises(ValueError):
        parse_overrides([bad])


def test_clear_values_empties_overrides():
    inst = make(None)
    inst.values.append("A=1")
    inst.clear_values()
    assert inst.values == []


def test_log_keeps_a_bounded_buffer():
    inst = make(None)
    inst.log("\n".join(str(i) for i in range(50)), limit=10)
    assert len(inst.output) == 10


def test_ready_count_counts_ready_rows_only():
    inst = make(None, have=True)
    assert inst.ready_count == 2
    assert make(None, have=False).ready_count == 1


def test_selection_points_at_the_cursor():
    inst = make(None)
    inst.move(1)
    assert inst.selected.name == f"{TABS[1][0]}.b"


def test_empty_tab_has_no_selection_and_raises_on_command():
    inst = Model({"wifi": []}, have_tool=lambda t: True)
    inst.set_needs({})
    inst.tab = 1
    assert inst.selected is None
    with pytest.raises(ValueError, match="nothing selected"):
        inst.command()


def test_modules_helper_matches_dashboard_fields():
    assert dashboard.Row("a", "b", []).mark == "+"

