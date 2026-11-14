"""Tree-driven Android takeover: the flow grammar, the view tree, the streams.

No device: the uiautomator dump and both live streams are text, so they are
parsed from fixed samples the way they arrive off a phone.
"""

import pytest

from omni.android import events, ui
from omni.core import flow

DUMP = """UI hierchary dumped to: /dev/tty
<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="Sign in" resource-id="com.example:id/login"
        class="android.widget.Button" package="com.example"
        content-desc="" clickable="true" enabled="true"
        bounds="[100,200][300,260]"/>
  <node index="1" text="Password" resource-id="com.example:id/pw"
        class="android.widget.EditText" package="com.example"
        content-desc="" clickable="true" enabled="true"
        bounds="[100,300][500,360]"/>
  <node index="2" text="" resource-id="" class="android.widget.TextView"
        package="com.example" content-desc="Search" clickable="false"
        enabled="true" bounds="[0,0][100,100]"/>
</hierarchy>
"""


# -- the shared script grammar ----------------------------------------------

def test_a_script_splits_on_newlines_and_semicolons_but_not_inside_quotes():
    chunks = flow.split('tap "a;b"; sleep 1  # note\nkey enter')
    assert [chunk for _, chunk in chunks] == ['tap "a;b"', "sleep 1",
                                              "key enter"]
    assert chunks[0][0] == 1 and chunks[2][0] == 2


def test_parse_keeps_quoted_arguments_whole():
    steps = flow.parse('tap "Sign in" 540,1200\ntype "a b"')
    assert [step.verb for step in steps] == ["tap", "type"]
    assert steps[0].args == ("Sign in", "540,1200")
    assert steps[1].arg(0) == "a b"


def test_parse_validates_the_vocabulary_when_asked():
    with pytest.raises(ValueError):
        flow.parse("teleport 1,2", verbs=("tap", "type"))
    assert flow.parse("# nothing but a comment") == []
    with pytest.raises(ValueError):
        flow.parse('tap "unbalanced')


def test_execute_reports_each_step_and_stops_on_the_first_failure():
    steps = flow.parse("tap a\ntap boom\ntap c")
    seen = []

    def handler(step):
        if step.arg(0) == "boom":
            raise RuntimeError("no such node")
        return step.arg(0)

    report = flow.execute(steps, {"tap": handler}, observer=seen.append)
    assert report["ok"] is False and report["ran"] == 2
    assert report["failed"] == 1
    assert "no such node" in report["results"][1]["error"]
    assert [row["step"] for row in seen] == ["tap a", "tap boom"]


def test_a_step_without_a_handler_fails_alone():
    report = flow.execute(flow.parse("swipe up"), {}, stop_on_error=False)
    assert report["failed"] == 1
    assert "swipe" in report["results"][0]["error"]





# -- the view tree ----------------------------------------------------------

def test_bounds_and_centre_come_from_the_dump():
    assert ui.parse_bounds("[100,200][300,260]") == (100, 200, 300, 260)
    assert ui.parse_bounds("junk") == (0, 0, 0, 0)
    nodes = ui.parse_dump(DUMP)
    login = ui.select(nodes, text="sign in")
    assert login is not None and login.centre == (200, 230)
    assert login.area == 200 * 60


def test_a_label_can_come_from_text_or_a_content_description():
    nodes = ui.parse_dump(DUMP)
    assert ui.labels(nodes) == ["Sign in", "Password", "Search"]
    assert ui.select(nodes, text="Search").desc == "Search"


def test_pick_prefers_the_clickable_node_a_human_meant():
    nodes = ui.parse_dump(DUMP)
    hits = ui.find(nodes, text="com.example")
    assert len(hits) == 2                     # the id is on two nodes
    assert ui.pick(hits).clickable is True
    assert [node.label for node in ui.find(nodes, cls="EditText")] == [
        "Password"]
    assert ui.find(nodes, clickable=False)[0].label == "Search"


def test_an_empty_or_broken_dump_is_reported_not_guessed():
    assert ui.parse_dump("UI hierchary dumped to: /dev/tty") == []
    assert ui.parse_dump("<hierarchy rotation='0'/>") == []
    with pytest.raises(ValueError):
        ui.parse_dump("<hierarchy><node")
    assert ui.select(ui.parse_dump(DUMP), text="nothing here") is None


# -- the live streams -------------------------------------------------------

GETEVENT = """/dev/input/event3: EV_KEY       KEY_A                DOWN
/dev/input/event3: EV_KEY       KEY_A                UP
/dev/input/event1: 0001 001e 00000001
/dev/input/event1: 0001 001e 00000000
/dev/input/event2: EV_ABS       ABS_MT_POSITION_X    00000123
add device 1: /dev/input/event3
"""


def test_getevent_parses_named_and_numeric_events():
    parsed = events.parse_getevent(GETEVENT)
    assert len(parsed) == 5
    assert parsed[0].code == "KEY_A" and parsed[0].down is True
    assert parsed[2].code == "KEY_A"          # numeric form still resolves
    assert events.is_key(parsed[4]) is False


def test_typed_text_survives_shift_and_backspace():
    stream = events.parse_getevent("""
/dev/input/event3: EV_KEY KEY_LEFTSHIFT DOWN
/dev/input/event3: EV_KEY KEY_H DOWN
/dev/input/event3: EV_KEY KEY_LEFTSHIFT UP
/dev/input/event3: EV_KEY KEY_I DOWN
/dev/input/event3: EV_KEY KEY_BACKSPACE DOWN
/dev/input/event3: EV_KEY KEY_O DOWN
/dev/input/event3: EV_KEY KEY_ENTER DOWN
""")
    assert events.decode_text(stream) == "Ho\n"
    assert events.key_counts(stream)["KEY_H"] == 1


def test_notifications_become_rows_with_their_body_text():
    dump = """
NotificationRecord(0x7f8c pkg=com.whatsapp userid=0 id=5 tag=null
  channel=msg importance=3 when=1700000000)
    android.title=String (Alice)
    android.text=String (see you at 8)
NotificationRecord(0x7f8d pkg=com.bank userid=0 id=9 tag=null)
    android.title=String (Code)
    android.text=SpannableString (482913)
    android.title=String (ignored duplicate)
"""
    notes = events.parse_notifications(dump)
    assert [note["package"] for note in notes] == ["com.whatsapp", "com.bank"]
    assert notes[0]["title"] == "Alice" and notes[0]["text"] == "see you at 8"
    assert notes[1]["text"] == "482913" and notes[1]["id"] == 9
    assert events.notification_rows(notes)[1][2] == "482913"
    assert events.parse_notifications("nothing") == []


def test_android_takeover_modules_are_registered():
    from omni.core.module import registry

    names = {module.NAME for module in registry.all("android")}
    assert {"android.ui", "android.automate", "android.keylog",
            "android.notify"} <= names
