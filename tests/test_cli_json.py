"""JSON output contract of the CLI."""

import json

import pytest

from omni import cli


def test_run_json_ok():
    rc = cli.main(["--json", "run", "news.user", "NAME=tlg"])
    assert rc == 0


def test_run_json_error():
    rc = cli.main(["--json", "run", "nope.doesnotexist"])
    assert rc == 1


def test_list_json_covers_all_families(capsys):
    cli.main(["--json", "list"])
    payload = json.loads(capsys.readouterr().out)
    fams = {m["family"] for m in payload}
    assert {"android", "windows", "pentest", "mobile", "news", "flip"} <= fams
    assert all(set(m) == {"name", "family", "description", "needs"}
               for m in payload)
