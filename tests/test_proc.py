"""Subprocess plumbing: argv everywhere, no shell=True for user data."""

import sys

import pytest

from omni.core import proc


def test_proc_argv_no_shell(tmp_path):
    marker = "arg with spaces; rm -rf /"
    r = proc.run([sys.executable, "-c", "import sys; print(sys.argv[1])", marker])
    assert r.ok
    assert marker in r.text


def test_proc_has_reports_missing(fake_bin):
    assert proc.has("nmap")
    assert not proc.has("definitely-not-a-binary-omni")


def test_run_reports_failure():
    r = proc.run([sys.executable, "-c", "raise SystemExit(3)"])
    assert not r.ok

