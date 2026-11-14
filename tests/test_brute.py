"""Brute-force engine tests: keyspaces, mutation, hashes, radio, HTTP."""

import http.server
import threading

import pytest

from omni.brute import hash as hashmod
from omni.brute import http as httpmod
from omni.brute import space, words


# -- masks and keyspaces ----------------------------------------------------

def test_parse_mask_expands_placeholders():
    assert space.parse_mask("?d?d-a") == ["0123456789", "0123456789", "-", "a"]


def test_parse_mask_keeps_escaped_literal():
    assert space.parse_mask("??d") == ["?", "d"]


def test_keyspace_size_multiplies_groups():
    assert space.keyspace_size("?d?d?d?d") == 10_000
    assert space.keyspace_size("?l?u") == 26 * 26


def test_mask_generates_in_order():
    assert list(space.mask("?d-a")) == [f"{d}-a" for d in "0123456789"]


def test_numeric_pads_and_respects_range():
    assert list(space.numeric(3, 7, 11)) == ["007", "008", "009", "010"]


def test_cap_stops_at_limit():
    assert len(list(space.cap(space.mask("?d?d?d?d"), 25))) == 25


def test_is_plausible_uses_limit():
    assert space.is_plausible("?d?d?d?d", limit=20_000)
    assert not space.is_plausible("?a?a?a?a?a", limit=20_000)


# -- wordlist mutation -----------------------------------------------------

def test_read_words_skips_blanks_and_comments(tmp_path):
    path = tmp_path / "w.txt"
    path.write_text("alpha\n\n# comment\nbeta\n", encoding="utf-8")
    assert list(words.read_words(str(path))) == ["alpha", "beta"]


def test_load_accepts_inline_lists():
    assert list(words.load("one, two;three")) == ["one", "two", "three"]


def test_mutate_orders_cheap_variants_first():
    out = list(words.mutate(["pass"], suffixes=("", "1")))
    assert out[:2] == ["pass", "pass1"]
    assert "Pass" in out and "PASS" in out


def test_mutate_applies_leet():
    out = list(words.mutate(["pass"], suffixes=("",)))
    assert "p@$$" in out


def test_mutate_dedupes_and_caps():
    out = list(words.mutate(["a", "a"], limit=5))
    assert len(out) == len(set(out)) == 5


# -- hash identification ---------------------------------------------------

@pytest.mark.parametrize("value,kind,mode", [
    ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5", "0"),
    ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA1", "100"),
    ("$2b$12$abcdefghijklmnopqrstuv", "bcrypt", "3200"),
    ("WPA*01*abc", "WPA-PMKID", "22000"),
])
def test_identify_detects_common_hashes(value, kind, mode):
    out = hashmod.identify(value)
    assert out["kind"] == kind
    assert out["hashcat_mode"] == mode


def test_identify_unknown_hash():
    out = hashmod.identify("not-a-hash!!")
    assert out["kind"] == "unknown"
    assert out["hashcat_mode"] is None


def test_identify_file_samples_only(tmp_path):
    path = tmp_path / "h.txt"
    path.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n" * 5, encoding="utf-8")
    assert len(hashmod.identify_file(str(path))) == 3


# -- HTTP form parsing and brute force -------------------------------------

LOGIN_PAGE = """
<html><body>
<form method="post" action="/login">
  <input type="hidden" name="csrf" value="tok123">
  <input type="text" name="user">
  <input type="password" name="pass">
  <input type="submit" value="Go">
</form>
</body></html>
"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib naming
        self._send(LOGIN_PAGE)

    def do_POST(self):  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        ok = "pass=s3cret" in body
        self._send("<html><body>Welcome back</body></html>" if ok
                   else "<html><body>Invalid password, try again please</body></html>")

    def _send(self, text):
        payload = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}/"
    httpd.shutdown()


def test_parse_form_extracts_action_and_fields():
    form = httpmod.parse_form(LOGIN_PAGE, "http://x.test/login")
    assert form.method == "POST"
    assert form.action == "http://x.test/login"
    assert form.fields == {"csrf": "tok123", "user": "", "pass": ""}


def test_parse_form_needs_a_password_field():
    assert httpmod.parse_form("<form><input name='q'></form>", "http://x/") is None


def test_guess_fields_from_hints():
    form = httpmod.parse_form(LOGIN_PAGE, "http://x/")
    assert httpmod.guess_fields(form) == ("user", "pass")


def test_guess_fields_handles_named_variants():
    html = ('<form action="/l"><input name="csrf" type="hidden">'
            '<input name="login_email"><input name="passwd" type="password">'
            '</form>')
    form = httpmod.parse_form(html, "http://x/")
    assert httpmod.guess_fields(form) == ("login_email", "passwd")


def test_guess_marker_finds_failure_text():
    page = LOGIN_PAGE + "<div>Invalid password, try again</div>"
    assert httpmod._guess_marker(page) == "Invalid password, try again"


def test_guess_marker_empty_without_cue():
    assert httpmod._guess_marker(LOGIN_PAGE) == ""


def test_run_finds_the_right_password(server):
    form = httpmod.discover_form(server)
    assert form is not None
    hits = httpmod.run(form, ["wrong", "nope", "s3cret"], users=["admin"],
                       pass_field="pass", user_field="user", threads=2)
    assert [h.password for h in hits] == ["s3cret"]


def test_run_reports_nothing_on_full_miss(server):
    form = httpmod.discover_form(server)
    hits = httpmod.run(form, ["a", "b"], users=["admin"], pass_field="pass",
                       user_field="user", threads=2)
    assert hits == []

