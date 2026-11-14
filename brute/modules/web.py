"""HTTP login brute force and network/offline cracking modules."""

from __future__ import annotations

import sys

from omni.brute import hash as hashmod
from omni.brute import http as httpmod
from omni.brute import space
from omni.core import config, console
from omni.core.module import Option
from omni.brute.modules._base import BruteModule

__all__ = ["Http", "Hashes", "Identify", "Hydra", "John"]


def _progress(attempt) -> None:
    console.ok(f"HIT {attempt.user}:{attempt.password} "
               f"(status {attempt.status}, {attempt.length} bytes)")


class Http(BruteModule):
    NAME = "brute.http"
    DESCRIPTION = "Brute force an HTTP login form (POST/GET, threaded)"
    OPTIONS = (Option("URL", "login page URL", "", required=True),
               Option("USER", "single username"),
               Option("USERS", "username list file or inline list"),
               Option("PASSWORDS", "password list file or inline list"),
               Option("MASK", "password mask instead of a list"),
               Option("MUTATE", "mutate the wordlist", "1"),
               Option("USER_FIELD", "username field name (auto-detected)"),
               Option("PASS_FIELD", "password field name (auto-detected)"),
               Option("RULE", "auto|status:CODE|contains:TEXT|delta:N", "auto"),
               Option("THREADS", "parallel requests"),
               Option("DELAY", "delay between requests (ms)"),
               Option("ALL", "keep going after the first hit"))

    def execute(self) -> dict:
        form = httpmod.discover_form(self.get("URL"))
        if form is None:
            raise RuntimeError("no login form with a password field found")
        auto_user, auto_pass = httpmod.guess_fields(form)
        user_field = self.get("USER_FIELD") or auto_user
        pass_field = self.get("PASS_FIELD") or auto_pass
        if not pass_field:
            raise RuntimeError("could not identify the password field")
        console.info(f"{form.method} {form.action} — user={user_field or '-'} "
                     f"pass={pass_field}")
        users = [u for u in ([self.get("USER")] +
                             (self.get("USERS").replace(",", " ").split()
                              if self.get("USERS") else [])) if u]
        candidates = list(self.candidates(self.get("MASK"), self.get("PASSWORDS"),
                                          "", self.get_bool("MUTATE", True)))
        console.info(f"{len(candidates):,} password(s) x {max(1, len(users))} user(s)")
        hits = httpmod.run(form, candidates,
                           user_field=user_field,
                           pass_field=pass_field,
                           users=users or [""], rule=self.get("RULE"),
                           threads=self.get_int("THREADS", 0) or None,
                           delay_ms=self.get_int("DELAY", 0),
                           stop_on_first=not self.get_bool("ALL", False),
                           progress=_progress)
        if not hits:
            console.warn("no valid credentials found")
        return {"found": bool(hits),
                "credentials": [{"user": h.user, "password": h.password}
                                for h in hits]}


class Identify(BruteModule):
    NAME = "brute.identify"
    DESCRIPTION = "Identify the algorithm and crack mode of a hash"
    OPTIONS = (Option("HASH", "hash string (blank = use FILE)"),
               Option("FILE", "file with hashes to inspect"))

    def execute(self) -> list[dict]:
        if self.get("FILE"):
            rows = hashmod.identify_file(self.get("FILE"))
        else:
            rows = [hashmod.identify(self.get("HASH"))]
        for row in rows:
            if row["kind"] == "unknown":
                console.warn(f"unidentified: {row['hash'][:40]}")
            else:
                console.ok(f"{row['kind']} — hashcat -m {row['hashcat_mode']}")
        return rows


class Hashes(BruteModule):
    NAME = "brute.hashes"
    DESCRIPTION = "Crack a hash file with hashcat (wordlist or mask)"
    OPTIONS = (Option("FILE", "hash file", "", required=True),
               Option("MODE", "hashcat mode (auto when blank)"),
               Option("WORDLIST", "wordlist path"),
               Option("MASK", "mask instead of a wordlist"),
               Option("RULES", "hashcat rule file"))

    def execute(self) -> dict:
        out = hashmod.hashcat(self.get("FILE"), self.get("MODE") or None,
                              self.get("WORDLIST") or None,
                              self.get("MASK") or None,
                              self.get("RULES") or None)
        if out["found"]:
            console.ok(f"{len(out['keys'])} hash(es) cracked: "
                       + ", ".join(out["keys"][:5]))
        else:
            console.warn("nothing cracked")
        return out


class Hydra(BruteModule):
    NAME = "brute.hydra"
    DESCRIPTION = "Online service brute force through hydra (ssh, ftp, rdp…)"
    NEEDS = ("hydra",)
    OPTIONS = (Option("TARGET", "host or IP", "", required=True),
               Option("SERVICE", "protocol to attack", "ssh",
                      choices=hashmod.HYDRA_SERVICES),
               Option("USER", "single username"),
               Option("USERLIST", "username list file"),
               Option("PASSWORD", "single password"),
               Option("PASSLIST", "password list file"),
               Option("PORT", "override port"),
               Option("THREADS", "parallel tasks"),
               Option("ALL", "do not stop at the first hit"))

    def execute(self) -> dict:
        out = hashmod.hydra(self.get("TARGET"), self.get("SERVICE"),
                            self.get("USER") or None,
                            self.get("USERLIST") or None,
                            self.get("PASSWORD") or None,
                            self.get("PASSLIST") or None,
                            self.get_int("PORT", 0) or None,
                            self.get_int("THREADS", 0) or None,
                            stop_on_first=not self.get_bool("ALL", False))
        for cred in out["credentials"]:
            console.ok(f"{cred['service']} {cred['login']}:{cred['password']}")
        if not out["found"]:
            console.warn("no credentials found")
        return out


class John(BruteModule):
    NAME = "brute.john"
    DESCRIPTION = "Crack a hash file with john the ripper"
    NEEDS = ("john",)
    OPTIONS = (Option("FILE", "hash file", "", required=True),
               Option("WORDLIST", "wordlist path"),
               Option("FORMAT", "john format (auto when blank)"),
               Option("NORULES", "skip --rules"))

    def execute(self) -> dict:
        out = hashmod.john(self.get("FILE"), self.get("WORDLIST") or None,
                           self.get("FORMAT") or None,
                           not self.get_bool("NORULES"))
        if out["found"]:
            for line in out["cracked"][:10]:
                console.ok(line)
        else:
            console.warn("nothing cracked")
        return out

