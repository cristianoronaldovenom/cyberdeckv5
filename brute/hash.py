"""Offline hash cracking: identification, hashcat modes, john, hydra auth."""

from __future__ import annotations

import os
import re

from omni.core import config, proc

__all__ = ["MODES", "identify", "hashcat", "john", "hydra", "hydra_services"]


#: regex -> (label, hashcat mode, john format)
MODES: list[tuple[str, str, str, str]] = [
    (r"^[a-f0-9]{32}$", "MD5", "0", "raw-md5"),
    (r"^[a-f0-9]{40}$", "SHA1", "100", "raw-sha1"),
    (r"^[a-f0-9]{56}$", "SHA224", "1300", "raw-sha224"),
    (r"^[a-f0-9]{64}$", "SHA256", "1400", "raw-sha256"),
    (r"^[a-f0-9]{96}$", "SHA384", "10800", "raw-sha384"),
    (r"^[a-f0-9]{128}$", "SHA512", "1700", "raw-sha512"),
    (r"^\$2[aby]\$", "bcrypt", "3200", "bcrypt"),
    (r"^\$1\$", "MD5crypt", "500", "md5crypt"),
    (r"^\$5\$", "SHA256crypt", "7400", "sha256crypt"),
    (r"^\$6\$", "SHA512crypt", "1800", "sha512crypt"),
    (r"^\$argon2", "Argon2", "34100", "argon2"),
    (r"^\$pbkdf2", "PBKDF2", "10900", "pbkdf2"),
    (r"^WPA\*", "WPA-PMKID", "22000", "wpapmk"),
    (r"^[a-f0-9]{16}$", "MySQL/CRC", "200", "mysql"),
    (r"^\$NT\$|^[a-f0-9]{32}$", "NTLM-ish", "1000", "nt"),
]

HYDRA_SERVICES = ("ssh", "ftp", "rdp", "smb", "telnet", "http-get",
                  "https-get", "http-post-form", "mysql", "postgres", "vnc",
                  "imap", "pop3", "smtp", "ldap2")


def identify(hash_value: str) -> dict:
    """Guess the algorithm of a single hash string."""
    value = (hash_value or "").strip()
    for pattern, label, mode, john_format in MODES:
        if re.search(pattern, value):
            return {"hash": value, "kind": label, "hashcat_mode": mode,
                    "john_format": john_format}
    return {"hash": value, "kind": "unknown", "hashcat_mode": None,
            "john_format": None}


def identify_file(path: str, sample: int = 3) -> list[dict]:
    out = []
    with open(os.path.expanduser(path), "r", encoding="utf-8",
              errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= sample:
                break
            if line.strip():
                out.append(identify(line))
    return out


def hashcat(hashfile: str, mode: str | None = None, wordlist: str | None = None,
            mask: str | None = None, rules: str | None = None) -> dict:
    """Run hashcat; ``mode`` auto-detected from the file when omitted."""
    binary = str(config.get_value("brute.hashcat_binary", "hashcat"))
    proc.require(binary, "apt install hashcat")
    if mode is None:
        guesses = identify_file(hashfile)
        modes = [g["hashcat_mode"] for g in guesses if g["hashcat_mode"]]
        if not modes:
            raise ValueError("could not identify the hash type — pass MODE")
        mode = modes[0]
    outdir = config.output_dir("brute/hashcat")
    outfile = os.path.join(outdir, "recovered.txt")
    if mask:
        argv = [binary, "-m", str(mode), "-a", "3", hashfile, mask]
    else:
        target = wordlist or str(config.get_value("wifi.wordlist", ""))
        if not target:
            raise ValueError("need a WORDLIST or a MASK")
        argv = [binary, "-m", str(mode), "-a", "0", hashfile, target]
        if rules:
            argv += ["-r", rules]
    argv += ["--potfile-path", os.path.join(outdir, "omni.pot"),
             "--outfile", outfile, "--outfile-format", "2",
             "--status", "--status-timer", "5"]
    res = proc.run(argv, timeout=7200)
    keys = []
    if os.path.exists(outfile):
        with open(outfile, "r", encoding="utf-8", errors="replace") as fh:
            keys = [ln.strip().split("\t")[-1] for ln in fh if ln.strip()]
    return {"found": bool(keys), "keys": keys, "mode": str(mode),
            "status": res.lines()[-4:]}


def john(hashfile: str, wordlist: str | None = None,
         john_format: str | None = None, rules: bool = True) -> dict:
    """Run john; ``john --show`` harvests whatever the run recovered."""
    binary = str(config.get_value("brute.john_binary", "john"))
    proc.require(binary, "apt install john")
    if john_format is None:
        guesses = identify_file(hashfile)
        formats = [g["john_format"] for g in guesses if g["john_format"]]
        john_format = formats[0] if formats else None
    argv = [binary]
    if john_format:
        argv += [f"--format={john_format}"]
    argv.append(hashfile)
    if wordlist:
        argv += [f"--wordlist={os.path.expanduser(wordlist)}"]
    if rules:
        argv.append("--rules")
    run_res = proc.run(argv, timeout=7200)
    show = proc.run([binary, "--show", hashfile], timeout=300)
    cracked = [line for line in show.lines() if ":" in line and
               not line.startswith("0 password")]
    return {"found": bool(cracked), "cracked": cracked,
            "format": john_format, "tail": run_res.lines()[-4:]}


def hydra(target: str, service: str = "ssh", user: str | None = None,
          userlist: str | None = None, password: str | None = None,
          passlist: str | None = None, port: int | None = None,
          threads: int | None = None, extra: list[str] | None = None,
          stop_on_first: bool = True) -> dict:
    """Run hydra against a network service."""
    binary = str(config.get_value("brute.hydra_binary", "hydra"))
    proc.require(binary, "apt install hydra")
    if service not in HYDRA_SERVICES:
        raise ValueError(f"unsupported service {service!r}")
    argv = [binary, "-I"]
    if stop_on_first:
        argv.append("-f")
    argv += ["-t", str(int(threads or config.get_value("brute.threads", 8)))]
    if port:
        argv += ["-s", str(int(port))]
    argv.append(target)
    argv.append(service)
    if userlist:
        argv += ["-L", os.path.expanduser(userlist)]
    elif user:
        argv += ["-l", user]
    if passlist:
        argv += ["-P", os.path.expanduser(passlist)]
    elif password:
        argv += ["-p", password]
    if extra:
        argv += list(extra)
    res = proc.run(argv, timeout=7200)
    found = []
    for line in res.lines():
        m = re.search(r"\[\d+\]\[(\w+)\]\s+host:\s*\S+\s+login:\s*(\S+)\s+"
                      r"password:\s*(\S+)", line)
        if m:
            found.append({"service": m.group(1), "login": m.group(2),
                          "password": m.group(3)})
    return {"found": bool(found), "credentials": found,
            "tail": res.lines()[-5:]}


def hydra_services() -> list[str]:
    return list(HYDRA_SERVICES)

