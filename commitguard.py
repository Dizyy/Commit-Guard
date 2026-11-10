#!/usr/bin/env python3
"""Commit Guard: block git commits and pushes that contain personal data.

Usage:
  python commitguard.py install       write pre-commit + pre-push hooks into this repo
  python commitguard.py install --global
                                      guard EVERY repo (sets global core.hooksPath;
                                      each repo's own .git/hooks still run after it)
  python commitguard.py uninstall --global
                                      remove the global core.hooksPath again
  python commitguard.py scan          scan staged changes (what the pre-commit hook runs)
  python commitguard.py test-config   show which private patterns loaded (masked)
  python commitguard.py --version     print the version

Your name, account email, username, PC name and country/language hints are detected
from the OS on every run (memory only). Optional extras: ~/.commitguard/private.toml.
Standard library only. Python 3.11+.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

__version__ = "1.0.0"
ALLOW_MARKER = "commitguard:allow"
HOOK_TAG = "# installed by commitguard"
PRIVATE_KEYS = {  # config key -> rule name
    "names": "private-name",
    "emails": "private-email",
    "pc_names": "private-pc-name",
    "home_ips": "private-home-ip",
    "words": "private-word",
}
BLOCKED_NAMES = {".env", "id_rsa", "handoff.md", "private.toml"}
BLOCKED_SUFFIXES = (".pem", ".key")

TEMPLATE = """\
# Commit Guard private patterns (OPTIONAL extras). NEVER commit this file.
# Your name, account email, username, PC name and country/language hints are auto-detected.
# Each entry: plain text = literal match (case-insensitive), "re:..." = Python regex.
names = []
emails = []
pc_names = []
home_ips = []
words = []
# Text that a rule matches but is fine to commit (same syntax):
allow = []
# true = 192.168.x.x addresses are allowed
allow_private_ips = false
# false = turn off auto-detection of your identity from the OS
auto_detect = true
"""


@dataclass
class Rule:
    name: str
    rx: re.Pattern
    ok: Callable[[str, "Config"], bool] | None = None  # True = match is allowed
    src: str = ""  # original config entry (private rules only)


@dataclass
class Config:
    path: Path
    loaded: bool = False
    rules: list[Rule] = field(default_factory=list)
    allow: list[re.Pattern] = field(default_factory=list)
    allow_src: list[str] = field(default_factory=list)
    allow_private_ips: bool = False


@dataclass
class Hit:
    where: str
    line: int | None
    rule: str
    text: str


# ---------------------------------------------------------------- built-in rules

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"


def _ip_ok(s: str, cfg: Config) -> bool:
    return s in ("127.0.0.1", "0.0.0.0") or (cfg.allow_private_ips and s.startswith("192.168."))


_PLACEHOLDER_PASSWORDS = {"password", "pass", "passwd", "pwd", "secret", "changeme", "xxx", "..."}


def _url_password_ok(s: str) -> bool:
    """Placeholders like ${DB_PASS}, <password>, ***, or the word 'password' are fine."""
    pw = s.split("://", 1)[1].rsplit("@", 1)[0].split(":", 1)[1]
    return (pw[0] in "$<{*%[" or pw.lower() in _PLACEHOLDER_PASSWORDS
            or set(pw) <= set("*x.") or len(pw) < 3)


BUILTIN_RULES = [
    Rule("windows-user-path", re.compile(r"\b[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s'\"`<>|:*?]+", re.I)),
    Rule("windows-user-path", re.compile(r"(?<![\w.])/[A-Za-z]/Users/[^/\s'\"`<>|:*?]+", re.I)),
    Rule("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
         lambda s, c: s.lower().endswith("@users.noreply.github.com")),
    Rule("ipv4", re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\.?\d)"), _ip_ok),
    Rule("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    Rule("sk-api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    Rule("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    Rule("env-secret", re.compile(
        r"^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY)[A-Z0-9_]*"
        r"=(['\"]?)[^\s'\"$<>(){}\[\]]{4,}\1\s*(?:#.*)?$")),
    # Keys by provider prefix (AI providers and common dev services).
    Rule("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    Rule("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    Rule("groq-key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    Rule("xai-key", re.compile(r"\bxai-[A-Za-z0-9]{40,}")),
    Rule("replicate-token", re.compile(r"\br8_[A-Za-z0-9]{30,}")),
    Rule("stripe-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
    Rule("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    Rule("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    Rule("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}")),
    Rule("bearer-token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*")),
    # scheme://user:password@host (database URLs, git remotes with a token in them).
    Rule("url-password", re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@'\"<>]*:([^\s/@'\"<>]+)@[\w.-]+"),
         lambda s, c: _url_password_ok(s)),
    # A secret-looking name assigned a quoted literal: JSON (.mcp.json, settings files), YAML,
    # code. The value must be 16+ chars with a letter and a digit and no spaces, so variables,
    # ${VARS}, <placeholders> and "your-key-here" texts pass.
    Rule("assigned-secret", re.compile(
        r"(?i)[\w.-]*(?:secret|token|passw(?:or)?d|api[_-]?key|access[_-]?key|auth[_-]?key)"
        r"[\w.-]*[\"']?\s*[:=]\s*([\"'])(?![A-Za-z][\w+.-]*://)"  # URLs (token_uri) are fine
        r"(?=[^\"'\s]*\d)(?=[^\"'\s]*[A-Za-z])"
        r"[^\s'\"<>${}()\[\]]{16,}\1")),
]


# ---------------------------------------------------------------- config

def config_path() -> Path:
    env = os.environ.get("COMMITGUARD_CONFIG")
    return Path(env) if env else Path.home() / ".commitguard" / "private.toml"


def _compile(entry: str) -> re.Pattern:
    if entry.startswith("re:"):
        return re.compile(entry[3:])
    return re.compile(re.escape(entry), re.I)


def load_config(path: Path | None = None, auto: bool | None = None) -> Config:
    """Private config file is optional. Auto-detected identity rules are added unless
    disabled (auto=False, env COMMITGUARD_AUTO=0, or auto_detect = false in the file)."""
    path = path or config_path()
    cfg = Config(path=path)
    data: dict = {}
    if path.is_file():
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            for key, rule_name in PRIVATE_KEYS.items():
                for entry in data.get(key, []):
                    if entry:
                        cfg.rules.append(Rule(rule_name, _compile(str(entry)), src=str(entry)))
            for entry in data.get("allow", []):
                if entry:
                    cfg.allow.append(_compile(str(entry)))
                    cfg.allow_src.append(str(entry))
            cfg.allow_private_ips = bool(data.get("allow_private_ips", False))
        except (tomllib.TOMLDecodeError, re.error, OSError, TypeError) as e:
            # Fail closed: a broken config must not silently let data through.
            print(f"commitguard: error: cannot read {path}: {e}", file=sys.stderr)
            sys.exit(1)
        cfg.loaded = True
    if auto is None:
        auto = os.environ.get("COMMITGUARD_AUTO") != "0" and data.get("auto_detect", True)
    if auto:
        cfg.rules += auto_rules(detect_identity())
    return cfg


# ---------------------------------------------------------------- auto-detection
# Reads who you are from the OS on every run. Values live in memory only: never written
# to disk, never printed unmasked.

GENERIC_USERS = {"user", "admin", "administrator", "owner", "root", "guest", "pc", "home",
                 "dev", "default", "test", "ubuntu", "vagrant", "runner"}
# Letters that mostly show up in one language family = language/country hint.
# Written as \u escapes so this file itself contains no such letters.
LANG_LETTERS = {"sv": "\u00e5\u00e4\u00f6", "fi": "\u00e4\u00f6",
                "de": "\u00e4\u00f6\u00fc\u00df", "da": "\u00e6\u00f8\u00e5",
                "nb": "\u00e6\u00f8\u00e5", "nn": "\u00e6\u00f8\u00e5",
                "no": "\u00e6\u00f8\u00e5", "is": "\u00fe\u00f0\u00e6",
                "pl": "\u0105\u0119\u0142\u0144\u015b\u017a\u017c",
                "cs": "\u011b\u0161\u010d\u0159\u017e\u016f\u0148",
                "tr": "\u011f\u0131\u015f", "hu": "\u0151\u0171", "ro": "\u0103\u0219\u021b",
                "lt": "\u0105\u010d\u0119\u0117\u012f\u0161\u0173\u016b\u017e",
                "lv": "\u0101\u010d\u0113\u0123\u012b\u0137\u013c\u0146\u0161\u016b\u017e"}


def _empty_identity() -> dict[str, list[str]]:
    return {k: [] for k in ("names", "emails", "users", "hosts", "words", "regions", "langs")}


def _word(s: str) -> re.Pattern:
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(s) + r"(?![A-Za-z0-9])", re.I)


def auto_rules(ident: dict[str, list[str]]) -> list[Rule]:
    """Turn detected identity values into rules (pure function, testable with fake data)."""
    rules: list[Rule] = []

    def add(name: str, rx: re.Pattern, src: str) -> None:
        if all(r.rx.pattern != rx.pattern for r in rules):
            rules.append(Rule(name, rx, src="auto:" + src))

    for n in ident.get("names", []):
        n = n.strip()
        if len(n) >= 3:
            add("auto-name", _word(n), n)
            for part in n.split():
                if len(part) >= 4:
                    add("auto-name", _word(part), part)
    for e in ident.get("emails", []):
        if "@" in e and not e.lower().endswith("@users.noreply.github.com"):
            add("auto-email", re.compile(re.escape(e.strip()), re.I), e.strip())
    for u in ident.get("users", []):
        if len(u) >= 3 and u.lower() not in GENERIC_USERS:
            add("auto-username", _word(u), u)
    for h in ident.get("hosts", []):
        if len(h) >= 3 and h.lower() not in ("localhost", "localhost.localdomain"):
            add("auto-pc-name", _word(h), h)
    for w in ident.get("words", []):
        if len(w) >= 3:
            add("auto-country-hint", _word(w), w)
    for r in ident.get("regions", []):
        if re.fullmatch(r"[A-Z]{2}", r):  # locale tags like xx-YY / xx_YY
            add("auto-country-hint", re.compile(rf"(?<![A-Za-z])[a-z]{{2}}[-_]{r}(?![A-Za-z])"),
                f"xx-{r}")
    letters = "".join(sorted({c for lang in ident.get("langs", [])
                              for c in LANG_LETTERS.get(lang, "")}))
    if letters:  # upper() only where it stays one letter (German sharp s uppercases to "SS")
        chars = {c for ch in letters for c in (ch, ch.upper()) if len(c) == 1}
        add("auto-language-letter",
            re.compile("[" + "".join(re.escape(c) for c in sorted(chars)) + "]"), letters)
    return rules


def detect_identity() -> dict[str, list[str]]:
    ident = _empty_identity()
    try:
        import getpass
        import socket
        ident["users"].append(getpass.getuser())
        ident["hosts"].append(socket.gethostname().split(".")[0])
        if os.environ.get("COMPUTERNAME"):
            ident["hosts"].append(os.environ["COMPUTERNAME"])
    except Exception:
        pass
    try:
        if sys.platform == "win32":
            _detect_windows(ident)
        else:
            _detect_posix(ident)
    except Exception:  # detection is best effort; built-in rules still run
        pass
    return ident


def _detect_posix(ident: dict[str, list[str]]) -> None:
    import locale
    import pwd
    gecos = pwd.getpwuid(os.getuid()).pw_gecos.split(",")[0]
    if gecos:
        ident["names"].append(gecos)
    tag = (locale.getlocale()[0] or os.environ.get("LANG", "")).split(".")[0]
    if "_" in tag:
        lang, region = tag.split("_", 1)
        ident["regions"].append(region)
        if lang != "en":
            ident["langs"].append(lang)


def _detect_windows(ident: dict[str, list[str]]) -> None:
    import ctypes
    from ctypes import wintypes
    user = ident["users"][0] if ident["users"] else os.environ.get("USERNAME", "")

    netapi = ctypes.WinDLL("netapi32")
    netapi.NetUserGetInfo.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                      ctypes.POINTER(ctypes.c_void_p)]
    for level, idx, key in ((10, 3, "names"), (24, 2, "emails")):
        # USER_INFO_10.full_name; USER_INFO_24.internet_principal_name (Microsoft account)
        buf = ctypes.c_void_p()
        if netapi.NetUserGetInfo(None, user, level, ctypes.byref(buf)) == 0 and buf.value:
            val = ctypes.cast(buf, ctypes.POINTER(ctypes.c_wchar_p))[idx]
            if val:
                ident[key].append(val)
            netapi.NetApiBufferFree(buf)

    secur = ctypes.WinDLL("secur32")
    b = ctypes.create_unicode_buffer(256)
    n = wintypes.ULONG(256)
    if secur.GetUserNameExW(3, b, ctypes.byref(n)) and b.value:  # NameDisplay
        ident["names"].append(b.value)

    k32 = ctypes.WinDLL("kernel32")

    def info(tag: str, lctype: int) -> str:
        out = ctypes.create_unicode_buffer(100)
        return out.value if k32.GetLocaleInfoEx(tag, lctype, out, 100) else ""

    b = ctypes.create_unicode_buffer(85)
    k32.GetUserDefaultLocaleName(b, 85)
    default = b.value  # e.g. xx-YY: YY = region = where you are
    region = default.split("-")[-1] if "-" in default else ""
    langs = {default.split("-")[0]}
    user32 = ctypes.WinDLL("user32")
    count = user32.GetKeyboardLayoutList(0, None)
    if count > 0:
        arr = (ctypes.c_void_p * count)()
        user32.GetKeyboardLayoutList(count, arr)
        for hkl in arr:
            k32.LCIDToLocaleName((hkl or 0) & 0xFFFF, b, 85, 0)
            if b.value:
                langs.add(b.value.split("-")[0])
    if region:
        ident["regions"].append(region)
        ident["words"] += [info(default, 0x1002), info(default, 0x8)]  # country, EN + native
    for lang in sorted(langs - {"en", ""}):
        ident["langs"].append(lang)
        tag = f"{lang}-{region}" if region else lang
        ident["words"] += [info(tag, 0x1001), info(tag, 0x4), info(tag, 0x8)]
    ident["words"] = [w for w in dict.fromkeys(ident["words"]) if w]


# ---------------------------------------------------------------- scanning

def mask(s: str) -> str:
    return s[:2] + "***"


def scan_text(text: str, cfg: Config) -> list[tuple[str, str]]:
    """Return (rule name, matched text) for every hit in one line."""
    if ALLOW_MARKER in text:
        return []
    hits = []
    for rule in BUILTIN_RULES + cfg.rules:
        for m in rule.rx.finditer(text):
            s = m.group(0)
            if rule.ok and rule.ok(s, cfg):
                continue
            if any(a.search(s) for a in cfg.allow):
                continue
            hits.append((rule.name, s))
    return hits


def is_blocked_name(path: str) -> bool:
    base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base in BLOCKED_NAMES or base.endswith(BLOCKED_SUFFIXES)


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines(diff: str) -> Iterator[tuple[str, int, str]]:
    """Yield (file, new line number, text) for each added line of a -U0 diff."""
    cur, ln, in_header = None, 0, False
    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            in_header, cur = True, None
        elif in_header and raw.startswith("+++ "):
            p = raw[4:].rstrip("\t")
            if p.startswith('"') and p.endswith('"'):
                p = p[1:-1]
            cur = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
        elif raw.startswith("@@"):
            in_header = False
            m = _HUNK.match(raw)
            ln = int(m.group(1)) if m else 0
        elif not in_header and raw.startswith("+") and cur is not None:
            yield cur, ln, raw[1:]
            ln += 1


def git(*args: str) -> str:
    r = subprocess.run(["git", "-c", "core.quotepath=false", *args],
                       capture_output=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def scan_staged(cfg: Config) -> list[Hit]:
    hits = []
    names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0")
    for name in filter(None, names):
        if is_blocked_name(name):
            hits.append(Hit(name, None, "blocked-file-name", name))
        hits += [Hit(name, None, r, s) for r, s in scan_text(name, cfg)]
    diff = git("diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--no-textconv")
    for f, ln, text in added_lines(diff):
        hits += [Hit(f, ln, r, s) for r, s in scan_text(text, cfg)]
    return hits


def scan_push(lines: list[str], cfg: Config) -> list[Hit]:
    """pre-push: stdin lines are '<local ref> <local sha> <remote ref> <remote sha>'."""
    hits, seen, seen_content = [], set(), set()
    for line in lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        lref, lsha, _, rsha = parts
        if set(lsha) == {"0"}:  # branch deletion
            continue
        if git("cat-file", "-t", lsha).strip() == "tag":  # annotated tag: its own who/when/message
            hits += _scan_tag(lref, lsha, cfg)
        rev = [lsha, "--not", "--remotes"]
        if set(rsha) != {"0"} and subprocess.run(
                ["git", "cat-file", "-e", rsha], capture_output=True).returncode == 0:
            rev.append(rsha)
        out = git("log", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%ad%x00%cd",
                  "--date=raw", *rev)
        for row in filter(None, out.split("\n")):
            sha, an, ae, cn, ce, ad, cd = row.split("\0")
            if sha in seen:
                continue
            seen.add(sha)
            where = f"commit {sha[:10]}"
            for role, name, email, date in (("author", an, ae, ad), ("committer", cn, ce, cd)):
                hits += [Hit(where, None, f"{r} ({role})", s)
                         for r, s in scan_text(f"{name} <{email}>", cfg)]
                offset = date.split()[-1]
                if offset != "+0000":
                    hits.append(Hit(where, None, f"timezone-not-utc ({role})", offset))
        # Content too: catches commits made with --no-verify or before Commit Guard was installed.
        hits += _scan_pushed_content(rev, cfg, seen_content)
    return hits


def _scan_tag(ref: str, sha: str, cfg: Config) -> list[Hit]:
    """Annotated tags store a tagger (name, email, time) and a message, apart from commits."""
    hits: list[Hit] = []
    where = f"tag {ref.removeprefix('refs/tags/')}"
    header, _, message = git("cat-file", "-p", sha).partition("\n\n")
    for line in header.splitlines():
        if line.startswith("tagger "):
            who, _, when = line[7:].rpartition("> ")
            hits += [Hit(where, None, f"{r} (tagger)", s) for r, s in scan_text(who + ">", cfg)]
            offset = when.split()[-1] if when.split() else ""
            if offset != "+0000":
                hits.append(Hit(where, None, "timezone-not-utc (tagger)", offset))
    for i, text in enumerate(message.split("-----BEGIN PGP SIGNATURE-----")[0].splitlines(), 1):
        hits += [Hit(f"{where} message", i, r, s) for r, s in scan_text(text, cfg)]
    return hits


def _chunks(out: str) -> Iterator[tuple[str, str]]:
    """Split `git log --format=%x00%H...` output into (sha, rest)."""
    for chunk in out.split("\0")[1:]:
        sha, _, rest = chunk.partition("\n")
        yield sha.strip(), rest


def _scan_pushed_content(rev: list[str], cfg: Config, seen: set[str]) -> list[Hit]:
    hits: list[Hit] = []
    new = set()
    for sha, body in _chunks(git("log", "--format=%x00%H%n%B", *rev)):
        if sha in seen:
            continue
        new.add(sha)
        hits += [Hit(f"commit {sha[:10]} message", i, r, s)
                 for i, text in enumerate(body.rstrip("\n").splitlines(), 1)
                 for r, s in scan_text(text, cfg)]
    for sha, names in _chunks(git("log", "--format=%x00%H", "--name-only",
                                  "--diff-filter=ACMR", *rev)):
        if sha in new:
            for name in filter(None, names.splitlines()):
                if is_blocked_name(name):
                    hits.append(Hit(f"commit {sha[:10]} {name}", None, "blocked-file-name", name))
                hits += [Hit(f"commit {sha[:10]} {name}", None, r, s)
                         for r, s in scan_text(name, cfg)]
    for sha, diff in _chunks(git("log", "--format=%x00%H", "-p", "-U0", "--no-color",
                                 "--no-ext-diff", "--no-textconv", *rev)):
        if sha in new:
            hits += [Hit(f"commit {sha[:10]} {f}", ln, r, s)
                     for f, ln, text in added_lines(diff) for r, s in scan_text(text, cfg)]
    seen |= new
    return hits


def scan_message(path: str, cfg: Config) -> list[Hit]:
    """commit-msg hook: scan the message git is about to commit (comments and the
    `git commit -v` diff below the scissors line are ignored)."""
    hits = []
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(text.splitlines(), 1):
        if line.startswith("# ------------------------ >8"):
            break
        if line.startswith("#"):
            continue
        hits += [Hit("commit message", i, r, s) for r, s in scan_text(line, cfg)]
    return hits


def report(hits: list[Hit]) -> int:
    if not hits:
        return 0
    print(f"commitguard: BLOCKED, {len(hits)} hit(s):", file=sys.stderr)
    for h in hits:
        loc = f"{h.where}:{h.line}" if h.line is not None else f"{h.where} (name/metadata)"
        print(f"  {loc}  {h.rule}  {mask(h.text)}", file=sys.stderr)
    print(f"Fix it, or add '{ALLOW_MARKER}' to a line that is safe.", file=sys.stderr)
    if any(h.where.startswith("commit ") and h.where != "commit message" for h in hits):
        print("Already committed: fix the last commit with 'git commit --amend',"
              " older ones with 'git rebase -i'.", file=sys.stderr)
    return 1


# ---------------------------------------------------------------- commands

def cmd_install() -> int:
    try:
        hooks = Path(git("rev-parse", "--git-path", "hooks").strip())
    except RuntimeError:
        print("commitguard: not inside a git repository", file=sys.stderr)
        return 1
    if hooks.resolve() == global_hooks_dir().resolve():
        print("commitguard: global install is active; this repo is already guarded")
        return 0
    py =Path(sys.executable).as_posix()
    me = Path(__file__).resolve().as_posix()
    hooks.mkdir(parents=True, exist_ok=True)
    plan = {"pre-commit": "hook-pre-commit", "commit-msg": 'hook-commit-msg "$1"',
            "pre-push": 'hook-pre-push "$@"'}
    for name in plan:
        f = hooks / name
        if f.exists() and HOOK_TAG not in f.read_text(encoding="utf-8", errors="replace"):
            print(f"commitguard: {f} exists and is not ours; not overwriting", file=sys.stderr)
            return 1
    for name, args in plan.items():
        f = hooks / name
        f.write_text(f'#!/bin/sh\n{HOOK_TAG}\nexec "{py}" "{me}" {args}\n',
                     encoding="utf-8", newline="\n")
        f.chmod(0o755)
        print(f"installed {f}")
    _ensure_template()
    return 0


def _ensure_template() -> None:
    cp = config_path()
    if not cp.exists():
        cp.parent.mkdir(parents=True, exist_ok=True)
        cp.write_text(TEMPLATE, encoding="utf-8")
        print(f"created empty private config template: {cp}")


# Client-side hooks git may run. In global mode every one of them chains to the repo's
# own .git/hooks/<name>, so tools like git-lfs keep working. (reference-transaction is
# left out on purpose: it fires on every ref update and nothing common uses it.)
GLOBAL_HOOKS = ["applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
                "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit",
                "pre-rebase", "post-checkout", "post-merge", "pre-push", "post-rewrite",
                "push-to-checkout", "pre-auto-gc"]


def global_hooks_dir() -> Path:
    return config_path().parent / "hooks"


def global_hook_script(name: str, py: str, me: str) -> str:
    head = f"#!/bin/sh\n{HOOK_TAG}\n"
    chain = (f'cg_local="$(git rev-parse --git-common-dir)/hooks/{name}"\n'
             f'if [ -x "$cg_local" ] && ! grep -q "{HOOK_TAG}" "$cg_local"; then\n')
    if name == "pre-commit":
        return (head + f'"{py}" "{me}" hook-pre-commit || exit 1\n'
                + chain + '  exec "$cg_local" "$@"\nfi\nexit 0\n')
    if name == "commit-msg":
        return (head + f'"{py}" "{me}" hook-commit-msg "$1" || exit 1\n'
                + chain + '  exec "$cg_local" "$@"\nfi\nexit 0\n')
    if name == "pre-push":  # stdin (the ref list) must reach both commitguard and the local hook
        return (head + 'cg_in="$(cat)"\n'
                "cg_feed() { if [ -n \"$cg_in\" ]; then printf '%s\\n' \"$cg_in\"; fi; }\n"
                f'cg_feed | "{py}" "{me}" hook-pre-push "$@" || exit 1\n'
                + chain + '  cg_feed | "$cg_local" "$@"\n  exit $?\nfi\nexit 0\n')
    return head + chain + '  exec "$cg_local" "$@"\nfi\nexit 0\n'


def _global_hooks_path() -> str:
    r = subprocess.run(["git", "config", "--global", "--get", "core.hooksPath"],
                       capture_output=True, text=True)
    return r.stdout.strip()


def _is_ours(p: str) -> bool:
    return bool(p) and Path(p).expanduser().resolve() == global_hooks_dir().resolve()


def cmd_install_global() -> int:
    cur = _global_hooks_path()
    if cur and not _is_ours(cur):
        print(f"commitguard: global core.hooksPath is already {cur}; not changing it",
              file=sys.stderr)
        return 1
    hooks = global_hooks_dir()
    hooks.mkdir(parents=True, exist_ok=True)
    py = Path(sys.executable).as_posix()
    me = Path(__file__).resolve().as_posix()
    for name in GLOBAL_HOOKS:
        f = hooks / name
        f.write_text(global_hook_script(name, py, me), encoding="utf-8", newline="\n")
        f.chmod(0o755)
    subprocess.run(["git", "config", "--global", "core.hooksPath", hooks.as_posix()], check=True)
    print(f"installed {len(GLOBAL_HOOKS)} hooks in {hooks}")
    print(f"set: git config --global core.hooksPath {hooks.as_posix()}")
    print("Repos with their own local core.hooksPath (e.g. husky) are NOT covered.")
    _ensure_template()
    return 0


def cmd_uninstall_global() -> int:
    cur = _global_hooks_path()
    if not _is_ours(cur):
        print("commitguard: global core.hooksPath is not set to commitguard; nothing to do")
        return 0
    subprocess.run(["git", "config", "--global", "--unset", "core.hooksPath"], check=True)
    print("removed global core.hooksPath (hook files left in place)")
    return 0


def cmd_test_config() -> int:
    cfg = load_config()
    print(f"config file: {cfg.path} ({'loaded' if cfg.loaded else 'not present, optional'})")
    for r in cfg.rules:
        kind = r.src.split(":", 1)[0] if r.src.startswith(("re:", "auto:")) else "literal"
        val = r.src.split(":", 1)[1] if kind != "literal" else r.src
        print(f"  {r.name:21} {kind:7} {mask(val)}")
    for a in cfg.allow_src:
        print(f"  {'allow':16} {'':7} {mask(a)}")
    print(f"  allow_private_ips = {str(cfg.allow_private_ips).lower()}")
    print(f"{len(cfg.rules)} private pattern(s), {len(cfg.allow)} allow entr(y/ies) loaded.")
    return 0


def main(argv: list[str]) -> int:
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(errors="backslashreplace")
    cmd = argv[0] if argv else ""
    try:
        if cmd == "install":
            return cmd_install_global() if "--global" in argv else cmd_install()
        if cmd == "uninstall" and "--global" in argv:
            return cmd_uninstall_global()
        if cmd in ("--version", "version"):
            print(f"commitguard {__version__}")
            return 0
        if cmd == "test-config":
            return cmd_test_config()
        if cmd in ("scan", "hook-pre-commit"):
            return report(scan_staged(load_config()))
        if cmd == "hook-commit-msg" and len(argv) > 1:
            return report(scan_message(argv[1], load_config()))
        if cmd == "hook-pre-push":
            return report(scan_push(sys.stdin.read().splitlines(), load_config()))
    except RuntimeError as e:
        print(f"commitguard: error: {e}", file=sys.stderr)
        return 1
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
