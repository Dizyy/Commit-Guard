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

Private patterns live in ~/.commitguard/private.toml (never in a repo).
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
# Commit Guard private patterns. NEVER commit this file.
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
]


# ---------------------------------------------------------------- config

def config_path() -> Path:
    env = os.environ.get("COMMITGUARD_CONFIG")
    return Path(env) if env else Path.home() / ".commitguard" / "private.toml"


def _compile(entry: str) -> re.Pattern:
    if entry.startswith("re:"):
        return re.compile(entry[3:])
    return re.compile(re.escape(entry), re.I)


def load_config(path: Path | None = None, warn: bool = True) -> Config:
    path = path or config_path()
    cfg = Config(path=path)
    if not path.is_file():
        if warn:
            print(f"commitguard: warning: no private config at {path}, built-in rules only",
                  file=sys.stderr)
        return cfg
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
    return cfg


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
    hits, seen = [], set()
    for line in lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        _, lsha, _, rsha = parts
        if set(lsha) == {"0"}:  # branch deletion
            continue
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
    return hits


def report(hits: list[Hit]) -> int:
    if not hits:
        return 0
    print(f"commitguard: BLOCKED, {len(hits)} hit(s):", file=sys.stderr)
    for h in hits:
        loc = f"{h.where}:{h.line}" if h.line is not None else f"{h.where} (name/metadata)"
        print(f"  {loc}  {h.rule}  {mask(h.text)}", file=sys.stderr)
    print(f"Fix it, or add '{ALLOW_MARKER}' to a line that is safe.", file=sys.stderr)
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
    plan = {"pre-commit": "hook-pre-commit", "pre-push": 'hook-pre-push "$@"'}
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
    if not cfg.loaded:
        return 0
    print(f"config: {cfg.path}")
    for r in cfg.rules:
        kind = "regex" if r.src.startswith("re:") else "literal"
        print(f"  {r.name:16} {kind:7} {mask(r.src[3:] if kind == 'regex' else r.src)}")
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
        if cmd == "test-config":
            return cmd_test_config()
        if cmd in ("scan", "hook-pre-commit"):
            return report(scan_staged(load_config()))
        if cmd == "hook-pre-push":
            return report(scan_push(sys.stdin.read().splitlines(), load_config()))
    except RuntimeError as e:
        print(f"commitguard: error: {e}", file=sys.stderr)
        return 1
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
