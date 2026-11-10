"""Rule tests. FAKE DATA ONLY. Lines with fake data carry a 'commitguard:allow'
comment so this repo's own hooks skip them; the strings under test do not contain it."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import commitguard as cg  # noqa: E402

FAKE_CONFIG = r'''
names = ["Jane Testperson"]
emails = ["jane.private@example.org"]  # commitguard:allow
pc_names = ["JANE-LAPTOP"]
home_ips = ["203.0.113.77"]  # commitguard:allow
words = ["zorblax", "re:\\bquuxword\\b"]
allow = ["docs@example.net"]  # commitguard:allow
allow_private_ips = false
'''  # commitguard:allow

# (expected rule, line) - every built-in and private rule must appear here.
POSITIVE = [
    ("windows-user-path", r"open('C:\Users\testuser\notes.txt')"),  # commitguard:allow
    ("windows-user-path", r'path = "C:\\Users\\testuser\\x"'),  # commitguard:allow
    ("windows-user-path", "cd /c/Users/testuser/projects"),  # commitguard:allow
    ("windows-user-path", "c:/users/testuser/AppData"),  # commitguard:allow
    ("email", "Contact: jane@example.com"),  # commitguard:allow
    ("ipv4", "server = 10.0.0.5"),  # commitguard:allow
    ("ipv4", "home 198.51.100.23."),  # commitguard:allow
    ("ipv4", "router 192.168.1.1"),  # commitguard:allow
    ("aws-access-key", "aws_key = 'AKIAIOSFODNN7EXAMPLE'"),  # commitguard:allow
    ("github-token", "token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),  # commitguard:allow
    ("github-token", "github_pat_11ABCDEFG0123456789_abcdefghijklmnop"),  # commitguard:allow
    ("sk-api-key", "OPENAI = 'sk-proj-abcdefghijklmnopqrstuvwxyz012345'"),  # commitguard:allow
    ("sk-api-key", "key='sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123'"),  # commitguard:allow
    ("private-key", "-----BEGIN RSA PRIVATE KEY-----"),  # commitguard:allow
    ("private-key", "-----BEGIN OPENSSH PRIVATE KEY-----"),  # commitguard:allow
    ("private-key", "-----BEGIN PRIVATE KEY-----"),  # commitguard:allow
    ("env-secret", "DB_PASSWORD=hunter2hunter2"),  # commitguard:allow
    ("env-secret", "export STRIPE_SECRET='abcd1234efgh'"),  # commitguard:allow
    ("env-secret", "SLACK_TOKEN=xoxb-fake-value"),  # commitguard:allow
    ("env-secret", 'MY_API_KEY="fakefakefake" # comment'),  # commitguard:allow
    ("private-name", "Written by Jane Testperson"),  # commitguard:allow
    ("private-name", "author: jane testperson"),  # commitguard:allow
    ("private-email", "mail jane.private@example.org"),  # commitguard:allow
    ("private-pc-name", "host JANE-LAPTOP online"),  # commitguard:allow
    ("private-home-ip", "ssh 203.0.113.77"),  # commitguard:allow
    ("private-word", "print('zorblax')"),  # commitguard:allow
    ("private-word", "# a quuxword here"),  # commitguard:allow
]

BLOCKED_FILES = [".env", "config/.env", "server.pem", "certs/site.key", "id_rsa",
                 ".ssh/id_rsa", "HANDOFF.md", "docs/handoff.md", "private.toml"]
OK_FILES = [".env.example", "env.py", "keys.py", "README.md", "id_rsa.pub", "monkey.txt"]

CLEAN = r'''
import os
from dataclasses import dataclass, field

API_KEY = os.environ["API_KEY"]
token = get_token(user)
password = input("Password: ")
SECRET_NAME = "MY_SECRET"
VERSION = "1.2.3"
HOST = "127.0.0.1"
BIND = "0.0.0.0:8080"
URL = "http://localhost:8000/api/v1/users"
INSTALL_DIR = r"C:\Program Files\Tool"
BIN = "/usr/local/bin/python3"

@dataclass
class User:
    name: str
    tags: list = field(default_factory=list)

    @property
    def display(self):
        return f"{self.name} ({len(self.tags)} tags)"

def task_runner(items):
    for i, item in enumerate(items):
        print(i, item)
    return {"count": len(items), "ratio": 0.75}

// JavaScript
import { useState } from "react";
import type { Node } from "@types/node";
const apiKey = process.env.API_KEY;
const token = await fetchToken({ userId, scope: "read" });
export function sum(a, b) { return a + b; }
const re = /^[a-z0-9_-]{3,16}$/;
console.log(`Total: ${total.toFixed(2)}`);

# Project title

Install with `pip install -r requirements.txt`, then run `python main.py`.
See [the docs](https://example.org/docs/guide) for details.
- Step 1: copy `private.example.toml` to `~/.commitguard/private.toml`
- Step 2: set `PASSWORD=` in your own env, never here
| Column | Value |
|--------|-------|
| port   | 8080  |
Release v2.10.0 on 2026-11-10.
'''


def fake_config() -> cg.Config:
    d = tempfile.mkdtemp()
    p = Path(d) / "private.toml"
    p.write_text(FAKE_CONFIG, encoding="utf-8")
    return cg.load_config(p)


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = fake_config()

    def rules_hit(self, line, cfg=None):
        return {r for r, _ in cg.scan_text(line, cfg or self.cfg)}

    def test_every_positive_detected(self):
        missed = [(r, l) for r, l in POSITIVE if r not in self.rules_hit(l)]
        self.assertEqual(missed, [])

    def test_corpus_covers_every_rule(self):
        all_rules = {r.name for r in cg.BUILTIN_RULES} | set(cg.PRIVATE_KEYS.values())
        self.assertEqual(all_rules - {r for r, _ in POSITIVE}, set())

    def test_clean_corpus_no_false_positives(self):
        lines = CLEAN.strip().splitlines()
        self.assertGreaterEqual(len(lines), 30)
        fps = [(l, self.rules_hit(l)) for l in lines if self.rules_hit(l)]
        self.assertEqual(fps, [])

    def test_blocked_file_names(self):
        self.assertEqual([f for f in BLOCKED_FILES if not cg.is_blocked_name(f)], [])
        self.assertEqual([f for f in OK_FILES if cg.is_blocked_name(f)], [])

    def test_noreply_email_allowed(self):
        self.assertEqual(self.rules_hit("12345+testuser@users.noreply.github.com"), set())

    def test_allow_marker(self):
        self.assertEqual(self.rules_hit("jane@example.com  # commitguard:allow"), set())  # commitguard:allow

    def test_config_allowlist(self):
        self.assertEqual(self.rules_hit("docs@example.net"), set())  # commitguard:allow

    def test_private_ip_toggle(self):
        self.cfg.allow_private_ips = True
        try:
            self.assertEqual(self.rules_hit("router 192.168.1.1"), set())  # commitguard:allow
            self.assertIn("ipv4", self.rules_hit("server 10.0.0.5"))  # commitguard:allow
        finally:
            self.cfg.allow_private_ips = False

    def test_mask(self):
        self.assertEqual(cg.mask("jane@example.com"), "ja***")  # commitguard:allow

    def test_missing_config_runs_builtins(self):
        cfg = cg.load_config(Path(tempfile.mkdtemp()) / "nope.toml", warn=False)
        self.assertFalse(cfg.loaded)
        self.assertIn("email", self.rules_hit("a jane@example.com", cfg))  # commitguard:allow
        self.assertEqual(self.rules_hit("Jane Testperson", cfg), set())  # commitguard:allow

    def test_added_lines_parsing(self):
        diff = (
            "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -3,0 +4,2 @@\n+line four\n+++ looks like header\n"
            "@@ -10 +12 @@\n-old\n+line twelve\n"
            "diff --git a/gone.txt b/gone.txt\n--- a/gone.txt\n+++ /dev/null\n"
            "@@ -1 +0,0 @@\n-bye\n"
        )
        self.assertEqual(list(cg.added_lines(diff)), [
            ("a.py", 4, "line four"), ("a.py", 5, "++ looks like header"),
            ("a.py", 12, "line twelve")])


if __name__ == "__main__":
    unittest.main()
