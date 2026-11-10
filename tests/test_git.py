"""End-to-end tests in throwaway git repos. FAKE DATA ONLY."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = str(Path(__file__).resolve().parent.parent / "commitguard.py")
FAKE_CONFIG = 'names = ["Jane Testperson"]\nallow_private_ips = false\n'  # commitguard:allow
NOREPLY = "12345+testuser@users.noreply.github.com"
UTC_DATE = "2026-01-01T12:00:00 +0000"


class GitRepoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cg-test-"))
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.cfg = self.tmp / "private.toml"
        self.cfg.write_text(FAKE_CONFIG, encoding="utf-8")
        self.env = {**os.environ, "COMMITGUARD_CONFIG": str(self.cfg), "COMMITGUARD_AUTO": "0",
                    "GIT_AUTHOR_DATE": UTC_DATE, "GIT_COMMITTER_DATE": UTC_DATE}
        self.git("init", "-q", "-b", "main")
        for k, v in [("user.name", "Test User"), ("user.email", NOREPLY),
                     ("commit.gpgsign", "false"), ("core.hooksPath", ".git/hooks"),
                     ("core.autocrlf", "false")]:
            self.git("config", k, v)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args, env=None, check=True):
        r = subprocess.run(["git", *args], cwd=self.repo, env=env or self.env,
                           capture_output=True, text=True)
        if check and r.returncode != 0:
            raise AssertionError(f"git {args} failed: {r.stderr}")
        return r

    def cg(self, *args, env=None):
        return subprocess.run([sys.executable, SCRIPT, *args], cwd=self.repo,
                              env=env or self.env, capture_output=True, text=True)

    def stage(self, name, content):
        p = self.repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")
        self.git("add", name)

    # ---- scan (pre-commit logic)

    def test_clean_scan_is_silent(self):
        self.stage("app.py", "print('hello')\nx = 1\n")
        r = self.cg("scan")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))

    def test_hit_reports_file_line_rule_masked(self):
        self.stage("notes.txt", "fine\nmail jane@example.com\n")  # commitguard:allow
        r = self.cg("scan")
        self.assertEqual(r.returncode, 1)
        self.assertIn("notes.txt:2  email  ja***", r.stderr)
        self.assertNotIn("example.com", r.stderr)

    def test_only_added_lines_scanned(self):
        self.stage("a.txt", "jane@example.com  # commitguard:allow\n")  # commitguard:allow
        self.git("commit", "-q", "-m", "init")
        (self.repo / "a.txt").write_text("jane@example.com\nok\n", encoding="utf-8",  # commitguard:allow
                                         newline="\n")
        self.git("add", "a.txt")
        r = self.cg("scan")
        self.assertEqual(r.returncode, 1)  # the marker removal makes it a new added line
        self.assertIn("a.txt:1", r.stderr)

    def test_blocked_file_and_path_in_name(self):
        self.stage(".env", "X=1\n")
        self.stage("jane testperson/readme.md", "hi\n")  # commitguard:allow
        r = self.cg("scan")
        self.assertEqual(r.returncode, 1)
        self.assertIn(".env (name/metadata)  blocked-file-name", r.stderr)
        self.assertIn("private-name  ja***", r.stderr)

    def test_private_pattern_hit(self):
        self.stage("README.md", "# By Jane Testperson\n")  # commitguard:allow
        r = self.cg("scan")
        self.assertEqual(r.returncode, 1)
        self.assertIn("README.md:1  private-name  Ja***", r.stderr)

    def test_missing_config_is_fine_and_silent(self):
        env = {**self.env, "COMMITGUARD_CONFIG": str(self.tmp / "missing.toml")}
        self.stage("a.py", "x = 1\n")
        r = self.cg("scan", env=env)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.stage("b.py", "mail = 'jane@example.com'\n")  # commitguard:allow
        self.assertEqual(self.cg("scan", env=env).returncode, 1)  # built-ins still run

    def test_auto_detect_blocks_real_username_without_config(self):
        # Uses this machine's real username at runtime only; it is never written to a file
        # in the repo and the assertion messages never print it.
        import getpass
        user = getpass.getuser()
        if len(user) < 3 or user.lower() in ("user", "admin", "administrator", "owner"):
            self.skipTest("generic username")
        env = {**self.env, "COMMITGUARD_CONFIG": str(self.tmp / "missing.toml"),
               "COMMITGUARD_AUTO": "1"}
        self.stage("a.txt", f"made by {user} today\n")
        r = self.cg("scan", env=env)
        self.assertEqual(r.returncode, 1)
        self.assertIn("auto-username", r.stderr)
        self.assertNotIn(user, r.stderr.replace(user[:2] + "***", ""))

    def test_broken_config_fails_closed(self):
        self.cfg.write_text("names = [unclosed", encoding="utf-8")
        self.stage("a.py", "x = 1\n")
        self.assertEqual(self.cg("scan").returncode, 1)

    def test_500_line_diff_under_1s(self):
        line = "def f{0}(x):  return x * {0}  # value {0} for http://localhost/item/{0}\n"
        self.stage("big.py", "".join(line.format(i) for i in range(500)))
        start = time.perf_counter()
        r = self.cg("scan")
        elapsed = time.perf_counter() - start
        print(f"\n[perf] scan of 500-line diff: {elapsed:.3f}s", file=sys.stderr)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(elapsed, 1.0)

    def test_version(self):
        r = self.cg("--version")
        self.assertEqual(r.returncode, 0)
        self.assertRegex(r.stdout.strip(), r"^commitguard \d+\.\d+\.\d+$")

    def test_test_config_masks(self):
        r = self.cg("test-config")
        self.assertEqual(r.returncode, 0)
        self.assertIn("private-name", r.stdout)
        self.assertIn("Ja***", r.stdout)
        self.assertNotIn("Testperson", r.stdout)  # commitguard:allow

    # ---- installed hooks, driven by real git commands

    def install(self):
        r = self.cg("install")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_install_refuses_foreign_hook(self):
        hooks = self.repo / ".git" / "hooks"
        hooks.mkdir(exist_ok=True)
        (hooks / "pre-commit").write_text("#!/bin/sh\necho mine\n")
        self.assertEqual(self.cg("install").returncode, 1)
        self.assertIn("echo mine", (hooks / "pre-commit").read_text())

    def test_install_creates_template_when_missing(self):
        env = {**self.env, "COMMITGUARD_CONFIG": str(self.tmp / "new" / "private.toml")}
        self.assertEqual(self.cg("install", env=env).returncode, 0)
        self.assertIn("names = []", (self.tmp / "new" / "private.toml").read_text())

    def test_pre_commit_hook_blocks_real_commit(self):
        self.install()
        self.stage("k.py", "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")  # commitguard:allow
        r = self.git("commit", "-m", "x", check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("aws-access-key", r.stderr)
        self.stage("k.py", "KEY = os.environ['KEY']\n")
        self.assertEqual(self.git("commit", "-q", "-m", "ok", check=False).returncode, 0)

    def make_remote(self):
        remote = self.tmp / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
        self.git("remote", "add", "origin", str(remote))

    def commit_clean(self, name, env=None):
        self.stage(name, "x = 1\n")
        self.git("commit", "-q", "-m", name, env=env)

    def test_pre_push_allows_clean_utc_noreply(self):
        self.install()
        self.make_remote()
        self.commit_clean("a.py")
        r = self.git("push", "-q", "origin", "main", check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.commit_clean("b.py")  # second push: range from remote sha
        self.assertEqual(self.git("push", "-q", "origin", "main", check=False).returncode, 0)

    def test_pre_push_blocks_timezone(self):
        self.install()
        self.make_remote()
        self.commit_clean("a.py")
        self.git("push", "-q", "origin", "main")
        env = {**self.env, "GIT_COMMITTER_DATE": "2026-01-01T12:00:00 +0530"}
        self.commit_clean("b.py", env=env)
        r = self.git("push", "origin", "main", check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("timezone-not-utc (committer)  +0***", r.stderr)
        self.assertNotIn("(author)", r.stderr)

    def test_pre_push_blocks_author_email_and_name(self):
        self.install()
        self.make_remote()
        env = {**self.env, "GIT_AUTHOR_NAME": "Jane Testperson",  # commitguard:allow
               "GIT_AUTHOR_EMAIL": "jane@example.com"}  # commitguard:allow
        self.commit_clean("a.py", env=env)
        r = self.git("push", "origin", "main", check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("email (author)", r.stderr)
        self.assertIn("private-name (author)", r.stderr)

    # ---- commit messages

    def test_commit_msg_hook_blocks_message(self):
        self.install()
        self.stage("a.py", "x = 1\n")
        r = self.git("commit", "-m", "fix config", "-m", "thanks jane@example.com",  # commitguard:allow
                     check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("commit message:3  email  ja***", r.stderr)
        self.assertNotIn("--amend", r.stderr)  # nothing is committed yet
        r = self.git("commit", "-q", "-m", "fix config", check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_scan_message_ignores_comments_and_verbose_diff(self):
        msg = self.tmp / "MSG"
        msg.write_text("clean subject\n# jane@example.com\n"  # commitguard:allow
                       "# ------------------------ >8 ------------------------\n"
                       "+ jane@example.com\n", encoding="utf-8")  # commitguard:allow
        sys.path.insert(0, str(Path(SCRIPT).parent))
        import commitguard as cg
        cfg = cg.load_config(self.cfg, auto=False)
        self.assertEqual(cg.scan_message(str(msg), cfg), [])
        msg.write_text("leak jane@example.com\n", encoding="utf-8")  # commitguard:allow
        self.assertEqual([h.rule for h in cg.scan_message(str(msg), cfg)], ["email"])

    # ---- pre-push content scan (commits that skipped the commit hooks)

    def test_pre_push_scans_content_of_no_verify_commit(self):
        self.install()
        self.make_remote()
        self.stage("k.py", "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")  # commitguard:allow
        self.git("commit", "-q", "--no-verify", "-m", "sneaky")
        r = self.git("push", "origin", "main", check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("k.py:1  aws-access-key  AK***", r.stderr)
        self.assertIn("git commit --amend", r.stderr)

    def test_pre_push_scans_messages_and_file_names(self):
        self.install()
        self.make_remote()
        self.stage(".env", "X=1\n")
        self.git("commit", "-q", "--no-verify", "-m", "mail jane@example.com")  # commitguard:allow
        r = self.git("push", "origin", "main", check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(".env (name/metadata)  blocked-file-name", r.stderr)
        self.assertIn("message:1  email  ja***", r.stderr)

    def test_pre_push_skips_commits_already_on_remote(self):
        self.install()
        self.make_remote()
        self.stage("k.py", "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")  # commitguard:allow
        self.git("commit", "-q", "--no-verify", "-m", "old")
        self.git("push", "-q", "--no-verify", "origin", "main")  # already public: not our job now
        self.commit_clean("b.py")
        r = self.git("push", "-q", "origin", "main", check=False)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
