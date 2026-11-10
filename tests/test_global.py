"""Global mode (install --global). Uses a throwaway global gitconfig via GIT_CONFIG_GLOBAL,
so the real ~/.gitconfig is never touched. FAKE DATA ONLY."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = str(Path(__file__).resolve().parent.parent / "commitguard.py")
NOREPLY = "12345+testuser@users.noreply.github.com"
UTC_DATE = "2026-01-01T12:00:00 +0000"


class GlobalInstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cg-global-"))
        self.gitconfig = self.tmp / "gitconfig"
        self.gitconfig.write_text("")
        cfg = self.tmp / "cghome" / "private.toml"
        cfg.parent.mkdir()
        cfg.write_text('names = ["Jane Testperson"]\n')  # commitguard:allow
        self.hooks_dir = cfg.parent / "hooks"
        self.env = {**os.environ, "COMMITGUARD_CONFIG": str(cfg), "COMMITGUARD_AUTO": "0",
                    "GIT_CONFIG_GLOBAL": str(self.gitconfig), "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_DATE": UTC_DATE, "GIT_COMMITTER_DATE": UTC_DATE}
        self.repo = self.new_repo("repo")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_git(self, cwd, *args, check=True):
        r = subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True, text=True)
        if check and r.returncode != 0:
            raise AssertionError(f"git {args} failed: {r.stderr}")
        return r

    def new_repo(self, name):
        repo = self.tmp / name
        repo.mkdir()
        self.run_git(repo, "init", "-q", "-b", "main")
        for k, v in [("user.name", "Test User"), ("user.email", NOREPLY),
                     ("commit.gpgsign", "false"), ("core.autocrlf", "false")]:
            self.run_git(repo, "config", k, v)
        return repo

    def cg(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *args], env=self.env,
                              capture_output=True, text=True, cwd=self.tmp)

    def install(self):
        r = self.cg("install", "--global")
        self.assertEqual(r.returncode, 0, r.stderr)

    def write(self, repo, name, content):
        (repo / name).write_text(content, encoding="utf-8", newline="\n")
        self.run_git(repo, "add", name)

    def local_hook(self, repo, name, body):
        f = repo / ".git" / "hooks" / name
        f.parent.mkdir(exist_ok=True)
        f.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8", newline="\n")
        f.chmod(0o755)

    def test_install_sets_global_hooks_path(self):
        self.install()
        got = self.run_git(self.tmp, "config", "--global", "core.hooksPath").stdout.strip()
        self.assertEqual(Path(got).resolve(), self.hooks_dir.resolve())
        self.assertTrue((self.hooks_dir / "pre-commit").is_file())

    def test_blocks_commit_in_any_repo(self):
        self.install()
        for repo in (self.repo, self.new_repo("other")):
            self.write(repo, "k.py", "KEY = 'AKIAIOSFODNN7EXAMPLE'\n")  # commitguard:allow
            r = self.run_git(repo, "commit", "-m", "x", check=False)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("aws-access-key", r.stderr)

    def test_local_hooks_still_run(self):
        self.install()
        self.local_hook(self.repo, "pre-commit", 'echo ran > local-pre-commit.txt')
        self.local_hook(self.repo, "post-commit", 'echo ran > local-post-commit.txt')
        self.local_hook(self.repo, "commit-msg", 'cp "$1" local-commit-msg.txt')
        self.write(self.repo, "a.py", "x = 1\n")
        self.run_git(self.repo, "commit", "-q", "-m", "ok")
        self.assertTrue((self.repo / "local-pre-commit.txt").exists())
        self.assertTrue((self.repo / "local-post-commit.txt").exists())
        self.assertIn("ok", (self.repo / "local-commit-msg.txt").read_text())

    def test_global_commit_msg_blocks(self):
        self.install()
        self.write(self.repo, "a.py", "x = 1\n")
        r = self.run_git(self.repo, "commit", "-m", "by Jane Testperson", check=False)  # commitguard:allow
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("commit message:1  private-name", r.stderr)

    def test_failing_local_hook_still_blocks(self):
        self.install()
        self.local_hook(self.repo, "pre-commit", "exit 1")
        self.write(self.repo, "a.py", "x = 1\n")
        self.assertNotEqual(self.run_git(self.repo, "commit", "-m", "x", check=False).returncode, 0)

    def test_pre_push_scans_and_passes_stdin_to_local_hook(self):
        self.install()
        remote = self.tmp / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, env=self.env)
        self.run_git(self.repo, "remote", "add", "origin", str(remote))
        self.local_hook(self.repo, "pre-push", "cat > local-pre-push.txt")
        self.write(self.repo, "a.py", "x = 1\n")
        self.run_git(self.repo, "commit", "-q", "-m", "ok")
        self.run_git(self.repo, "push", "-q", "origin", "main")
        self.assertIn("refs/heads/main", (self.repo / "local-pre-push.txt").read_text())
        # and the scan itself still blocks a bad timezone
        env = {**self.env, "GIT_COMMITTER_DATE": "2026-01-01T12:00:00 +0530"}
        self.write(self.repo, "b.py", "y = 2\n")
        subprocess.run(["git", "commit", "-q", "-m", "tz"], cwd=self.repo, env=env, check=True)
        r = self.run_git(self.repo, "push", "origin", "main", check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("timezone-not-utc (committer)", r.stderr)

    def test_old_per_repo_install_not_run_twice(self):
        self.install()
        r = subprocess.run([sys.executable, SCRIPT, "install"], cwd=self.repo, env=self.env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("already guarded", r.stdout)
        self.assertIn("cg_local", (self.hooks_dir / "pre-commit").read_text())  # not overwritten
        # a leftover per-repo commitguard hook is skipped by the chain (no double scan)
        self.local_hook(self.repo, "pre-commit", "# installed by commitguard\nexit 1")
        self.write(self.repo, "a.py", "x = 1\n")
        self.run_git(self.repo, "commit", "-q", "-m", "ok")

    def test_refuses_foreign_global_hooks_path(self):
        self.run_git(self.tmp, "config", "--global", "core.hooksPath", "/some/other/hooks")
        self.assertEqual(self.cg("install", "--global").returncode, 1)
        got = self.run_git(self.tmp, "config", "--global", "core.hooksPath").stdout.strip()
        self.assertEqual(got, "/some/other/hooks")

    def test_uninstall_global(self):
        self.install()
        self.assertEqual(self.cg("uninstall", "--global").returncode, 0)
        r = self.run_git(self.tmp, "config", "--global", "core.hooksPath", check=False)
        self.assertEqual(r.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
