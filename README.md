# Commit Guard

Git hooks that stop commits and pushes that leak your personal data: your name, email,
username, PC name, home folder paths, IP addresses, secrets, and hints about your country.

- Works in **every repo** on your machine with one command.
- **No setup**: it detects who you are from the OS on every run. Nothing to type.
- Python 3.11+, standard library only. No dependencies.

## Install

```bash
git clone https://github.com/Dizyy/Commit-Guard.git
python Commit-Guard/commitguard.py install --global
```

That sets `git config --global core.hooksPath` to `~/.commitguard/hooks`. From then on every
`git commit` and `git push`, in any repo, by you or by a coding agent, goes through Commit Guard.
Each repo's own `.git/hooks` still run after it (git-lfs and similar keep working).

Undo:

```bash
python Commit-Guard/commitguard.py uninstall --global
```

Only one repo instead: run `python path/to/commitguard.py install` inside it.

## What it checks

**On commit**: only the lines you add (`git diff --cached -U0`) plus the names of staged files.
**On push**: author and committer name + email of every commit being pushed, and the timezone
(anything other than `+0000` is blocked, because offsets reveal where you live).

Built-in rules:

| Rule | Catches |
|------|---------|
| `windows-user-path` | `C:\Users\<name>`, `/c/Users/<name>` |
| `email` | any email, except `*@users.noreply.github.com` |
| `ipv4` | any IPv4 except `127.0.0.1` and `0.0.0.0` |
| `aws-access-key`, `github-token`, `sk-api-key`, `private-key` | common secret formats |
| `env-secret` | `.env`-style `NAME=value` where NAME contains SECRET, TOKEN, PASSWORD or API_KEY |
| `blocked-file-name` | `.env`, `*.pem`, `*.key`, `id_rsa`, `HANDOFF.md`, `private.toml` |

Auto-detected on every run (kept in memory only, never written anywhere):

| Rule | Source |
|------|--------|
| `auto-name` | your account's full name, and each part of it |
| `auto-email` | your Microsoft account email (Windows) |
| `auto-username`, `auto-pc-name` | OS username and computer name |
| `auto-country-hint` | your region's country name (English + native), languages you type in, locale tags |
| `auto-language-letter` | letters typical for a non-English language you use |

See what was detected (masked):

```bash
python Commit-Guard/commitguard.py test-config
```

## When it blocks

```
commitguard: BLOCKED, 1 hit(s):
  src/app.py:12  email  ja***
Fix it, or add 'commitguard:allow' to a line that is safe.
```

Matched text is masked (first 2 characters + `***`) so the output itself does not leak.

- A line that contains `commitguard:allow` is skipped.
- Scan staged changes by hand: `python commitguard.py scan`

## Optional config

`~/.commitguard/private.toml` (on Windows `%USERPROFILE%\.commitguard\private.toml`) is never
inside a repo. You only need it for extras. See [private.example.toml](private.example.toml).

```toml
names = []              # extra names; plain text = literal, "re:..." = regex
emails = []
pc_names = []
home_ips = []
words = []
allow = []              # text that is fine to commit even if a rule matches it
allow_private_ips = false   # true = allow 192.168.x.x
auto_detect = true          # false = turn off auto-detection
```

A broken config file blocks the commit (fail closed) instead of silently letting data through.

## Limits

- `git commit --no-verify` skips all hooks.
- Repos that set their own local `core.hooksPath` (for example husky) are not covered by `--global`.
- Commit messages are not scanned.
- Possible false positives: SSH remote URLs (the `git` user at a host looks like an email) and
  four-part version numbers (they look like IPs). Use `commitguard:allow` or an `allow` entry.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests use fake data only and never touch your real git config (`GIT_CONFIG_GLOBAL` points to
a temp file).

## License

MIT. See [LICENSE](LICENSE).
