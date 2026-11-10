<div align="center">

<img src="docs/logo.svg" width="112" height="112" alt="Commit Guard logo: an amber shield around a commit line whose middle commit is masked in red">

# Commit Guard

### git commit, \*\*\*

**Your git history is forever.** One push can publish your real name, your home folder, an API key,<br>
or the timezone that tells the world where you live. Commit Guard checks every commit and every push,<br>
and stops the leak before it leaves your PC.<br>
**One command guards every repo. Nothing to configure: it knows who you are.**

<br>

<a href="#install"><img src="https://img.shields.io/badge/Install_in_10_seconds-f5b942?style=for-the-badge&logo=git&logoColor=0e0e0e" alt="Install in 10 seconds" height="36"></a>
&nbsp;
<a href="#what-it-checks"><img src="https://img.shields.io/badge/What_it_checks-1f1f1f?style=for-the-badge" alt="What it checks" height="36"></a>

<br>

[![Latest release](https://img.shields.io/github/v/release/Dizyy/Commit-Guard?style=flat-square&label=release&color=f5b942)](https://github.com/Dizyy/Commit-Guard/releases/latest)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-1f1f1f?style=flat-square&logo=python&logoColor=white)](#install)
[![No dependencies](https://img.shields.io/badge/dependencies-none-f5b942?style=flat-square)](#install)
[![Windows](https://img.shields.io/badge/tested_on-Windows-1f1f1f?style=flat-square)](#tests)
[![MIT License](https://img.shields.io/badge/license-MIT-1f1f1f?style=flat-square)](LICENSE)

<br>

<img src="docs/hero.svg" width="800" alt="Terminal: git commit is blocked by Commit Guard with 3 masked hits (an email, a Windows user path, a country hint), then git push passes">

</div>

<br>

<table>
<tr>
<td width="33%" align="center" valign="top">

**1. Clone**<br>
<sub>Python 3.11+, no packages to install.</sub>

</td>
<td width="33%" align="center" valign="top">

**2. `install --global`**<br>
<sub>Every repo, every commit and push.</sub>

</td>
<td width="33%" align="center" valign="top">

**3. Forget about it**<br>
<sub>It only speaks up when you leak.</sub>

</td>
</tr>
</table>

> [!NOTE]
> **Your data never leaves your PC.**
> - **No network calls, no telemetry.** Commit Guard only runs `git` and reads your OS settings.
> - **Nothing to leak.** Your name, email and PC name are read from the OS on each run and kept in memory only. There is no config file with your details in it.
> - **Even the warning is masked.** Hits are printed as `ja***`, so a screenshot or CI log doesn't leak either.
> - **You can check every line.** It's one Python file, standard library only.

## What it catches

<table>
<tr>
<td width="33%" valign="top">

**Who you are**<br>
<sub>Full name, account email, username, PC name. Detected, not typed.</sub>

</td>
<td width="33%" valign="top">

**Where you are**<br>
<sub>Home folder paths, IPs, country and language hints, non-UTC commit times.</sub>

</td>
<td width="33%" valign="top">

**Secrets**<br>
<sub>Anthropic, OpenAI, Gemini and other AI keys, GitHub/AWS/Stripe tokens, keys in <code>.mcp.json</code> and settings files, <code>.env</code> lines and files.</sub>

</td>
</tr>
</table>

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

**On commit**: only the lines you add (`git diff --cached -U0`), the names of staged files, and
the commit message.<br>
**On push**: every commit that isn't on the remote yet: author and committer name + email, the
timezone (anything other than `+0000` is blocked, because offsets reveal where you live), and
again the added lines, file names and message. That catches commits made with `--no-verify` or
before Commit Guard was installed. Annotated tags get the same check for their tagger name,
email, timezone and message.

Built-in rules:

| Rule | Catches |
|------|---------|
| `windows-user-path` | `C:\Users\<name>`, `/c/Users/<name>` |
| `email` | any email, except `*@users.noreply.github.com` |
| `ipv4` | any IPv4 except `127.0.0.1` and `0.0.0.0` |
| `sk-api-key` | Anthropic (`sk-ant-...`) and OpenAI (`sk-proj-...`) keys |
| `google-api-key`, `huggingface-token`, `groq-key`, `xai-key`, `replicate-token` | other AI provider keys (Gemini, Hugging Face, Groq, xAI, Replicate) |
| `aws-access-key`, `github-token`, `gitlab-token`, `npm-token`, `stripe-key`, `slack-token` | dev service tokens |
| `private-key`, `bearer-token` | private key headers, `Authorization: Bearer ...` values |
| `url-password` | passwords in URLs: `postgres://user:pass@host`, git remotes with a token (`${VARS}`, `<password>` and `***` pass) |
| `env-secret` | `.env`-style `NAME=value` where NAME contains SECRET, TOKEN, PASSWORD or API_KEY |
| `assigned-secret` | the same names given a quoted value in JSON, YAML or code: `"ANTHROPIC_API_KEY": "..."` in `.mcp.json` or a settings file, `api_key = "..."` |
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

- `git push --no-verify` skips all hooks. (`git commit --no-verify` is caught at push time.)
- Repos that set their own local `core.hooksPath` (for example husky) are not covered by `--global`.
- Commits already on the remote are not rescanned.
- Auto-detection is tested on Windows. On macOS and Linux it reads the account name and locale (best effort).
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
