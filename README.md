# report-sanitizer

`sanitize-reports` redacts paths, secrets, emails and identity terms in text report files, in place, with a plain script (no LLM tokens). Use it as a backstop over `reports/` folders.

## Usage

    sanitize-reports [--dry-run] [--project-root DIR] [--extra TERM]... [PATH...]

PATH is a file or directory (recursed, symlinks not followed, `.git` skipped). With no PATH it sanitizes `<git toplevel of cwd>/reports`. Writes are atomic and keep the file mode; reruns change nothing. It prints one line per changed file (`path: n replacements (kinds)`) and a summary, never a matched value. `SANITIZE_REPORTS_EXTRA` takes comma-separated extra terms. Exit 0 ok, 1 file error, 2 bad usage.

Install globally: `ln -s <this dir>/sanitize_reports.py ~/.local/bin/sanitize-reports`. Tests: `uv run --with pytest pytest -q`.

## What it redacts

- PEM private keys; API tokens (Anthropic, OpenRouter, OpenAI, GitHub, GitLab, Slack, AWS, Google, Hugging Face, npm, JWT); Bearer values; SSH public keys.
- Credential assignments (`password`, `secret`, `token`, `api_key`, `cookie`, ... also with a prefix such as `GITHUB_TOKEN`): value only, when it is 8+ non-space chars and quoted or mixes letters and digits.
- `scheme://user:pass@host` logins; emails (except noreply and example addresses).
- Paths: project root -> `$CLAUDE_PROJECT_DIR`, plugin env roots, Claude project slugs, temp dirs -> `$TMPDIR`, `/private/tmp/claude-<uid>`, home and `/Users/<name>`, `/home/<name>` -> `~`, other `/Volumes/<name>` -> `/Volumes/VOLUME`.
- Username -> `USER`, hostname -> `HOST`, `--extra` terms -> `[REDACTED]`.

## What it cannot see

It matches shapes, not meaning. It cannot know system state (a hostname or account name outside the listed terms), secrets without a recognisable shape or key name, quoted configuration with free-form values, or text in binary / non-UTF-8 files (skipped). It is a backstop, not a gate: review reports that matter before publishing.

## License

MIT, see [LICENSE](LICENSE).
