# sanitize-reports spec (plan of record)

Purpose: backstop script that redacts paths, tokens, credentials, emails and identity terms in text report files, in place, with no agent tokens spent.

CLI: `sanitize-reports [--dry-run] [--project-root DIR] [--extra TERM]... [PATH...]`. PATH = files or dirs (recursed, symlinks not followed, .git skipped). Default PATH = `<git toplevel of cwd>/reports`. Text files only (skip: NUL in first 8 KB, or not valid UTF-8; counted as skipped). Atomic in-place write (temp file in same dir + os.replace, mode kept). Idempotent. One line per changed file `<path>: <n> replacements (<kinds>)` then a summary; matched values are never printed. Exit 0 ok, 1 file error, 2 bad usage.

Replacements, most specific first:
a. PEM private key blocks -> `[REDACTED PRIVATE KEY]`.
b. Tokens (sk-ant-, sk-or-v1-, sk-/sk-proj- 20+, gh[pousr]_, github_pat_, glpat-, xox[abprs]-, AKIA, AIza, hf_, npm_, JWT) -> `[REDACTED TOKEN]`; `Bearer x` -> `Bearer [REDACTED]`; SSH public keys -> `[REDACTED SSH KEY]`.
c. Credential assignments (key exactly password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key|client_secret|auth_token|cookie|session_key, case-insensitive, _/- variants; k=v, k: v, "k": "v") keep key, value -> `[REDACTED]`; only when value is 8+ non-space chars and quoted or mixing letters and digits.
d. URL logins `scheme://user:pass@host` -> `scheme://[REDACTED]@host`.
e. Emails -> `[REDACTED EMAIL]`, except *@users.noreply.github.com, noreply@anthropic.com, @example.com|org.
f. Paths, longest first: project root (+ realpath and symlink aliases) -> `$CLAUDE_PROJECT_DIR`; `$CLAUDE_PLUGIN_ROOT`/`$CLAUDE_PLUGIN_DATA` env values -> those names; Claude projects slug of the project -> `<project-slug>`, other `-Users-<name>-` -> `-Users-USER-`; macOS /var/folders temp -> `$TMPDIR`; /private/tmp/claude-<uid> -> /tmp/claude-UID; real $HOME and /Users/<name>, /home/<name> -> `~` (/Users/Shared untouched); other /Volumes/<name> -> /Volumes/VOLUME.
g. Whole-word username -> USER; hostname (minus .local, plus scutil LocalHostName/ComputerName) -> HOST; --extra and SANITIZE_REPORTS_EXTRA (comma-separated) -> `[REDACTED]`. Terms under 3 chars skipped.

Tests: real files in tmp_path, one per rule a-g, idempotence, binary/non-UTF-8 skip, dry-run, mode kept, stdout never leaks, false-positive guards, then gitleaks on sanitized fixtures. Real-data check on a COPY of apple-docs-mcp/reports only.

Limits: a backstop, not a gate. Cannot see system state or quoted configuration that does not match a pattern.
