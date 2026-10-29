#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""sanitize-reports: redact paths, tokens, credentials, emails and identity terms in text files, in place.

A backstop for report folders, not a gate. Matched values are never printed.
Exit codes: 0 ok, 1 file error, 2 bad usage.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import socket
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Callable
from pathlib import Path

NUL_PROBE = 8192
Repl = str | Callable[[re.Match[str]], str]

PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)
TOKENS = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"sk-ant-[A-Za-z0-9_-]{10,}"
    r"|sk-or-v1-[A-Za-z0-9]{20,}"
    r"|sk-(?:proj-)?(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|hf_[A-Za-z0-9]{30,}"
    r"|npm_[A-Za-z0-9]{36}"
    r"|eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+"
    r")"
)
# A Bearer value must contain a digit, otherwise prose such as "Bearer authentication" would match.
BEARER = re.compile(r"\b(Bearer)\s+(?=[A-Za-z0-9._~+/=-]*\d)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
SSH = re.compile(r"(?:ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp\d+)\s+AAAA[A-Za-z0-9+/=]+")
CRED = re.compile(
    r"(?P<pre>(?<![A-Za-z0-9])(?P<q>[\"\x27]?)(?:[A-Za-z0-9]+[_-])*"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret"
    r"|auth[_-]?token|cookie|session[_-]?key)(?P=q)\s*[:=]\s*)"
    r"(?P<val>\"[^\"\s]{8,}\"|\x27[^\x27\s]{8,}\x27|[^\s\"\x27,;]{8,})",
    re.IGNORECASE,
)
URL_LOGIN = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]*)://[^/\s:@\"\x27]+:[^/\s@\"\x27]+@")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
SLUG_OTHER = re.compile(r"(?<![A-Za-z0-9])-Users-(?!Shared(?![A-Za-z0-9]))[A-Za-z0-9_.]+?(?=-|/|\s|$)")
TMP_VAR = re.compile(r"(?:/private)?/var/folders/[A-Za-z0-9_]+/[A-Za-z0-9_]+/T(?![A-Za-z0-9_])")
TMP_CLAUDE = re.compile(r"(?:/private)?/tmp/claude-\d+")
USER_PATH = re.compile(r"(?<![\w.~-])/(?:Users|home)/(?!Shared(?![\w.-]))[\w.-]+")
VOLUME = re.compile(r"(?<![\w.~-])/Volumes/(?!VOLUME(?![\w.-]))[^/\s\"\x27`)\]]+")
NOISY_NAMES = {"root", "user", "runner", "localhost"}


def cred_repl(m: re.Match[str]) -> str:
    val = m.group("val")
    quoted = val[0] in "\"\x27"
    inner = val[1:-1] if quoted else val
    if inner.startswith("[REDACTED") or inner[0] in "$<{":
        return m.group(0)
    if not quoted and not (re.search(r"[A-Za-z]", inner) and re.search(r"\d", inner)):
        return m.group(0)
    q = val[0] if quoted else ""
    pre = m.group("pre")
    return f"{pre}{q}[REDACTED]{q}"


def email_repl(m: re.Match[str]) -> str:
    low = m.group(0).lower()
    domain = low.rsplit("@", 1)[1]
    if domain == "users.noreply.github.com" or low == "noreply@anthropic.com" or domain in ("example.com", "example.org"):
        return m.group(0)
    return "[REDACTED EMAIL]"


def git_toplevel(directory: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", directory, "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def root_variants(root: str) -> set[str]:
    """Project root plus its realpath and any home-level symlink alias (e.g. ~/Code -> /Volumes/X/Code)."""
    real = os.path.realpath(root)
    variants = {root.rstrip("/"), real}
    home = os.path.expanduser("~")
    try:
        entries = list(os.scandir(home))
    except OSError:
        entries = []
    for entry in entries:
        if entry.is_symlink():
            target = os.path.realpath(entry.path)
            if real == target or real.startswith(target + "/"):
                variants.add(entry.path + real[len(target):])
    return {v for v in variants if v.count("/") >= 2}


def slug_of(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9-]", "-", path)


def identity_terms(extra: list[str]) -> tuple[list[str], list[str], list[str]]:
    users: set[str] = set()
    hosts: set[str] = set()
    for u in (getpass.getuser(), os.path.basename(os.path.expanduser("~"))):
        users.add(u)
    names = [socket.gethostname()]
    if sys.platform == "darwin":
        for key in ("LocalHostName", "ComputerName"):
            try:
                res = subprocess.run(["scutil", "--get", key], capture_output=True, text=True, timeout=5, check=False)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            if res.returncode == 0 and res.stdout.strip():
                names.append(res.stdout.strip())
    for n in names:
        hosts.add(n.removesuffix(".local"))
    ex = list(extra)
    ex += [t for t in os.environ.get("SANITIZE_REPORTS_EXTRA", "").split(",")]

    def ok(t: str) -> bool:
        t = t.strip()
        return len(t) >= 3 and t.lower() not in NOISY_NAMES

    return (
        sorted({t for t in users if ok(t)}, key=len, reverse=True),
        sorted({t for t in hosts if ok(t)}, key=len, reverse=True),
        sorted({t.strip() for t in ex if ok(t)}, key=len, reverse=True),
    )


def term_regex(terms: list[str]) -> re.Pattern[str] | None:
    if not terms:
        return None
    return re.compile(r"(?<!\w)(?:" + "|".join(re.escape(t) for t in terms) + r")(?!\w)", re.IGNORECASE)


Rule = tuple[str, re.Pattern[str], Repl]


def build_rules(roots: tuple[str, ...], terms: tuple[list[str], list[str], list[str]]) -> list[Rule]:
    rules: list[Rule] = [
        ("key", PEM, "[REDACTED PRIVATE KEY]"),
        ("token", TOKENS, "[REDACTED TOKEN]"),
        ("bearer", BEARER, lambda m: f"{m.group(1)} [REDACTED]"),
        ("ssh", SSH, "[REDACTED SSH KEY]"),
        ("cred", CRED, cred_repl),
        ("url", URL_LOGIN, lambda m: f"{m.group(1)}://[REDACTED]@"),
        ("email", EMAIL, email_repl),
    ]
    literals: list[tuple[str, str]] = []
    slugs: set[str] = set()
    for r in roots:
        for v in root_variants(r):
            literals.append((v, "$CLAUDE_PROJECT_DIR"))
            slugs.add(slug_of(v))
    for env in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA"):
        val = os.environ.get(env, "").rstrip("/")
        if val.count("/") >= 2:
            literals.append((val, f"${env}"))
    for val, label in sorted(set(literals), key=lambda x: len(x[0]), reverse=True):
        rules.append(("path", re.compile(re.escape(val) + r"(?![\w-])"), lambda m, label=label: label))
    for s in sorted(slugs, key=len, reverse=True):
        rules.append(("path", re.compile(re.escape(s) + r"(?!\w)"), "<project-slug>"))
    home = os.path.expanduser("~")
    homes = {h for h in (home, os.path.realpath(home)) if h.count("/") >= 2}
    rules.append(("path", SLUG_OTHER, "-Users-USER"))
    for h in sorted(homes, key=len, reverse=True):
        rules.append(("path", re.compile(re.escape(h) + r"(?![\w-])"), "~"))
    rules += [
        ("path", TMP_VAR, "$TMPDIR"),
        ("path", TMP_CLAUDE, "/tmp/claude-UID"),
        ("path", USER_PATH, "~"),
        ("path", VOLUME, "/Volumes/VOLUME"),
    ]
    for kind, rx, label in (
        ("identity", term_regex(terms[0]), "USER"),
        ("identity", term_regex(terms[1]), "HOST"),
        ("extra", term_regex(terms[2]), "[REDACTED]"),
    ):
        if rx is not None:
            rules.append((kind, rx, label))
    return rules


def apply_rules(text: str, rules: list[Rule]) -> tuple[str, Counter[str]]:
    counts: Counter[str] = Counter()
    for kind, rx, repl in rules:

        def wrapped(m: re.Match[str], repl: Repl = repl, kind: str = kind) -> str:
            out = repl(m) if callable(repl) else repl
            if out != m.group(0):
                counts[kind] += 1
            return out

        text = rx.sub(wrapped, text)
    return text, counts


def collect(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        if p.is_symlink():
            files.append(p)
        elif p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
                dirnames[:] = [d for d in dirnames if d != ".git"]
                files += [Path(dirpath) / f for f in filenames]
        else:
            files.append(p)
    return files


def write_atomic(path: Path, data: bytes) -> None:
    mode = path.stat().st_mode & 0o7777
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".sanitize-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sanitize-reports", description="Redact paths, secrets, emails and identity terms in text files, in place.")
    ap.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    ap.add_argument("--project-root", metavar="DIR", help="project root to replace with $CLAUDE_PROJECT_DIR (default: git toplevel of each file)")
    ap.add_argument("--extra", action="append", default=[], metavar="TERM", help="additional term to redact (repeatable)")
    ap.add_argument("paths", nargs="*", metavar="PATH", help="files or directories (default: <git toplevel of cwd>/reports)")
    args = ap.parse_args(argv)

    if args.paths:
        targets = [Path(p) for p in args.paths]
    else:
        top = git_toplevel(os.getcwd())
        if top is None:
            ap.error("no PATH given and the current directory is not inside a git repository")
        targets = [Path(top) / "reports"]
    for t in targets:
        if not (t.exists() or t.is_symlink()):
            ap.error(f"no such file or directory: {t}")
    if args.project_root and not os.path.isdir(args.project_root):
        ap.error(f"--project-root is not a directory: {args.project_root}")

    terms = identity_terms(args.extra)
    rules_cache: dict[tuple[str, ...], list[Rule]] = {}
    toplevel_cache: dict[str, str | None] = {}
    env_root = os.environ.get("CLAUDE_PROJECT_DIR")
    changed = skipped = errors = total = 0
    kinds_total: Counter[str] = Counter()

    for f in collect(targets):
        try:
            if f.is_symlink() or not f.is_file():
                skipped += 1
                continue
            raw = f.read_bytes()
            if b"\0" in raw[:NUL_PROBE]:
                skipped += 1
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                skipped += 1
                continue
            parent = str(f.resolve().parent)
            roots: list[str] = []
            if args.project_root:
                roots.append(os.path.abspath(args.project_root))
            else:
                if parent not in toplevel_cache:
                    toplevel_cache[parent] = git_toplevel(parent)
                if toplevel_cache[parent]:
                    roots.append(toplevel_cache[parent])
            if env_root:
                roots.append(env_root)
            key = tuple(sorted(set(roots)))
            if key not in rules_cache:
                rules_cache[key] = build_rules(key, terms)
            new_text, counts = apply_rules(text, rules_cache[key])
            if new_text == text:
                continue
            if not args.dry_run:
                write_atomic(f, new_text.encode("utf-8"))
            n = sum(counts.values())
            total += n
            kinds_total.update(counts)
            changed += 1
            kind_list = ", ".join(sorted(counts))
            print(f"{f}: {n} replacements ({kind_list})")
        except OSError as e:
            errors += 1
            print(f"{f}: error: {e.strerror or type(e).__name__}", file=sys.stderr)

    verb = "would change" if args.dry_run else "changed"
    print(f"summary: {verb} {changed} files, {total} replacements, {skipped} skipped, {errors} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
