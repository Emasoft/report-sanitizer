"""Real-file tests for sanitize_reports.py: no mocks, subprocess runs of the actual script."""

from __future__ import annotations

import getpass
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "sanitize_reports.py"
HOME = os.path.expanduser("~")
USER = getpass.getuser()
HOST = socket.gethostname().removesuffix(".local")

# Fake secrets, assembled at runtime so no scanner flags this test file itself.
FAKE_SECRETS = [
    "sk-ant-" + "api03-AbCdEf1234567890XyZ",
    "sk-or-v1-" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4",
    "sk-proj-" + "Ab12Cd34Ef56Gh78Ij90Kl",
    "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "github_pat_" + "11ABCDEFG0abcdefghij_klmnopqrstuvwxyz",
    "glpat-" + "abcdefghij1234567890",
    "xoxb-" + "1234567890-abcdefghij",
    "AKIA" + "IOSFODNN7EXAMPLE",
    "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "hf_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
    "npm_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
]


def run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    e = dict(os.environ)
    e.pop("CLAUDE_PROJECT_DIR", None)
    e.pop("SANITIZE_REPORTS_EXTRA", None)
    e.update(env or {})
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, cwd=cwd, env=e, check=False)


def sanitize(tmp_path: Path, content: str, *args: str, env: dict[str, str] | None = None) -> str:
    f = tmp_path / "report.md"
    f.write_text(content, encoding="utf-8")
    res = run(*args, str(f), env=env)
    assert res.returncode == 0, res.stderr
    return f.read_text(encoding="utf-8")


def test_a_pem_private_key(tmp_path: Path) -> None:
    """Rule a: PEM private key blocks become a placeholder."""
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\nabcd\n-----END RSA PRIVATE KEY-----"
    out = sanitize(tmp_path, f"before\n{body}\nafter\n")
    assert out == "before\n[REDACTED PRIVATE KEY]\nafter\n"


@pytest.mark.parametrize("secret", FAKE_SECRETS)
def test_b_tokens(tmp_path: Path, secret: str) -> None:
    """Rule b: every known token shape becomes [REDACTED TOKEN]."""
    out = sanitize(tmp_path, f"value {secret} end\n")
    assert out == "value [REDACTED TOKEN] end\n"


def test_b_bearer_and_ssh(tmp_path: Path) -> None:
    """Rule b: Bearer values and SSH public keys are redacted, prose is not."""
    ssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij0123456789"
    out = sanitize(tmp_path, f"Authorization: Bearer abc123def456ghi\nBearer authentication is used\n{ssh}\n")
    assert "Bearer [REDACTED]" in out
    assert "Bearer authentication is used" in out
    assert "[REDACTED SSH KEY]" in out
    assert "AAAAC3" not in out


def test_c_credential_assignments(tmp_path: Path) -> None:
    """Rule c: credential values redacted in k=v, k: v and JSON forms; counters untouched."""
    src = (
        "password=hunter2hunter2\n"
        "api_key: abc12345def\n"
        "\"client_secret\": \"longsecretvalue\"\n"
        "GITHUB_TOKEN=zz99yy88xx77\n"
        "tokens: 37,911\n"
        "token: short1\n"
        "password: yourpasswordhere\n"
    )
    out = sanitize(tmp_path, src)
    assert "password=[REDACTED]" in out
    assert "api_key: [REDACTED]" in out
    assert "\"client_secret\": \"[REDACTED]\"" in out
    assert "GITHUB_TOKEN=[REDACTED]" in out
    assert "tokens: 37,911" in out
    assert "token: short1" in out
    assert "password: yourpasswordhere" in out  # unquoted, letters only: not a credential shape
    assert "hunter2" not in out


def test_d_url_login(tmp_path: Path) -> None:
    """Rule d: user:pass in a URL is redacted, host kept."""
    out = sanitize(tmp_path, "clone https://bob:s3cr3tpw@github.com/x/y.git now\n")
    assert out == "clone https://[REDACTED]@github.com/x/y.git now\n"


def test_e_emails(tmp_path: Path) -> None:
    """Rule e: emails redacted except noreply and example addresses."""
    src = "a@gmail.com 713559+Emasoft@users.noreply.github.com noreply@anthropic.com me@example.com x@example.org actions/checkout@v4\n"
    out = sanitize(tmp_path, src)
    assert out == "[REDACTED EMAIL] 713559+Emasoft@users.noreply.github.com noreply@anthropic.com me@example.com x@example.org actions/checkout@v4\n"


def test_f_project_root_and_slug(tmp_path: Path) -> None:
    """Rule f: project root, its realpath and its Claude slug are replaced."""
    root = tmp_path / "proj"
    root.mkdir()
    real = os.path.realpath(root)
    slug = "".join(c if c.isalnum() or c == "-" else "-" for c in real)
    src = f"file {root}/src/a.py and {real}/b.py\n{HOME}/.claude/projects/{slug}/memory\n"
    out = sanitize(tmp_path, src, "--project-root", str(root))
    assert "$CLAUDE_PROJECT_DIR/src/a.py" in out
    assert "$CLAUDE_PROJECT_DIR/b.py" in out
    assert "~/.claude/projects/<project-slug>/memory" in out


def test_f_plugin_env_home_tmp_volumes(tmp_path: Path) -> None:
    """Rule f: plugin env values, other users, temp dirs, uid dirs, volumes, HOME."""
    src = (
        "/opt/plug/root/x.json\n"
        f"{HOME}/dev/thing\n"
        "/Users/someoneelse/work and /home/bob/x and /Users/Shared/keep\n"
        "-Users-someoneelse-proj\n"
        "/private/var/folders/ab/cdefgh123/T/pytest-0 and /var/folders/ab/cdefgh123/T/x\n"
        "/private/tmp/claude-501/scratch\n"
        "/Volumes/MyDisk/Code/x\n"
    )
    out = sanitize(tmp_path, src, env={"CLAUDE_PLUGIN_ROOT": "/opt/plug/root"})
    assert "$CLAUDE_PLUGIN_ROOT/x.json" in out
    assert "~/dev/thing" in out
    assert "~/work and ~/x and /Users/Shared/keep" in out
    assert "-Users-USER-proj" in out
    assert "$TMPDIR/pytest-0 and $TMPDIR/x" in out
    assert "/tmp/claude-UID/scratch" in out
    assert "/Volumes/VOLUME/Code/x" in out


def test_g_identity_and_extra(tmp_path: Path) -> None:
    """Rule g: username, hostname and extra terms are replaced as whole words."""
    src = f"user {USER} host {HOST} codename Zanzibar99 and {USER}x stays\n"
    out = sanitize(tmp_path, src, "--extra", "zanzibar99", env={"SANITIZE_REPORTS_EXTRA": "otherterm"})
    assert f" {USER} " not in out
    assert out.startswith("user USER host HOST codename [REDACTED] and ")
    assert f"{USER}x stays" in out
    out2 = sanitize(tmp_path, "an otherterm here\n", env={"SANITIZE_REPORTS_EXTRA": "otherterm,ab"})
    assert out2 == "an [REDACTED] here\n"


def test_idempotent(tmp_path: Path) -> None:
    """A second run changes nothing."""
    f = tmp_path / "r.md"
    f.write_text(f"{HOME}/x {FAKE_SECRETS[0]} a@gmail.com password=hunter2hunter2 \"token\": \"abcdefgh12\" {USER}\n")
    first = run(str(f))
    assert "1 files" in first.stdout
    snapshot = f.read_bytes()
    second = run(str(f))
    assert "changed 0 files" in second.stdout
    assert f.read_bytes() == snapshot


def test_binary_and_non_utf8_skipped(tmp_path: Path) -> None:
    """Files with NUL bytes or invalid UTF-8 are left byte-identical and counted as skipped."""
    b = tmp_path / "a.bin"
    b.write_bytes(b"\0\1" + f"{HOME}/x".encode())
    n = tmp_path / "b.txt"
    n.write_bytes(f"{HOME}/x ".encode() + b"\xff\xfe")
    before = (b.read_bytes(), n.read_bytes())
    res = run(str(tmp_path))
    assert "2 skipped" in res.stdout
    assert (b.read_bytes(), n.read_bytes()) == before


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    """--dry-run reports changes but leaves bytes identical."""
    f = tmp_path / "r.md"
    f.write_text(f"{HOME}/x {FAKE_SECRETS[0]}\n")
    before = f.read_bytes()
    res = run("--dry-run", str(f))
    assert "would change 1 files" in res.stdout
    assert f.read_bytes() == before


def test_mode_preserved(tmp_path: Path) -> None:
    """File mode survives the atomic replace."""
    f = tmp_path / "r.md"
    f.write_text(f"{HOME}/x\n")
    f.chmod(0o640)
    run(str(f))
    assert stat.S_IMODE(f.stat().st_mode) == 0o640
    assert "~/x" in f.read_text()


def test_stdout_never_leaks(tmp_path: Path) -> None:
    """Neither stdout nor stderr contains any matched value."""
    f = tmp_path / "r.md"
    f.write_text("\n".join(FAKE_SECRETS) + f"\n{HOME}/x a@gmail.com {USER}\n")
    res = run(str(f))
    out = res.stdout + res.stderr
    for s in [*FAKE_SECRETS, "a@gmail.com", HOME]:
        assert s not in out
    assert USER not in out.replace(str(tmp_path), "")


def test_false_positives_untouched(tmp_path: Path) -> None:
    """Counters, versions, shared users dir and prose are not modified."""
    src = "tokens: 37,911\nversion 1.2.3 and v14.0.0\n/Users/Shared/x\nthe risk-assessment-of-things-in-general-use\nhttps://example.com/home/page\n"
    f = tmp_path / "r.md"
    f.write_text(src)
    res = run(str(f))
    assert f.read_text() == src
    assert "changed 0 files" in res.stdout


def test_symlink_not_followed(tmp_path: Path) -> None:
    """A symlink inside a directory is skipped, its target untouched."""
    target = tmp_path / "outside.md"
    target.write_text(f"{HOME}/x\n")
    d = tmp_path / "d"
    d.mkdir()
    (d / "link.md").symlink_to(target)
    run(str(d))
    assert target.read_text() == f"{HOME}/x\n"


def test_bad_usage_exit_2(tmp_path: Path) -> None:
    """A missing path is a usage error."""
    assert run(str(tmp_path / "nope")).returncode == 2


def test_default_path_is_git_reports(tmp_path: Path) -> None:
    """With no PATH the script sanitizes <git toplevel>/reports."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "reports").mkdir()
    f = tmp_path / "reports" / "r.md"
    f.write_text(f"{tmp_path}/a {HOME}/b\n")
    res = run(cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    assert f.read_text() == "$CLAUDE_PROJECT_DIR/a ~/b\n"


def test_gitleaks_clean_after_sanitizing(tmp_path: Path) -> None:
    """gitleaks finds nothing in a sanitized fixture folder."""
    d = tmp_path / "fx"
    d.mkdir()
    (d / "a.md").write_text("\n".join(f"key = {s}" for s in FAKE_SECRETS) + "\npassword=hunter2hunter2\n")
    (d / "b.pem").write_text("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n")
    assert run(str(d)).returncode == 0
    res = subprocess.run(["gitleaks", "detect", "--no-git", "--source", str(d)], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stdout + res.stderr
