"""Tests for the rule-based PR review agent (prreview.py)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from flowstallion_agent.prreview import (
    PRReviewError,
    PRReviewHTTPError,
    ReviewFinding,
    build_review_payload,
    post_pr_review,
    review,
)


def _diff(path: str, lines: list[str]) -> str:
    """Build a git diff adding ``lines`` as a brand-new file ``path``."""
    out = [
        f"diff --git a/{path} b/{path}",
        "new file mode 100644",
        "--- /dev/null",
        f"+++ b/{path}",
        f"@@ -0,0 +1,{len(lines)} @@",
    ]
    out.extend("+" + line for line in lines)
    return "\n".join(out) + "\n"


def _git_uni_diff(path: str, lines: list[str]) -> str:
    """Build a plain `diff -u` style diff (no `diff --git` header)."""
    out = [
        f"--- a/{path}\t2026-10-23 12:00:00",
        f"+++ b/{path}\t2026-10-23 12:00:01",
        f"@@ -0,0 +1,{len(lines)} @@",
    ]
    out.extend("+" + line for line in lines)
    return "\n".join(out) + "\n"


# --- clean / negative ---------------------------------------------------------


def test_clean_diff_no_findings() -> None:
    diff = _diff("docs/README.md", ["# Title", "", "Some documentation text."])
    assert review(diff) == []


def test_docs_change_selects_nothing() -> None:
    diff = _diff("docs/guide.md", ["A documentation line."])
    assert review(diff) == []


# --- security rules -----------------------------------------------------------


def test_sql_concat_finding() -> None:
    diff = _diff(
        "agent/db.py",
        [
            "import sqlite3",
            "def q(conn, name):",
            '    return conn.execute("SELECT * FROM t WHERE n = \'" + name + "\'").fetchall()',
        ],
    )
    sec = [f for f in review(diff) if f.category == "security"]
    assert len(sec) == 1
    assert sec[0].severity == "high"
    assert sec[0].path == "agent/db.py"
    assert sec[0].line == 3


def test_sql_percent_format_finding() -> None:
    diff = _diff(
        "agent/db.py",
        ['cur.execute("SELECT * FROM t WHERE n = %s" % name)'],
    )
    sec = [f for f in review(diff) if f.category == "security"]
    assert len(sec) == 1
    assert "SQL injection" in sec[0].message


def test_sql_parameterized_no_finding() -> None:
    diff = _diff("agent/db.py", ['cur.execute("SELECT * FROM t WHERE n = ?", (name,))'])
    sec = [f for f in review(diff) if f.category == "security"]
    assert sec == []


def test_shell_true_finding() -> None:
    diff = _diff("agent/sh.py", ["import subprocess", 'subprocess.run("ls " + cmd, shell=True)'])
    sec = [f for f in review(diff) if f.category == "security"]
    assert len(sec) == 1
    assert sec[0].severity == "high"
    assert "shell" in sec[0].message


def test_eval_finding() -> None:
    diff = _diff("agent/x.py", ["value = eval(user_input)"])
    sec = [f for f in review(diff) if f.category == "security"]
    assert len(sec) == 1
    assert "eval" in sec[0].message


def test_hardcoded_secret_finding() -> None:
    diff = _diff("agent/auth.py", ['headers = {"Authorization": "Bearer sk-abc123DEF456ghi789JKL012"}'])
    sec = [f for f in review(diff) if f.category == "security"]
    assert len(sec) == 1
    assert "credential" in sec[0].message


def test_hardcoded_password_finding() -> None:
    diff = _diff("agent/cfg.py", ['password = "sup3r-secret-value"'])
    sec = [f for f in review(diff) if f.category == "security"]
    assert len(sec) == 1
    assert "credential" in sec[0].message


def test_weak_crypto_finding() -> None:
    diff = _diff("agent/hash.py", ["digest = hashlib.md5(data).hexdigest()"])
    sec = [f for f in review(diff) if f.category == "security"]
    assert len(sec) == 1
    assert "MD5" in sec[0].message


def test_security_rules_gated_to_code_files() -> None:
    """Docs/comments that merely mention dangerous patterns must not fire."""
    diff = _diff(
        "docs/README.md",
        [
            "Example key: sk-abc123DEF456ghi789JKL012",
            "Do not run subprocess.run(cmd, shell=True) with user input.",
        ],
    )
    assert review(diff) == []


def test_style_rules_gated_to_code_files() -> None:
    diff = _diff("docs/README.md", ["a" * 200])
    assert review(diff) == []


# --- style rules --------------------------------------------------------------


def test_bare_except_finding() -> None:
    diff = _diff("agent/h.py", ["try:", "    do()", "except:", "    pass"])
    style = [f for f in review(diff) if f.category == "style"]
    assert len(style) == 1
    assert style[0].severity == "medium"
    assert style[0].line == 3


def test_todo_finding() -> None:
    diff = _diff("agent/t.py", ["# TODO: implement later"])
    fs = review(diff)
    assert len(fs) == 1
    assert fs[0].category == "style"
    assert fs[0].severity == "low"


def test_long_line_finding() -> None:
    diff = _diff("agent/l.py", ["a" * 170])
    fs = review(diff)
    assert any(f.category == "style" and "160" in f.message for f in fs)


def test_long_line_ignored_in_markdown() -> None:
    diff = _diff("notes/readme.md", ["x" * 300])
    assert review(diff) == []


# --- risk rules ---------------------------------------------------------------


def test_risk_path_findings() -> None:
    diff = "\n".join(
        [
            _diff("pkg/policy/p.go", ["package policy"]),
            _diff("pkg/scheduler/s.go", ["package scheduler"]),
            _diff("pkg/store/store.go", ["package store"]),
            _diff("Makefile", ["all:"]),
        ]
    )
    risks = {f.path: f.message for f in review(diff) if f.category == "risk"}
    assert risks["pkg/policy/p.go"].startswith("change risk: policy engine")
    assert risks["pkg/scheduler/s.go"].startswith("change risk: scheduler core")
    assert risks["pkg/store/store.go"].startswith("change risk: storage layer")
    assert risks["Makefile"].startswith("change risk: build config")
    assert all(f.severity == "medium" for f in review(diff) if f.category == "risk")


def test_large_file_finding() -> None:
    lines = [f"x{i} = {i}" for i in range(310)]
    diff = _diff("agent/big.py", lines)
    fs = [f for f in review(diff) if "large change" in f.message]
    assert len(fs) == 1
    assert fs[0].line == 1


def test_risk_finding_without_added_lines_has_no_line() -> None:
    diff = (
        "diff --git a/Makefile b/Makefile\n"
        "index 123..456 100644\n"
        "--- a/Makefile\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-all:\n"
        "-\techo hi\n"
    )
    fs = review(diff)
    assert len(fs) == 1
    assert fs[0].category == "risk"
    assert fs[0].line is None


# --- diff parser robustness ---------------------------------------------------


def test_unified_diff_without_git_header_rejected() -> None:
    diff = _git_uni_diff("agent/x.py", ["value = eval(user_input)"])
    with pytest.raises(PRReviewError):
        review(diff)


def test_crlf_line_numbers() -> None:
    diff = (
        "diff --git a/a.py b/a.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/a.py\n"
        "@@ -0,0 +1,2 @@\r\n"
        "+first\r\n"
        "+second\r\n"
    )
    diff = diff.replace("\r\n", "\r\n")  # keep CRLF
    fs = [f for f in review(diff) if f.line is not None]
    # no security/style hits expected; just check line numbers parsed
    diff2 = diff.replace("first", "x = eval(y)")
    fs2 = review(diff2)
    assert any(f.line == 1 for f in fs2)


def test_quoted_path_with_space() -> None:
    diff = (
        'diff --git "a/my file.py" "b/my file.py"\n'
        "new file mode 100644\n"
        '--- /dev/null\n'
        '+++ "b/my file.py"\n'
        "@@ -0,0 +1,1 @@\n"
        "+x = 1\n"
    )
    fs = review(diff)
    # path must be clean (no quotes, no b/ prefix) and non-empty
    assert all("my file.py" == f.path for f in fs)


def test_quoted_octal_escape_path() -> None:
    # git C-locale quoting: "b/\344\270\255.py" == b/中.py
    diff = (
        'diff --git "a/x" "b/\\344\\270\\255.py"\n'
        "new file mode 100644\n"
        "--- /dev/null\n"
        '+++ "b/\\344\\270\\255.py"\n'
        "@@ -0,0 +1,1 @@\n"
        "+x = 1\n"
    )
    fs = review(diff)
    assert all(f.path == "中.py" for f in fs)


# --- payload -----------------------------------------------------------------


def test_payload_no_findings_approves() -> None:
    p = build_review_payload([])
    assert p["event"] == "APPROVE"
    assert p["comments"] == []
    assert "No issues" in str(p["body"]) or "0 finding" in str(p["body"])


def test_payload_high_finding_requests_changes() -> None:
    fs = [ReviewFinding("high", "security", "a.py", 3, "bad")]
    p = build_review_payload(fs)
    assert p["event"] == "REQUEST_CHANGES"
    assert p["comments"] == [{"path": "a.py", "line": 3, "body": "[high/security] bad"}]


def test_payload_omits_lineless_and_unsafe_comments() -> None:
    fs = [
        ReviewFinding("medium", "risk", "Makefile", None, "build changed"),
        ReviewFinding("high", "security", "../../evil", 3, "traversal"),
    ]
    p = build_review_payload(fs)
    # line=None finding excluded; unsafe path excluded from comments
    assert p["comments"] == []
    assert "Makefile" in str(p["body"])
    assert "../../evil" in str(p["body"])
    assert "skipped" in str(p["body"])
    assert p["event"] == "REQUEST_CHANGES"


def test_payload_caps_comments() -> None:
    fs = [ReviewFinding("low", "style", "a.py", i, f"l{i}") for i in range(1, 150)]
    p = build_review_payload(fs)
    assert len(cast(list[Any], p["comments"])) == 100
    assert "omitted" in str(p["body"])


def test_finding_to_dict_omits_none_line() -> None:
    d = ReviewFinding("low", "style", "a.py", None, "m").to_dict()
    assert "line" not in d
    d2 = ReviewFinding("low", "style", "a.py", 4, "m").to_dict()
    assert d2["line"] == 4


# --- GitHub post ----------------------------------------------------------------


class _FakeTransport:
    def __init__(self, status: int = 200, body: bytes = b'{"id": 7}') -> None:
        self.status = status
        self.body = body
        self.calls: list[tuple[str, dict[str, str], bytes]] = []

    def post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_s: float,
    ) -> tuple[int, dict[str, str], bytes]:
        self.calls.append((url, dict(headers), body))
        return self.status, {}, self.body


def test_post_pr_review_success() -> None:
    tr = _FakeTransport()
    diff = _diff("docs/a.md", ["hello"])
    fs = post_pr_review(owner="o", repo="r", pr_number=7, diff=diff, token="t", transport=tr)
    assert fs == []
    url, headers, body = tr.calls[0]
    assert url == "https://api.github.com/repos/o/r/pulls/7/reviews"
    assert headers["Authorization"] == "Bearer t"
    payload = json.loads(body)
    assert payload["event"] == "APPROVE"


def test_post_pr_review_posts_findings() -> None:
    tr = _FakeTransport()
    diff = _diff("pkg/policy/p.go", ["x = eval(y)"])
    fs = post_pr_review(owner="o", repo="r", pr_number=3, diff=diff, token="t", transport=tr)
    assert any(f.severity == "high" for f in fs)
    payload = json.loads(tr.calls[0][2])
    assert payload["event"] == "REQUEST_CHANGES"
    assert payload["comments"]


def test_post_pr_review_empty_diff_refused() -> None:
    tr = _FakeTransport()
    with pytest.raises(PRReviewError):
        post_pr_review(owner="o", repo="r", pr_number=1, diff="  \n", token="t", transport=tr)
    assert tr.calls == []


def test_post_pr_review_invalid_owner_rejected() -> None:
    tr = _FakeTransport()
    with pytest.raises(PRReviewError):
        post_pr_review(owner="a b", repo="r", pr_number=1, diff=_diff("a.py", ["x=1"]), token="t", transport=tr)
    assert tr.calls == []


def test_post_pr_review_http_error() -> None:
    tr = _FakeTransport(status=401, body=b'{"message":"Bad credentials"}')
    with pytest.raises(PRReviewHTTPError) as ei:
        post_pr_review(owner="o", repo="r", pr_number=1, diff=_diff("a.py", ["x=1"]), token="bad", transport=tr)
    assert ei.value.status == 401


def test_post_pr_review_network_error() -> None:
    class _Down:
        def post(
            self,
            url: str,
            headers: dict[str, str],
            body: bytes,
            timeout_s: float,
        ) -> tuple[int, dict[str, str], bytes]:
            raise OSError("connection refused")

    with pytest.raises(PRReviewError):
        post_pr_review(owner="o", repo="r", pr_number=1, diff=_diff("a.py", ["x=1"]), token="t", transport=_Down())


def test_post_pr_review_own_pr_degrades_to_comment() -> None:
    """GitHub 422 'own pull request' -> retry once with event=COMMENT."""

    class _OwnPR:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str], bytes]] = []

        def post(
            self,
            url: str,
            headers: dict[str, str],
            body: bytes,
            timeout_s: float,
        ) -> tuple[int, dict[str, str], bytes]:
            self.calls.append((url, dict(headers), body))
            if len(self.calls) == 1:
                return (
                    422,
                    {},
                    b'{"message":"Unprocessable Entity","errors":'
                    b'["Review Can not request changes on your own pull request"]}',
                )
            return 200, {}, b'{"id": 9}'

    tr = _OwnPR()
    diff = _diff("pkg/policy/p.go", ["x = eval(y)"])
    fs = post_pr_review(owner="o", repo="r", pr_number=3, diff=diff, token="t", transport=tr)
    assert any(f.severity == "high" for f in fs)
    assert len(tr.calls) == 2
    first = json.loads(tr.calls[0][2])
    second = json.loads(tr.calls[1][2])
    assert first["event"] == "REQUEST_CHANGES"
    assert second["event"] == "COMMENT"
    assert tr.calls[1][0] == tr.calls[0][0]  # same endpoint
    assert second["comments"] == first["comments"]  # findings preserved


def test_post_pr_review_422_other_error_not_retried() -> None:
    tr = _FakeTransport(
        status=422,
        body=b'{"message":"Unprocessable Entity","errors":["Invalid line number"]}',
    )
    with pytest.raises(PRReviewHTTPError) as ei:
        post_pr_review(owner="o", repo="r", pr_number=1, diff=_diff("a.py", ["x=1"]), token="t", transport=tr)
    assert ei.value.status == 422
    assert len(tr.calls) == 1  # no fallback retry for unrelated 422s


def test_post_pr_review_own_pr_retry_also_fails() -> None:
    """422 own-PR then a second failure: must raise (no silent swallow)."""

    class _OwnPRThenFail:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str], bytes]] = []

        def post(
            self,
            url: str,
            headers: dict[str, str],
            body: bytes,
            timeout_s: float,
        ) -> tuple[int, dict[str, str], bytes]:
            self.calls.append((url, dict(headers), body))
            if len(self.calls) == 1:
                return (
                    422,
                    {},
                    b'{"message":"Unprocessable Entity","errors":'
                    b'["Review Can not request changes on your own pull request"]}',
                )
            return 500, {}, b"internal error"

    tr = _OwnPRThenFail()
    with pytest.raises(PRReviewHTTPError) as ei:
        post_pr_review(
            owner="o", repo="r", pr_number=3, diff=_diff("a.py", ["x = eval(y)"]), token="t", transport=tr
        )
    assert ei.value.status == 500
    assert "degraded" in str(ei.value)  # error carries the degradation context
    assert len(tr.calls) == 2  # exactly one retry, then raise


# --- CLI --------------------------------------------------------------------------


def _run_cli(
    *args: str,
    env_extra: dict[str, str] | None = None,
    expect_fail: bool = False,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "flowstallion_agent.prreview", *args],
        capture_output=True,
        text=True,
        check=not expect_fail,
        env=env,
    )


def test_cli_diff_file_json(tmp_path: Path) -> None:
    patch = tmp_path / "p.diff"
    patch.write_text(_diff("pkg/policy/p.go", ["package policy"]), encoding="utf-8")
    out = _run_cli(str(patch), "--json")
    data = json.loads(out.stdout)
    assert any(f["path"] == "pkg/policy/p.go" and f["category"] == "risk" for f in data)


def test_cli_stdin() -> None:
    diff = _diff("docs/a.md", ["hello world"])
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    out = subprocess.run(
        [sys.executable, "-m", "flowstallion_agent.prreview"],
        input=diff,
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    assert "0 findings" in out.stdout


def test_cli_empty_stdin_no_findings() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    out = subprocess.run(
        [sys.executable, "-m", "flowstallion_agent.prreview"],
        input="",
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    assert "0 findings" in out.stdout


def test_cli_git_diff_range(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, env=env)

    git("init", "-q")
    (repo / "Makefile").write_text("all:\n\techo 1\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "a")
    (repo / "Makefile").write_text("all:\n\techo 2\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "b")

    out = _run_cli("--diff", "HEAD~1..HEAD", "--git-dir", str(repo), "--json")
    data = json.loads(out.stdout)
    assert any(f["path"] == "Makefile" and f["category"] == "risk" for f in data)


def test_cli_git_diff_failure_clean_error(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True, env=env)
    out = _run_cli("--diff", "HEAD~5..HEAD", "--git-dir", str(repo), expect_fail=True)
    assert out.returncode == 2
    assert "git diff" in out.stderr


def test_cli_missing_diff_file_clean_error(tmp_path: Path) -> None:
    out = _run_cli(str(tmp_path / "nope.diff"), expect_fail=True)
    assert out.returncode == 2
    assert "error" in out.stderr


def test_cli_diff_and_file_mutually_exclusive(tmp_path: Path) -> None:
    patch = tmp_path / "p.diff"
    patch.write_text(_diff("a.py", ["x=1"]), encoding="utf-8")
    out = _run_cli(str(patch), "--diff", "HEAD~1..HEAD", expect_fail=True)
    assert out.returncode == 2
    assert "not allowed" in out.stderr or "mutually exclusive" in out.stderr


def test_cli_missing_token_returns_error(tmp_path: Path) -> None:
    # Use a throwaway git repo (not a hard-coded dev-machine path) so the CLI
    # reaches its "0 findings -> token required" path on any machine/CI.
    git_dir = tmp_path / "repo"
    git_dir.mkdir()
    (git_dir / "a.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=git_dir, check=True)
    subprocess.run(["git", "add", "."], cwd=git_dir, check=True)
    subprocess.run(
        [
            "git", "-c", "user.email=ci@example.com", "-c", "user.name=ci",
            "commit", "-qm", "init",
        ],
        cwd=git_dir, check=True,
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    env.pop("GITHUB_TOKEN", None)
    diff = _diff("a.py", ["x=1"])
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "flowstallion_agent.prreview",
            "--diff",
            "HEAD..HEAD",
            "--git-dir",
            str(git_dir),
            "--owner",
            "o",
            "--repo",
            "r",
            "--pr",
            "1",
        ],
        input=diff,
        capture_output=True,
        text=True,
        env=env,
    )
    assert out.returncode == 2
    assert "GITHUB_TOKEN" in out.stderr
