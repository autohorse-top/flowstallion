"""Rule-based PR review agent.

v1: no LLM. Takes a unified (git) diff and emits structured findings in
three categories: security (hardcoded credentials, SQL injection, dangerous
calls), style (bare except, TODO/FIXME, over-long lines) and change risk
(sensitive paths, large diffs).

CLI:
    python -m flowstallion_agent.prreview file.diff
    python -m flowstallion_agent.prreview --diff HEAD~1..HEAD
    cat patch.diff | python -m flowstallion_agent.prreview
    python -m flowstallion_agent.prreview --diff HEAD~1..HEAD \
        --owner foo --repo bar --pr 42   # posts to GitHub via $GITHUB_TOKEN

Only git diff format (``diff --git`` per-file headers) is accepted; hunk
headers without a file header are rejected with :class:`PRReviewError`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional, Sequence, cast

from flowstallion_agent.llm import Transport

__all__ = [
    "PRReviewError",
    "PRReviewHTTPError",
    "ReviewFinding",
    "build_review_payload",
    "post_pr_review",
    "review",
]

# --- tuning ------------------------------------------------------------------

_MAX_COMMENT_LINE = 160
_LARGE_FILE_LINES = 300
_MAX_COMMENTS = 100
_MAX_BODY_CHARS = 60_000

# Risk paths (prefix match, checked as substring of the repo-relative path).
_RISK_RULES: tuple[tuple[str, str], ...] = (
    ("pkg/policy", "policy engine (approval/risk gating) changed"),
    ("pkg/scheduler", "scheduler core changed"),
    ("pkg/store", "storage layer / schema changed"),
    ("cmd/scheduler", "scheduler entrypoint changed"),
    (".github/workflows", "CI workflow changed"),
    ("Makefile", "build config changed"),
    ("Dockerfile", "container build changed"),
    ("docker-compose", "compose config changed"),
    ("go.mod", "Go dependency manifest changed"),
    ("go.sum", "Go dependency lock changed"),
)

# File-type gate: content rules (security/style) only apply to code files.
# Risk rules and the large-file rule always apply, based on path/size only.
_CODE_EXTS: frozenset[str] = frozenset(
    {
        ".py", ".pyi",
        ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx",
        ".js", ".jsx", ".ts", ".tsx",
        ".java", ".kt", ".kts", ".scala", ".groovy",
        ".rb", ".php", ".cs", ".fs", ".fsx", ".swift",
        ".rs", ".sh", ".bash", ".zsh",
        ".m", ".mm",
        ".pl", ".pm",
        ".lua", ".r",
    }
)


def _is_code_file(path: str) -> bool:
    dot = path.rfind(".")
    if dot <= 0:
        return False
    return path[dot:].lower() in _CODE_EXTS


# --- rule patterns (content rules; applied only to code files) ---------------

# SQL executed from a string built with string concatenation / f-string /
# .format / % formatting.
_SQL_EXEC_RE = re.compile(
    r"(?i)\b(execute|executemany|execute_script|query|querydict|raw_sql)\s*\(",
)
_SQL_ARG = re.compile(r'["\'].*["\']')
_STR_CONCAT = re.compile(r'(f["\']|["\']\s*\+|["\']\s*%\s*[A-Za-z(]|\)\s*%|\.format\s*\()')

# Dangerous shell / code execution.
_SHELL_RE = re.compile(
    r"(?i)(os\.system|os\.popen|subprocess\.[a-z_]+\s*\([^)]*shell\s*=\s*True|"
    r"subprocess\.call\s*\([^)]*shell\s*=\s*True)"
)
_EVAL_RE = re.compile(r"(?<![\w.])\b(eval|exec)\s*\(")

# Hardcoded credential heuristics.
_SECRET_RE = re.compile(
    r"(?i)(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|"
    r"(password|passwd|secret|api_key|apikey|token|auth)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"'])"
)

# Weak crypto used as a digest / integrity check.
_WEAK_CRYPTO_RE = re.compile(
    r"(?i)(hashlib\.(md5|sha1)\s*\(|\b(md5|sha1)\s*\(\s*.*\))"
)


# --- errors ------------------------------------------------------------------

class PRReviewError(Exception):
    """Base error for the PR review agent."""


class PRReviewHTTPError(PRReviewError):
    """GitHub REST call returned a non-2xx status code."""

    def __init__(self, status: int, message: str = "") -> None:
        self.status = status
        super().__init__(f"GitHub returned HTTP {status}: {message}")


# --- data model ---------------------------------------------------------------

@dataclass(frozen=True)
class ReviewFinding:
    severity: str   # "low" | "medium" | "high"
    category: str   # "security" | "style" | "risk"
    path: str       # repo-relative path (may be None for whole-PR findings)
    line: Optional[int]
    message: str

    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "severity": self.severity,
            "category": self.category,
            "path": self.path,
            "message": self.message,
        }
        if self.line is not None:
            d["line"] = self.line
        return d


class _FileDiff:
    __slots__ = ("path", "added")

    def __init__(self, path: str) -> None:
        self.path: str = path
        self.added: list[tuple[int, str]] = []


# --- diff parsing --------------------------------------------------------------

_HUNK_RE = re.compile(
    r"^@@\s*(?:-\d+(?:,\d+)?\s+)?\+(\d+)(?:,\d+)?\s*@@"
)


def _git_unquote(raw: str) -> str:
    """Decode a git quoted path (`"a/..."`) including C escapes."""
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return raw
    inner = raw[1:-1]
    out: list[str] = []
    i = 0
    while i < len(inner):
        c = inner[i]
        if c == "\\" and i + 1 < len(inner):
            n = inner[i + 1]
            if n in ("t", "n", "r"):
                out.append({"t": "\t", "n": "\n", "r": "\r"}[n])
                i += 2
                continue
            if n in ("\\", '"', "'"):
                out.append(n)
                i += 2
                continue
            if n.isdigit():
                if i + 3 < len(inner) and inner[i + 2:i + 4].isdigit():
                    code = int(inner[i + 1:i + 4], 8)
                    out.append(chr(code))
                    i += 4
                    continue
        out.append(c)
        i += 1
    return "".join(out)


def _clean_path(raw: str) -> str:
    """Normalize a path from a ``+++ b/path`` line or a ``diff --git`` header."""
    s = _git_unquote(raw.strip())
    if s.startswith("a/") or s.startswith("b/"):
        s = s[2:]
    return s


def _git_header_path(line: str) -> str:
    """Extract the new path from ``diff --git a/<old> b/<new>`` (fallback).

    Used only when the hunk has no usable ``+++ b/...`` line. Quoted paths
    are decoded.
    """
    m = re.match(r"^diff --git (.+?) (.+?)$", line)
    if not m:
        return ""
    raw = m.group(2)
    return _clean_path(raw)


def _parse_diff(diff: str) -> list[_FileDiff]:
    """Parse a git-format unified diff into per-file sections.

    Raises :class:`PRReviewError` if the text looks like a diff (contains
    ``@@``) but no ``diff --git`` file headers are present. Pure
    ``diff -u`` output without git headers is rejected by design (see
    module docstring).
    """
    files: list[_FileDiff] = []
    current: _FileDiff | None = None
    new_lineno = 0
    in_hunk = False
    saw_hunk = False
    for raw in diff.splitlines():
        m = _HUNK_RE.match(raw)
        if raw.startswith("diff --git "):
            current = _FileDiff(path=_git_header_path(raw))
            files.append(current)
            in_hunk = False
            continue
        if m:
            saw_hunk = True
        if current is None:
            continue
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target != "/dev/null":
                current.path = _clean_path(target)
            continue
        if raw.startswith("--- "):
            continue
        if m:
            new_lineno = int(m.group(1))
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if raw.startswith("+"):
            current.added.append((new_lineno, raw[1:]))
            new_lineno += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            # removed line or "\ No newline at end of file"
            continue
        else:
            # context line (or an empty context line that lost its space)
            new_lineno += 1
    if saw_hunk and not files:
        raise PRReviewError(
            "diff has hunk headers but no `diff --git` file headers; "
            "only git diff format is supported"
        )
    return files


# --- path safety --------------------------------------------------------------

def _path_is_safe_for_github(path: str) -> bool:
    """Reject paths that GitHub would 422 (abs, ``..`` segments, control chars)."""
    if not path or path.startswith("/"):
        return False
    if any(ord(c) < 0x20 for c in path):
        return False
    parts = path.split("/")
    if any(p == ".." for p in parts):
        return False
    return True


# --- rules ---------------------------------------------------------------------


def _security_msgs(text: str) -> list[str]:
    """Content-security findings for one added line."""
    out: list[str] = []
    has_sql = _SQL_EXEC_RE.search(text)
    if has_sql and _SQL_ARG.search(text) and _STR_CONCAT.search(text):
        out.append("possible SQL injection: string-built SQL passed to execute/query")
    if _SHELL_RE.search(text):
        out.append("dangerous shell invocation (system/popen/shell=True)")
    if _EVAL_RE.search(text):
        out.append("use of eval/exec on runtime values")
    if _SECRET_RE.search(text):
        out.append("possible hardcoded credential; move to env/secret store")
    if _WEAK_CRYPTO_RE.search(text):
        out.append("MD5/SHA1 digest; use a modern algorithm (e.g. SHA-256)")
    return out


def _style_msgs(path: str, text: str) -> list[tuple[str, str]]:
    """Returns (severity, message) pairs for style rules on one line."""
    out: list[tuple[str, str]] = []
    if len(text) > _MAX_COMMENT_LINE:
        out.append(("low", f"line exceeds {_MAX_COMMENT_LINE} characters"))
    if re.search(r"^\s*#\s*(TODO|FIXME)", text) or re.search(r"//\s*(TODO|FIXME)", text):
        out.append(("low", "unresolved TODO/FIXME"))
    if re.match(r"^\s*except\s*:", text):
        out.append(("medium", "bare except: catches everything including SystemExit"))
    return out


def _risk_msgs(path: str) -> list[str]:
    """Change-risk findings for a touched path (applied once per file)."""
    for prefix, msg in _RISK_RULES:
        if prefix in path:
            return [f"change risk: {msg}"]
    return []


def review(diff: str) -> list[ReviewFinding]:
    """Run all rules on a git-format diff and return the findings.

    Raises :class:`PRReviewError` for unsupported diff input (see
    :func:`_parse_diff`).
    """
    files = _parse_diff(diff)
    findings: list[ReviewFinding] = []
    for fd in files:
        path = fd.path
        risk = _risk_msgs(path)
        if risk:
            findings.append(
                ReviewFinding(
                    severity="medium",
                    category="risk",
                    path=path,
                    line=fd.added[0][0] if fd.added else None,
                    message=risk[0],
                )
            )
        if len(fd.added) > _LARGE_FILE_LINES:
            findings.append(
                ReviewFinding(
                    severity="medium",
                    category="risk",
                    path=path,
                    line=fd.added[0][0],
                    message=(
                        f"large change: {len(fd.added)} lines added "
                        f"(> {_LARGE_FILE_LINES})"
                    ),
                )
            )
        gated = _is_code_file(path)
        for lineno, line in fd.added:
            if gated:
                for msg in _security_msgs(line):
                    findings.append(
                        ReviewFinding("high", "security", path, lineno, msg)
                    )
                for sev, msg in _style_msgs(path, line):
                    findings.append(
                        ReviewFinding(sev, "style", path, lineno, msg)
                    )
    return findings


# --- GitHub REST ----------------------------------------------------------------


def build_review_payload(findings: Sequence[ReviewFinding]) -> dict[str, object]:
    """Build the body of ``POST /repos/{o}/{r}/pulls/{n}/reviews``.

    - Any high-severity finding  -> REQUEST_CHANGES
    - Any finding                -> COMMENT
    - No findings                -> APPROVE
    """
    if not findings:
        event = "APPROVE"
    elif any(f.severity == "high" for f in findings):
        event = "REQUEST_CHANGES"
    else:
        event = "COMMENT"

    safe = [f for f in findings if _path_is_safe_for_github(f.path)]
    comments: list[dict[str, object]] = [
        {"path": f.path, "line": f.line, "body": f"[{f.severity}/{f.category}] {f.message}"}
        for f in safe
        if f.line is not None
    ]
    n_comments = len(comments)
    comments = comments[:_MAX_COMMENTS]
    omitted = n_comments - len(comments)

    body_lines = [f"Automated review: {len(findings)} finding(s)"]
    for f in findings:
        where = f.path if f.path else "(whole PR)"
        line_no = f":{f.line}" if f.line is not None else ""
        if f.path and not _path_is_safe_for_github(f.path):
            line_no += " (path skipped in inline comments)"
        body_lines.append(f"- [{f.severity}/{f.category}] {where}{line_no} — {f.message}")
    if omitted > 0:
        body_lines.append(f"- … {omitted} more inline comment(s) omitted (cap {_MAX_COMMENTS})")
    body = "\n".join(body_lines)
    if len(body) > _MAX_BODY_CHARS:
        body = body[:_MAX_BODY_CHARS] + "\n… (body truncated)"

    return {"event": event, "body": body, "comments": comments}


class _UrllibTransport:
    """Default stdlib transport (no third-party dependency)."""

    def post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_s: float,
    ) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                hdrs = {k: v for k, v in resp.headers.items() if v is not None}
                return resp.status, hdrs, resp.read()
        except urllib.error.HTTPError as exc:
            err_headers = exc.headers
            err_hdrs: dict[str, str] = {}
            if err_headers is not None:
                err_hdrs = {k: v for k, v in err_headers.items() if v is not None}
            return exc.code, err_hdrs, exc.read()
        except TimeoutError:
            raise
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (TimeoutError, OSError)) and "timed out" in str(reason).lower():
                raise TimeoutError(f"GitHub request to {url} timed out") from exc
            raise OSError(f"GitHub network error: {reason!r}") from exc
        except OSError as exc:
            raise OSError(f"GitHub network error: {exc}") from exc


def post_pr_review(
    *,
    owner: str,
    repo: str,
    pr_number: int,
    diff: str,
    token: str,
    transport: Optional[Transport] = None,
    timeout_s: float = 30.0,
    api_base: str = "",
) -> list[ReviewFinding]:
    """Review a PR diff and POST the review to GitHub.

    ``api_base`` defaults to ``$FLOWSTALLION_GITHUB_API`` (set for local fakes
    / E2E), falling back to ``https://api.github.com``.

    Own-PR degradation: GitHub rejects REQUEST_CHANGES/APPROVE on a PR
    created by the authenticated user (HTTP 422, body mentions "own pull
    request"). When that exact 422 is observed, the review is retried once
    with event=COMMENT so findings still land on the PR; any other failure
    raises.

    Raises:
        PRReviewHTTPError: GitHub returned a non-2xx status.
        PRReviewError:     network failure, invalid owner/repo, or empty diff.
    """
    if not diff.strip():
        raise PRReviewError("refusing to post a review for an empty diff")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", owner) or not re.fullmatch(r"[A-Za-z0-9._-]+", repo):
        raise PRReviewError(
            f"invalid owner/repo for GitHub URL: {owner!r}/{repo!r}"
        )
    findings = review(diff)
    payload = build_review_payload(findings)
    base = (api_base or os.environ.get("FLOWSTALLION_GITHUB_API", "")).strip()
    base = base.rstrip("/") or "https://api.github.com"
    url = f"{base}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    do_post: Callable[[str, dict[str, str], bytes, float], tuple[int, dict[str, str], bytes]] = (
        transport.post if transport is not None else _UrllibTransport().post
    )

    def _send(p: dict[str, object]) -> tuple[int, bytes]:
        b = json.dumps(p).encode("utf-8")
        try:
            s, _h, rb = do_post(url, headers, b, timeout_s)
        except TimeoutError as exc:
            raise PRReviewError(f"timed out posting PR review: {exc}") from exc
        except OSError as exc:
            raise PRReviewError(f"network error posting PR review: {exc}") from exc
        except Exception as exc:  # e.g. http.client.InvalidURL
            raise PRReviewError(f"failed to post PR review: {exc}") from exc
        return s, rb

    status, resp_body = _send(payload)
    if status < 200 or status >= 300:
        msg = resp_body.decode("utf-8", errors="replace").strip()
        if status == 422 and "own pull request" in msg.lower():
            # GitHub rejects REQUEST_CHANGES/APPROVE on one's own PR; degrade
            # to a plain comment review so the findings still land on the PR.
            fallback = dict(payload)
            fallback["event"] = "COMMENT"
            fallback["comments"] = list(
                cast("list[dict[str, object]]", payload["comments"])
            )
            status, resp_body = _send(fallback)
            if status < 200 or status >= 300:
                retry_msg = resp_body.decode("utf-8", errors="replace").strip()
                raise PRReviewHTTPError(
                    status,
                    f"degraded own-PR review to COMMENT; retry failed: {retry_msg}",
                )
        else:
            raise PRReviewHTTPError(status, msg)
    return findings


# --- CLI ------------------------------------------------------------------------


def _git_diff(rng: str, git_dir: str) -> str:
    out = subprocess.run(
        ["git", "diff", rng],
        cwd=git_dir,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="flowstallion_agent.prreview")
    diff_group = p.add_mutually_exclusive_group()
    diff_group.add_argument(
        "file", nargs="?", help="diff file (or use --diff / stdin)"
    )
    diff_group.add_argument(
        "--diff", help="git diff range (e.g. HEAD~1..HEAD); uses local git"
    )
    p.add_argument(
        "--git-dir", default=".", help="repo dir for --diff (default: .)"
    )
    p.add_argument("--json", action="store_true", help="emit findings as JSON")
    p.add_argument("--owner", help="GitHub owner (enables posting)")
    p.add_argument("--repo", help="GitHub repo name")
    p.add_argument("--pr", type=int, help="PR number")
    p.add_argument(
        "--token", default=None, help="GitHub PAT (default: $GITHUB_TOKEN)"
    )
    args = p.parse_args(argv)

    try:
        if args.diff:
            diff = _git_diff(args.diff, args.git_dir)
        elif args.file:
            diff = open(args.file, encoding="utf-8").read()
        else:
            diff = sys.stdin.read()
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or "").strip()
        print(f"error: git diff {args.diff} failed: {msg or exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot read {args.file!r}: {exc}", file=sys.stderr)
        return 2

    try:
        findings = review(diff)
    except PRReviewError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        for f in findings:
            line_no = f":{f.line}" if f.line is not None else ""
            print(f"[{f.severity}/{f.category}] {f.path}{line_no}: {f.message}")
        print(f"{len(findings)} findings")

    if args.owner and args.repo and args.pr:
        token = args.token or os.environ.get("GITHUB_TOKEN", "")
        if not token:
            print(
                "error: --owner/--repo/--pr require --token or GITHUB_TOKEN env var",
                file=sys.stderr,
            )
            return 2
        try:
            post_pr_review(
                owner=args.owner,
                repo=args.repo,
                pr_number=args.pr,
                diff=diff,
                token=token,
            )
            print(f"posted review to {args.owner}/{args.repo} PR #{args.pr}", file=sys.stderr)
        except (PRReviewError, PRReviewHTTPError) as exc:
            print(f"error: posting review failed: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
