"""PR-run AI wiring (P7⑥): prreview + testselect for PR-triggered runs.

Runs as a second phase of the same watch loop as RCA triage. For every
terminal (success/failed) run that carries PR metadata (``run.pr != 0`` and
a ``repo_url``):

1. fetch the PR diff from the GitHub REST API
   (``GET /repos/{o}/{r}/pulls/{n}`` with ``Accept: vnd.github.v3.diff``),
2. run the rule-based review (``prreview.review``) with an optional LLM
   summary, and store it as analysis ``kind="pr_review"`` (run-level,
   no step id),
3. map the changed files to affected tests (``testselect.select_tests``
   over the local checkout) and store ``kind="test_selection"``,
4. when a GitHub token is configured, also post the review to GitHub
   (``POST .../pulls/{n}/reviews``); without a token the review is stored
   as analysis only (graceful degradation per TASK.md: AI is a bypass).

Degrade rules (the sidecar never blocks the core pipeline):

- ``FLOWSTALLION_GITHUB_TOKEN`` unset  -> GitHub review POST is skipped;
  the analysis rows are still written.
- diff fetch failure -> the run is skipped for this pass; with a
  ``PollSkipState`` permanent failures (bad repo / PR number, 404, empty
  diff) are never retried, retryable ones (403/429/5xx, network) are
  retried after ``_RETRY_BACKOFF_S`` seconds.
- LLM missing or failing            -> rule-based review only.
- any per-run error                  -> logged and skipped.

Environment:

- ``FLOWSTALLION_GITHUB_TOKEN``  GitHub PAT (optional; enables review POST).
- ``FLOWSTALLION_GITHUB_API``    GitHub REST base (default
  ``https://api.github.com``; point at a local fake for E2E).

The diff is truncated to ``DIFF_MAX_CHARS`` before review/selection so a
pathologically large PR can never blow up the analysis rows.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional, Protocol

from flowstallion_agent import llm, prreview, repocheck, testselect
from flowstallion_agent.client import AnalysisReport, ClientError, RunInfo

__all__ = [
    "ENV_GITHUB_TOKEN",
    "ENV_GITHUB_API",
    "DEFAULT_GITHUB_API",
    "DIFF_MAX_CHARS",
    "GitHubTransport",
    "SchedulerLike",
    "PRWireError",
    "PollSkipState",
    "ReviewResult",
    "parse_repo_url",
    "changed_files_from_diff",
    "fetch_pr_diff",
    "review_diff",
    "process_pr_run",
    "poll_pr_runs",
]

ENV_GITHUB_TOKEN = "FLOWSTALLION_GITHUB_TOKEN"
ENV_GITHUB_API = "FLOWSTALLION_GITHUB_API"
DEFAULT_GITHUB_API = "https://api.github.com"

# Hard cap on the diff text fed to review/selection/LLM (analysis rows and
# prompt payloads stay bounded no matter how big the PR is).
DIFF_MAX_CHARS = 60_000

# Terminal run states that get AI wiring.
_PR_TERMINAL_STATES = frozenset({"success", "failed"})

_GITHUB_URL_RE = re.compile(r"^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+)")
_OWNER_REPO_RE = re.compile(r"[A-Za-z0-9._-]+")


class PRWireError(Exception):
    """Fatal for one run's wiring pass (bad URL, diff fetch failure, ...).

    ``permanent`` marks failures that will never succeed for this run
    (unsupported host, bad PR number, HTTP 404, empty diff): callers with a
    :class:`PollSkipState` remember them instead of retrying.
    """

    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


class GitHubTransport(Protocol):
    """Minimal GitHub REST abstraction; inject a fake in tests.

    Both methods return ``(status, headers, body_bytes)`` and must NOT
    raise on non-2xx (that is the caller's decision).
    """

    def get(
        self, url: str, headers: dict[str, str], timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        ...

    def post(
        self, url: str, headers: dict[str, str], body: bytes, timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        ...


class SchedulerLike(Protocol):
    """The scheduler-client surface the wiring needs.

    ``client.SchedulerClient`` satisfies it structurally; tests inject a
    duck-typed fake instead of opening a real HTTP connection.
    """

    def list_runs(self, limit: int = 50) -> list[RunInfo]:
        ...

    def post_analysis(
        self,
        run_id: int,
        *,
        step_id: str = "",
        kind: str,
        root_cause: str,
        detail: str = "",
        suggested_fix: str = "",
        command: str = "",
        log_excerpt: str = "",
    ) -> None:
        ...

    def list_analyses(self, run_id: int) -> list[AnalysisReport]:
        ...


class _UrllibTransport:
    """Default stdlib transport (no third-party dependency)."""

    def _open(
        self,
        url: str,
        headers: dict[str, str],
        body: Optional[bytes],
        method: str,
        timeout_s: float,
    ) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                hdrs = {k: v for k, v in resp.headers.items() if v is not None}
                return resp.status, hdrs, resp.read()
        except urllib.error.HTTPError as exc:
            err_hdrs: dict[str, str] = {}
            if exc.headers is not None:
                err_hdrs = {k: v for k, v in exc.headers.items() if v is not None}
            return exc.code, err_hdrs, exc.read()
        except TimeoutError:
            raise
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower():
                raise TimeoutError(f"GitHub request to {url} timed out") from exc
            raise OSError(f"GitHub network error: {reason!r}") from exc

    def get(
        self, url: str, headers: dict[str, str], timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        return self._open(url, headers, None, "GET", timeout_s)

    def post(
        self, url: str, headers: dict[str, str], body: bytes, timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        return self._open(url, headers, body, "POST", timeout_s)


# --- URL / diff parsing -------------------------------------------------------


def parse_repo_url(url: str) -> Optional[tuple[str, str]]:
    """Parse ``https://github.com/{owner}/{repo}`` into ``(owner, repo)``.

    Tolerates a ``.git`` suffix, trailing path fragments (``/tree/...`` is
    stripped because the regex stops at the first two path segments after
    the host), query strings and a ``www.`` prefix. Returns ``None`` for
    anything that is not a github.com repo URL.
    """
    m = _GITHUB_URL_RE.match((url or "").strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if not _OWNER_REPO_RE.fullmatch(owner) or not _OWNER_REPO_RE.fullmatch(repo):
        return None
    return owner, repo


def changed_files_from_diff(diff: str) -> list[str]:
    """Repo-relative paths touched by a git diff, in order of first touch.

    Primary source: ``diff --git a/<old> b/<new>`` headers (the ``b`` side,
    i.e. the new path; for renames that is the new name). Fallback: plain
    ``+++ b/<path>`` lines when a file header is missing. ``/dev/null``
    targets (deletions) are taken from the git header, so deleted files are
    still reported. Duplicates are removed; the first occurrence wins.
    """
    seen: set[str] = set()
    out: list[str] = []
    for line in (diff or "").splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"^diff --git a/(.+?) b/(.+?)\s*$", line)
            if not m:
                continue
            path = m.group(2)
        elif line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null" or not target.startswith("b/"):
                continue
            path = target[2:]
        else:
            continue
        path = path.strip().strip('"').strip()
        if not path or path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


# --- GitHub diff fetch ----------------------------------------------------------


def fetch_pr_diff(
    repo_url: str,
    pr_number: int,
    *,
    token: str = "",
    api_base: str = "",
    transport: Optional[GitHubTransport] = None,
    timeout_s: float = 30.0,
) -> str:
    """Fetch a PR's unified diff from the GitHub REST API.

    Raises:
        PRWireError: unsupported repo URL, PR number <= 0, HTTP 404, or any
            non-2xx status. TimeoutError / OSError propagate (the caller's
            per-run guard converts them to a skip).
    """
    if pr_number <= 0:
        raise PRWireError(f"invalid PR number: {pr_number}", permanent=True)
    pair = parse_repo_url(repo_url)
    if pair is None:
        raise PRWireError(f"unsupported GitHub repo URL: {repo_url!r}", permanent=True)
    owner, repo = pair
    base = (api_base or os.environ.get(ENV_GITHUB_API, "") or DEFAULT_GITHUB_API).strip()
    base = base.rstrip("/") or DEFAULT_GITHUB_API
    url = f"{base}/repos/{owner}/{repo}/pulls/{pr_number}"
    headers = {"Accept": "application/vnd.github.v3.diff", "User-Agent": "flowstallion-agent"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    do_get: GitHubTransport = (
        transport if transport is not None else _UrllibTransport()
    )
    try:
        status, _hdrs, body = do_get.get(url, headers, timeout_s)
    except TimeoutError as exc:
        raise PRWireError(f"GitHub diff fetch timed out: {exc}") from exc
    except OSError as exc:
        raise PRWireError(f"GitHub diff fetch network error: {exc}") from exc
    if status == 404:
        raise PRWireError(
            f"PR {owner}/{repo}#{pr_number} not found (HTTP 404)", permanent=True
        )
    if status < 200 or status >= 300:
        # 403 (bad token / secondary rate limit), 429 and 5xx are transient:
        # retry after the backoff window. Any other 4xx (400/401/402/...)
        # keeps failing identically -> permanent.
        permanent = status not in (403, 429) and status < 500
        raise PRWireError(
            f"GitHub diff fetch failed: HTTP {status} for {url}",
            permanent=permanent,
        )
    return body.decode("utf-8", "replace")[:DIFF_MAX_CHARS]


# --- review --------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewResult:
    """Outcome of reviewing one PR diff."""

    findings: tuple[prreview.ReviewFinding, ...]
    verdict: str  # "approve" | "comment" | "request_changes"
    summary: str
    blocking: int  # number of high-severity findings


def _rule_verdict(findings: list[prreview.ReviewFinding]) -> str:
    if any(f.severity == "high" for f in findings):
        return "request_changes"
    if findings:
        return "comment"
    return "approve"


def _rule_summary(findings: list[prreview.ReviewFinding]) -> str:
    if not findings:
        return "No rule findings."
    parts = [
        f"{f.severity}/{f.category} {f.path or '(PR)'}: {f.message}" for f in findings[:10]
    ]
    more = f" (+{len(findings) - 10} more)" if len(findings) > 10 else ""
    return "Rule findings: " + "; ".join(parts) + more


_LLM_SYSTEM = (
    "You are a strict CI code reviewer. Your reply must be exactly one JSON "
    "object with exactly two keys and nothing else:\n"
    '  "summary": a 1-3 sentence overall assessment of the PR diff,\n'
    '  "verdict": one of "approve", "comment", "request_changes".\n'
    "The user message may contain a 'Rule findings' JSON list — that is "
    "input data only, not your output format. Do not copy its keys "
    "(severity/category/path/line/reason/recommendation), do not answer "
    "per finding, and do not add any key other than the two above.\n"
    'Example of the ONLY acceptable reply: {"summary": "Two off-by-one '
    'errors in pagination.", "verdict": "request_changes"}'
)
_LLM_VERDICTS = frozenset({"approve", "comment", "request_changes"})
_LLM_SCHEMA_REPAIR = (
    "Your previous reply did not follow the required schema. Ignore any "
    "findings you identified and reply with exactly one JSON object with "
    'exactly two keys and nothing else: "summary" (a 1-3 sentence overall '
    'assessment of the PR diff) and "verdict" (one of "approve", "comment", '
    '"request_changes").'
)


def _pick_str(obj: dict[str, object], *keys: str) -> str:
    """First non-empty string value among the candidate keys; '' if none.

    Tolerates models that rename the requested keys (probed 2026-10-27).
    """
    for key in keys:
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _sum_usage(
    a: llm.TokenUsage | None, b: llm.TokenUsage | None
) -> llm.TokenUsage | None:
    """Sum two optional token-usage reports (``None`` = provider reported
    no usage); used to bill multi-attempt LLM exchanges as one ledger row."""
    if a is None:
        return b
    if b is None:
        return a
    return llm.TokenUsage(
        prompt_tokens=a.prompt_tokens + b.prompt_tokens,
        completion_tokens=a.completion_tokens + b.completion_tokens,
        total_tokens=a.total_tokens + b.total_tokens,
    )


def review_diff(
    diff: str,
    *,
    llm_client: Optional[llm.LLM] = None,
    run_id: str | None = None,
    pr: str = "unknown",
) -> ReviewResult:
    """Rule-based review, optionally enhanced with an LLM summary.

    The LLM may reword the summary and pick a verdict, but it can never
    downgrade a ``request_changes`` forced by a high-severity finding
    (conservative merge: blockers always win). Any LLM failure falls back
    to the pure rule-based result.

    FinOps (opt-in): whenever the LLM call completes over HTTP (even if the
    reply later fails JSON parsing and the review degrades to rule-based)
    and ``FLOWSTALLION_COST_LEDGER`` is set, the call's token usage is appended
    to that ledger with the ``run_id``/``pr`` labels (never raises, see
    :func:`flowstallion_agent.cost.maybe_record_llm_usage`).
    """
    findings = prreview.review(diff)
    verdict = _rule_verdict(findings)
    summary = _rule_summary(findings)
    if llm_client is not None:
        user = (
            "PR diff (git format):\n"
            f"{diff}\n\n"
            f"Rule findings: {json.dumps([f.to_dict() for f in findings], ensure_ascii=False)}"
        )
        try:
            obj = llm_client.chat_json(
                [
                    {"role": "system", "content": _LLM_SYSTEM},
                    {"role": "user", "content": user},
                ],
                max_tokens=2048,
            )
        except llm.LLMError as exc:
            obj = None
            print(f"[aiwire] [degraded] LLM JSON unavailable (run {run_id or '?'}): {exc}")
        usage_after_first = llm_client.last_usage
        # Schema-repair pass: some models answer a PR-review prompt with a
        # findings/patch object even though the system prompt demands
        # {"summary", "verdict"} only (observed 2026-10-28, qwen3.8-27b).
        # Echo the bad reply back once and demand the two-key schema; token
        # usage is accumulated across both attempts.
        if obj is not None and not (
            isinstance(obj, dict)
            and _pick_str(
                obj,
                "summary",
                "review_summary",
                "overview",
                "notes",
                "reason",
                "explanation",
            )
        ):
            repair_msgs = [
                {"role": "system", "content": _LLM_SYSTEM},
                {"role": "user", "content": user},
                {
                    "role": "assistant",
                    "content": json.dumps(obj, ensure_ascii=False),
                },
                {"role": "user", "content": _LLM_SCHEMA_REPAIR},
            ]
            try:
                obj2 = llm_client.chat_json(repair_msgs, max_tokens=2048)
            except llm.LLMError as exc:
                obj2 = None
                print(
                    f"[aiwire] [degraded] LLM schema repair failed (run {run_id or '?'}): {exc}"
                )
            if obj2 is not None:
                print(f"[aiwire] [repair] LLM schema repair succeeded (run {run_id or '?'})")
                obj = obj2
            llm_client.last_usage = _sum_usage(
                usage_after_first, llm_client.last_usage
            )
        # Lazy import: keeps ``python -m flowstallion_agent.cost`` free of the
        # runpy "module already in sys.modules" warning.
        # Recording anchor = "the LLM call completed over HTTP" (last_usage is
        # set only on success and cleared at the start of every call), not
        # "the reply was adopted": tokens are billed either way.
        from flowstallion_agent.cost import maybe_record_llm_usage

        maybe_record_llm_usage(llm_client, run_id=run_id, pr=pr)
        if isinstance(obj, dict):
            s = _pick_str(obj, "summary", "review_summary", "overview", "notes",
                          "reason", "explanation")
            if s:
                summary = s
            else:
                print(f"[aiwire] [degraded] LLM reply has no summary field; kept "
                      f"rule-based summary (run {run_id or '?'})")
            v = _pick_str(obj, "verdict", "decision", "recommendation")
            if v in _LLM_VERDICTS and verdict != "request_changes":
                verdict = v
        elif obj is not None:
            print(f"[aiwire] [degraded] LLM JSON reply is not an object; kept "
                  f"rule-based summary (run {run_id or '?'})")
    blocking = sum(1 for f in findings if f.severity == "high")
    return ReviewResult(
        findings=tuple(findings),
        verdict=verdict,
        summary=summary,
        blocking=blocking,
    )


# --- analysis payloads -----------------------------------------------------------


def _post_pr_review_analysis(
    client: SchedulerLike,
    run: RunInfo,
    diff: str,
    *,
    llm_client: Optional[llm.LLM],
) -> ReviewResult:
    result = review_diff(
        diff, llm_client=llm_client, run_id=str(run.id), pr=str(run.pr)
    )
    detail = json.dumps(
        {
            "summary": result.summary,
            "verdict": result.verdict,
            "blocking": result.blocking,
            "findings": [f.to_dict() for f in result.findings],
        },
        ensure_ascii=False,
    )
    if result.findings:
        root_cause = (
            f"PR review: {len(result.findings)} finding(s), "
            f"{result.blocking} blocking (verdict {result.verdict})"
        )
    else:
        root_cause = "PR review: clean (no findings, verdict approve)"
    suggested_fix = "; ".join(
        f.message for f in result.findings if f.severity == "high"
    )
    client.post_analysis(
        run.id,
        kind="pr_review",
        root_cause=root_cause,
        detail=detail,
        suggested_fix=suggested_fix,
    )
    return result


def _post_test_selection_analysis(
    client: SchedulerLike,
    run: RunInfo,
    changed: list[str],
    *,
    repo_root: str,
) -> testselect.TestSelection:
    sel = testselect.select_tests(changed, repo_root)
    detail = json.dumps(sel.to_dict(), ensure_ascii=False)
    n = len(sel.test_files())
    extra = []
    if sel.all_go:
        extra.append("all Go tests")
    if sel.all_python:
        extra.append("all Python tests")
    root_cause = (
        f"Test selection: {n} test file(s) for {len(changed)} changed file(s)"
        + (f" ({', '.join(extra)})" if extra else "")
    )
    client.post_analysis(
        run.id,
        kind="test_selection",
        root_cause=root_cause,
        detail=detail,
    )
    return sel


def _post_github_review(
    owner: str,
    repo: str,
    pr_number: int,
    diff: str,
    token: str,
    *,
    api_base: str,
    transport: Optional[GitHubTransport],
    timeout_s: float,
) -> bool:
    """Post the review to GitHub; degrade to False on any failure."""
    base = api_base.rstrip("/") or DEFAULT_GITHUB_API
    try:
        prreview.post_pr_review(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            diff=diff,
            token=token,
            transport=transport,
            timeout_s=timeout_s,
            api_base=base,
        )
        return True
    except (prreview.PRReviewError, prreview.PRReviewHTTPError) as exc:
        print(f"[aiwire] GitHub review post failed (degraded, analysis kept): {exc}")
        return False


def _resolve_selection_root(
    run: RunInfo,
    *,
    fallback: str,
    repo_cache: str,
    github_token: str,
    github_api: str,
    transport: Optional[GitHubTransport],
    timeout_s: float,
) -> str:
    """Map test selection against the PR's own head tree when a checkout
    cache is configured; degrade to ``fallback`` (the configured
    ``repo_root``) on any failure so the sidecar never blocks selection.
    """
    if not repo_cache:
        return fallback
    try:
        path = repocheck.resolve_pr_checkout(
            run.repo_url,
            run.pr,
            token=github_token,
            api_base=github_api,
            transport=transport,
            cache_dir=repo_cache,
            fetch_timeout_s=timeout_s,
        )
    except Exception as exc:  # defensive: repocheck reports+returns None itself
        print(f"[aiwire] [degraded] PR checkout error (run {run.id}): {exc}; "
              f"using repo_root")
        return fallback
    if path is None:
        print(f"[aiwire] [degraded] PR head checkout unavailable (run {run.id}); "
              f"using repo_root")
        return fallback
    print(f"[aiwire] run {run.id}: test selection uses PR head checkout {path}")
    return path


# --- per-run + poll-pass orchestration ---------------------------------------------


def process_pr_run(
    client: SchedulerLike,
    run: RunInfo,
    *,
    repo_root: str = ".",
    repo_cache: str = "",
    llm_client: Optional[llm.LLM] = None,
    github_token: str = "",
    github_api: str = "",
    transport: Optional[GitHubTransport] = None,
    timeout_s: float = 30.0,
    existing_kinds: frozenset[str] = frozenset(),
) -> dict[str, object]:
    """Wire one terminal PR run: review + test selection + optional GitHub post.

    Kinds already present in ``existing_kinds`` are not re-posted (idempotent
    re-passes). Raises ``PRWireError`` when the diff cannot be fetched or a
    kind still to post fails; the caller's per-run guard converts that into
    a skip (permanent or backed off, see :class:`PollSkipState`).

    ``repo_cache``: when non-empty, test selection maps changed files against
    the PR's own head checkout (``repocheck.resolve_pr_checkout``) instead of
    ``repo_root``; any checkout failure degrades to ``repo_root`` (the sidecar
    never blocks test selection). ``repo_cache`` also seeds the env default
    for the checkout cache directory when not set explicitly by the caller.

    Returns a result dict:
    ``{"reviewed", "selected", "review_posted", "findings", "blocking",
    "verdict", "tests", "skipped_review", "skipped_selection"}``.
    """
    pair = parse_repo_url(run.repo_url)
    result: dict[str, object] = {
        "reviewed": False,
        "selected": False,
        "review_posted": False,
        "findings": 0,
        "blocking": 0,
        "verdict": "",
        "tests": [],
        "skipped_review": False,
        "skipped_selection": False,
    }
    if run.pr <= 0 or not run.repo_url:
        raise PRWireError(f"run {run.id} carries no PR metadata", permanent=True)
    diff = fetch_pr_diff(
        run.repo_url,
        run.pr,
        token=github_token,
        api_base=github_api,
        transport=transport,
        timeout_s=timeout_s,
    )
    if not diff.strip():
        raise PRWireError(f"run {run.id}: empty PR diff", permanent=True)
    changed = changed_files_from_diff(diff)

    if "pr_review" not in existing_kinds:
        review = _post_pr_review_analysis(
            client, run, diff, llm_client=llm_client
        )
        result["reviewed"] = True
        result["findings"] = len(review.findings)
        result["blocking"] = review.blocking
        result["verdict"] = review.verdict
        if pair is not None and github_token:
            result["review_posted"] = _post_github_review(
                pair[0],
                pair[1],
                run.pr,
                diff,
                github_token,
                api_base=github_api or DEFAULT_GITHUB_API,
                transport=transport,
                timeout_s=timeout_s,
            )
    else:
        result["skipped_review"] = True

    if "test_selection" not in existing_kinds:
        sel_root = _resolve_selection_root(
            run,
            fallback=repo_root,
            repo_cache=repo_cache,
            github_token=github_token,
            github_api=github_api,
            transport=transport,
            timeout_s=timeout_s,
        )
        sel = _post_test_selection_analysis(
            client, run, changed, repo_root=sel_root
        )
        result["selected"] = True
        result["tests"] = sel.test_files()
    else:
        result["skipped_selection"] = True

    return result


# Backoff window for retryable wiring failures (rate limit / 5xx / timeout /
# network). Permanent failures are never retried.
_RETRY_BACKOFF_S = 60.0


class PollSkipState:
    """Per-process skip bookkeeping for :func:`poll_pr_runs`.

    The watch loop creates one instance and passes it to every pass so that
    doomed runs (unsupported host, missing PR, empty diff) are fetched at
    most once and transient failures (403/429/5xx, timeouts, network) are
    backed off instead of re-hit on every poll.

    - ``permanent``: run id -> reason. Fetched once, never retried.
    - ``retry_at``: run id -> monotonic deadline. Skipped until it passes.
    """

    def __init__(self) -> None:
        self.permanent: dict[int, str] = {}
        self.retry_at: dict[int, float] = {}

    def should_skip(self, run_id: int) -> bool:
        if run_id in self.permanent:
            return True
        deadline = self.retry_at.get(run_id)
        return deadline is not None and time.monotonic() < deadline


def _handle_skip(run_id: int, exc: Exception, skip_state: Optional[PollSkipState]) -> None:
    """Log a skipped run; classify it when skip state is in use."""
    if skip_state is None:
        print(f"[aiwire] skip run {run_id}: {exc}")
        return
    if isinstance(exc, PRWireError) and exc.permanent:
        skip_state.permanent[run_id] = str(exc)
        print(f"[aiwire] skip run {run_id} permanently: {exc}")
    else:
        skip_state.retry_at[run_id] = time.monotonic() + _RETRY_BACKOFF_S
        print(
            f"[aiwire] skip run {run_id} (retry in {int(_RETRY_BACKOFF_S)}s): {exc}"
        )


def poll_pr_runs(
    client: SchedulerLike,
    *,
    repo_root: str = ".",
    repo_cache: str = "",
    llm_client: Optional[llm.LLM] = None,
    github_token: str = "",
    github_api: str = "",
    transport: Optional[GitHubTransport] = None,
    timeout_s: float = 30.0,
    limit: int = 100,
    skip_state: Optional[PollSkipState] = None,
) -> int:
    """One pass: wire every new terminal PR run; return the count processed.

    A run qualifies when its status is terminal, it carries PR metadata
    (``pr > 0`` and ``repo_url``) and at least one of the two kinds
    (``pr_review`` / ``test_selection``) is not stored yet. Per-run errors
    are logged and skipped; the pass itself never raises (list failure -> 0).

    ``repo_cache``: forward to :func:`process_pr_run` — when set, test
    selection maps against the PR head checkout instead of ``repo_root``.

    With ``skip_state`` provided, permanent failures are remembered (no
    re-fetch for the process lifetime) and retryable failures are backed off
    for :data:`_RETRY_BACKOFF_S`; without it the pass behaves as before
    (every pass re-tries every pending run).
    """
    try:
        runs = client.list_runs(limit=limit)
    except ClientError as exc:
        print(f"[aiwire] list runs failed: {exc}")
        return 0
    processed = 0
    for run in runs:
        if run.status not in _PR_TERMINAL_STATES:
            continue
        if run.pr <= 0 or not run.repo_url:
            continue
        if skip_state is not None and skip_state.should_skip(run.id):
            continue
        try:
            existing = frozenset(a.kind for a in client.list_analyses(run.id))
        except ClientError as exc:
            print(f"[aiwire] skip run {run.id}: list analyses: {exc}")
            continue
        if {"pr_review", "test_selection"} <= existing:
            continue
        try:
            res = process_pr_run(
                client,
                run,
                repo_root=repo_root,
                repo_cache=repo_cache,
                llm_client=llm_client,
                github_token=github_token,
                github_api=github_api,
                transport=transport,
                timeout_s=timeout_s,
                existing_kinds=existing,
            )
        except Exception as exc:  # sidecar must stay alive past surprises
            _handle_skip(run.id, exc, skip_state)
            continue
        processed += 1
        verdict = res["verdict"] if isinstance(res["verdict"], str) else ""
        tests = res["tests"]
        n_tests = len(tests) if isinstance(tests, list) else 0
        print(
            f"[aiwire] run {run.id} PR #{run.pr}: "
            f"review={res['reviewed']}(skipped={res['skipped_review']}) "
            f"selection={res['selected']}(skipped={res['skipped_selection']}) "
            f"gh_review={res['review_posted']} "
            f"findings={res['findings']} blocking={res['blocking']} "
            f"verdict={verdict or '-'} tests={n_tests}"
        )
    return processed
