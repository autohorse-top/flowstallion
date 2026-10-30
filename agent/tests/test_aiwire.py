"""Tests for flowstallion_agent.aiwire (P7⑥ PR-run wiring).

All tests run in-process with fake transports (GitHub + LLM + scheduler
client); no network access.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from flowstallion_agent import aiwire, llm
from flowstallion_agent.aiwire import (
    DIFF_MAX_CHARS,
    PRWireError,
    changed_files_from_diff,
    fetch_pr_diff,
    parse_repo_url,
    poll_pr_runs,
    process_pr_run,
    review_diff,
)
from flowstallion_agent.client import AnalysisReport, RunInfo

DIFF_SAMPLE = (
    "diff --git a/pkg/demo/foo.go b/pkg/demo/foo.go\n"
    "index 111..222 100644\n"
    "--- a/pkg/demo/foo.go\n"
    "+++ b/pkg/demo/foo.go\n"
    "@@ -1,3 +1,6 @@\n"
    " package demo\n"
    "\n"
    "-func old() {}\n"
    "+func NewThing() int {\n"
    "+\treturn 42\n"
    "+}\n"
    "+var token = \"ghp_AbCdEfGhIjKlMnOpQrSt\"\n"
)
# ghp_ token (20+ chars) => hardcoded-credential high finding => request_changes

DIFF_CLEAN = (
    "diff --git a/docs/notes.md b/docs/notes.md\n"
    "--- a/docs/notes.md\n"
    "+++ b/docs/notes.md\n"
    "@@ -1 +1 @@\n"
    "-old\n"
    "+new\n"
)


# --- fakes ----------------------------------------------------------------------


class FakeGitHub:
    """Stands in for GitHub REST: diff GET + reviews POST."""

    def __init__(self, diff: str = DIFF_SAMPLE, status: int = 200) -> None:
        self.diff = diff
        self.status = status
        self.get_urls: list[tuple[str, dict[str, str]]] = []
        self.reviews: list[tuple[str, dict[str, object]]] = []

    def get(
        self, url: str, headers: dict[str, str], timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        self.get_urls.append((url, dict(headers)))
        return self.status, {}, self.diff.encode("utf-8")

    def post(
        self, url: str, headers: dict[str, str], body: bytes, timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        parsed = json.loads(body.decode("utf-8"))
        self.reviews.append((url, parsed if isinstance(parsed, dict) else {}))
        return 201, {}, b'{"id": 1}'


class FakeLLMTransport:
    """Implements llm.Transport (POST /chat/completions) in-process."""

    def __init__(
        self,
        reply: str = '{"summary": "LLM says: looks mostly fine", "verdict": "comment"}',
        usage: dict[str, int] | None = None,
    ) -> None:
        self.reply = reply
        self.usage = usage
        self.calls: list[bytes] = []

    def post(
        self, url: str, headers: dict[str, str], body: bytes, timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        self.calls.append(body)
        payload: dict[str, object] = {
            "choices": [{"message": {"content": self.reply}}]
        }
        if self.usage is not None:
            payload["usage"] = self.usage
        return 200, {}, json.dumps(payload).encode("utf-8")


def make_llm(
    reply: str, usage: dict[str, int] | None = None
) -> llm.LLM:
    cfg = llm.LLMConfig(
        base_url="http://fake", api_key="test-key", model="m", timeout_s=5.0, max_retries=0
    )
    return llm.LLM(cfg, transport=FakeLLMTransport(reply, usage=usage))


class _SeqLLMTransport:
    """FIFO scripted LLM replies (one per HTTP call) for multi-attempt tests."""

    def __init__(
        self,
        replies: list[str],
        usage: dict[str, int] | None = None,
    ) -> None:
        self.replies = list(replies)
        self.usage = usage
        self.calls: list[bytes] = []

    def post(
        self, url: str, headers: dict[str, str], body: bytes, timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        self.calls.append(body)
        if not self.replies:
            raise AssertionError("_SeqLLMTransport: out of scripted replies")
        reply = self.replies.pop(0)
        payload: dict[str, object] = {
            "choices": [{"message": {"content": reply}}]
        }
        if self.usage is not None:
            payload["usage"] = self.usage
        return 200, {}, json.dumps(payload).encode("utf-8")


class FakeScheduler:
    """Duck-typed SchedulerLike: list_runs / post_analysis / list_analyses."""

    def __init__(self, runs: list[RunInfo] | None = None) -> None:
        self.runs = runs or []
        self.posts: list[dict[str, object]] = []
        self.analyses: dict[int, list[str]] = {}

    def list_runs(self, limit: int = 50) -> list[RunInfo]:
        return self.runs[:limit]

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
        self.posts.append(
            {
                "run_id": run_id,
                "step_id": step_id,
                "kind": kind,
                "root_cause": root_cause,
                "detail": detail,
                "suggested_fix": suggested_fix,
            }
        )
        self.analyses.setdefault(run_id, []).append(kind)

    def list_analyses(self, run_id: int) -> list[AnalysisReport]:
        return [
            AnalysisReport(
                step_id="",
                kind=k,
                root_cause="x",
                detail="",
                suggested_fix="",
                command="",
                log_excerpt="",
                created_at="",
            )
            for k in self.analyses.get(run_id, [])
        ]


def make_run(
    run_id: int = 7,
    status: str = "success",
    pr: int = 12,
    repo_url: str = "https://github.com/octo/widget",
) -> RunInfo:
    return RunInfo(
        id=run_id,
        pipeline_id=1,
        status=status,
        trigger="pull_request",
        source_ref="feature",
        pr=pr,
        base_ref="main",
        head_ref="feature",
        repo_url=repo_url,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:01:00Z",
        created_at="2026-01-01T00:00:00Z",
    )


def make_repo(tmp: str) -> None:
    """Repo checkout with pkg/demo/{foo.go,foo_test.go} + go.mod."""
    pkg = os.path.join(tmp, "pkg", "demo")
    os.makedirs(pkg)
    for name in ("foo.go", "foo_test.go"):
        with open(os.path.join(pkg, name), "w", encoding="utf-8") as f:
            f.write("package demo\n")
    with open(os.path.join(tmp, "go.mod"), "w", encoding="utf-8") as f:
        f.write("module widget\n\ngo 1.22\n")


# --- parse_repo_url ---------------------------------------------------------------


def test_parse_repo_url_basic() -> None:
    assert parse_repo_url("https://github.com/octo/widget") == ("octo", "widget")


def test_parse_repo_url_git_suffix_and_www() -> None:
    assert parse_repo_url("https://www.github.com/octo/widget.git") == ("octo", "widget")


def test_parse_repo_url_rejects_non_github() -> None:
    assert parse_repo_url("https://gitlab.com/octo/widget") is None
    assert parse_repo_url("https://example.com/octo/widget") is None


def test_parse_repo_url_rejects_empty_and_garbage() -> None:
    assert parse_repo_url("") is None
    assert parse_repo_url("not a url") is None


# --- changed_files_from_diff ---------------------------------------------------------


def test_changed_files_basic() -> None:
    assert changed_files_from_diff(DIFF_SAMPLE) == ["pkg/demo/foo.go"]


def test_changed_files_renamed_and_deleted() -> None:
    diff = (
        "diff --git a/old_name.py b/new_name.py\n"
        "similarity index 95%\n"
        "rename from old_name.py\n"
        "rename to new_name.py\n"
        "--- a/old_name.py\n"
        "+++ b/new_name.py\n"
        "diff --git a/gone/x.py b/gone/x.py\n"
        "deleted file mode 100644\n"
        "--- a/gone/x.py\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-foo\n"
    )
    assert changed_files_from_diff(diff) == ["new_name.py", "gone/x.py"]


def test_changed_files_dedup_and_plusplus_fallback() -> None:
    diff = (
        "diff --git a/a.py b/a.py\n"
        "+++ b/a.py\n"
        "@@ -1 +1 @@\n"
        "-x\n"
        "+y\n"
        "diff --git a/b.py b/b.py\n"
        "+++ b/b.py\n"
        "@@ -1 +1 @@\n"
        "-x\n"
        "+y\n"
    )
    assert changed_files_from_diff(diff) == ["a.py", "b.py"]
    assert changed_files_from_diff("no diff here at all") == []


# --- fetch_pr_diff -----------------------------------------------------------------


def test_fetch_pr_diff_ok() -> None:
    gh = FakeGitHub()
    text = fetch_pr_diff(
        "https://github.com/octo/widget",
        12,
        token="tok",
        api_base="http://127.0.0.1:9",
        transport=gh,
    )
    assert text == DIFF_SAMPLE
    url, headers = gh.get_urls[0]
    assert url == "http://127.0.0.1:9/repos/octo/widget/pulls/12"
    assert headers["Accept"] == "application/vnd.github.v3.diff"
    assert headers["Authorization"] == "Bearer tok"


def test_fetch_pr_diff_404_raises() -> None:
    gh = FakeGitHub(status=404)
    with pytest.raises(PRWireError, match="404"):
        fetch_pr_diff("https://github.com/octo/widget", 99, transport=gh)


def test_fetch_pr_diff_http_error_raises() -> None:
    gh = FakeGitHub(status=500)
    with pytest.raises(PRWireError, match="HTTP 500"):
        fetch_pr_diff("https://github.com/octo/widget", 12, transport=gh)


def test_fetch_pr_diff_bad_url_or_number_raises() -> None:
    with pytest.raises(PRWireError):
        fetch_pr_diff("https://gitlab.com/o/r", 1, transport=FakeGitHub())
    with pytest.raises(PRWireError):
        fetch_pr_diff("https://github.com/octo/widget", 0, transport=FakeGitHub())


def test_fetch_pr_diff_truncates_to_cap() -> None:
    big = "x" * (DIFF_MAX_CHARS + 5000)
    text = fetch_pr_diff("https://github.com/octo/widget", 1, transport=FakeGitHub(diff=big))
    assert len(text) == DIFF_MAX_CHARS


# --- review_diff ---------------------------------------------------------------------


def test_review_diff_clean_diff_approves() -> None:
    res = review_diff(DIFF_CLEAN)
    assert res.verdict == "approve"
    assert res.findings == ()
    assert res.blocking == 0


def test_review_diff_high_severity_forces_request_changes() -> None:
    res = review_diff(DIFF_SAMPLE)
    assert res.blocking >= 1
    assert res.verdict == "request_changes"
    assert any(f.category == "security" for f in res.findings)


def test_review_diff_llm_summary_used_but_cannot_downgrade() -> None:
    llm_c = make_llm('{"summary": "LLM verdict: ship it", "verdict": "approve"}')
    res = review_diff(DIFF_SAMPLE, llm_client=llm_c)
    # blocker present -> verdict stays request_changes despite LLM "approve"
    assert res.verdict == "request_changes"
    assert res.summary == "LLM verdict: ship it"


def test_review_diff_llm_verdict_applies_when_no_blockers() -> None:
    llm_c = make_llm('{"summary": "minor nits", "verdict": "comment"}')
    # diff with only a style finding (bare except) -> rule verdict "comment"
    diff = (
        "diff --git a/m.py b/m.py\n"
        "--- a/m.py\n"
        "+++ b/m.py\n"
        "@@ -1,2 +1,3 @@\n"
        " try:\n"
        "     pass\n"
        "+except:\n"
    )
    res = review_diff(diff, llm_client=llm_c)
    assert res.verdict == "comment"
    assert res.summary == "minor nits"


def test_review_diff_llm_failure_falls_back_to_rules() -> None:
    llm_c = make_llm("this is not json")
    res = review_diff(DIFF_CLEAN, llm_client=llm_c)
    assert res.verdict == "approve"
    assert res.summary == "No rule findings."


# --- review_diff cost-ledger wiring -------------------------------------------------------


def test_review_diff_records_llm_usage_to_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from flowstallion_agent.cost import CostLedger

    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(ledger))
    llm_c = make_llm(
        '{"summary": "ok", "verdict": "approve"}',
        usage={"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
    )
    res = review_diff(DIFF_CLEAN, llm_client=llm_c, run_id="42", pr="7")
    assert res.summary == "ok"
    recs = CostLedger(ledger).records()
    assert len(recs) == 1
    rec = recs[0]
    assert rec.source == "llm"
    assert rec.run_id == "42"
    assert rec.pr == "7"
    assert (rec.prompt_tokens, rec.completion_tokens, rec.total_tokens) == (11, 3, 14)


def test_review_diff_records_usage_even_if_verdict_not_adopted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """LLM said approve but a high-severity finding forces request_changes:
    tokens were consumed, so the call must still be recorded."""
    from flowstallion_agent.cost import CostLedger

    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(ledger))
    llm_c = make_llm(
        '{"summary": "ship it", "verdict": "approve"}',
        usage={"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    )
    res = review_diff(DIFF_SAMPLE, llm_client=llm_c, run_id="43", pr="8")
    assert res.verdict == "request_changes"  # blocker wins
    assert len(CostLedger(ledger).records()) == 1


def test_review_diff_no_ledger_record_when_llm_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(ledger))
    llm_c = make_llm("this is not json")  # chat_json raises LLMError
    res = review_diff(DIFF_CLEAN, llm_client=llm_c, run_id="44", pr="9")
    assert res.summary == "No rule findings."
    assert not ledger.exists()


def test_review_diff_no_ledger_when_env_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("FLOWSTALLION_COST_LEDGER", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))  # default path would land here
    llm_c = make_llm(
        '{"summary": "ok", "verdict": "approve"}',
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    )
    res = review_diff(DIFF_CLEAN, llm_client=llm_c, run_id="45", pr="10")
    assert res.summary == "ok"
    assert not (tmp_path / ".flowstallion").exists()


# --- process_pr_run --------------------------------------------------------------------


def test_process_pr_run_writes_both_analyses_and_posts_review() -> None:
    client = FakeScheduler()
    gh = FakeGitHub()
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        res = process_pr_run(
            client,
            make_run(),
            repo_root=tmp,
            llm_client=None,
            github_token="ghp_test123",
            github_api="http://fake",
            transport=gh,
        )
    assert res["reviewed"] is True and res["selected"] is True
    assert res["review_posted"] is True
    kinds = [p["kind"] for p in client.posts]
    assert kinds == ["pr_review", "test_selection"]
    review = next(p for p in client.posts if p["kind"] == "pr_review")
    assert review["step_id"] == ""
    detail = json.loads(str(review["detail"]))
    assert detail["verdict"] == "request_changes"
    assert detail["blocking"] >= 1
    assert any(f["category"] == "security" for f in detail["findings"])
    # GitHub review POSTed with REQUEST_CHANGES (high severity)
    url, body = gh.reviews[0]
    assert url == "http://fake/repos/octo/widget/pulls/12/reviews"
    assert body["event"] == "REQUEST_CHANGES"
    sel = next(p for p in client.posts if p["kind"] == "test_selection")
    assert json.loads(str(sel["detail"]))["go_tests"] == ["pkg/demo/foo_test.go"]


def test_process_pr_run_records_llm_usage_with_run_labels(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """run 7 / PR 12 labels must land in the ledger (regression for the
    run 31 gap where PR-review LLM calls left no cost record)."""
    from flowstallion_agent.cost import CostLedger

    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(ledger))
    client = FakeScheduler()
    gh = FakeGitHub()
    llm_c = make_llm(
        '{"summary": "ok", "verdict": "approve"}',
        usage={"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
    )
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        res = process_pr_run(
            client,
            make_run(),  # run_id=7, pr=12
            repo_root=tmp,
            llm_client=llm_c,
            github_token="ghp_test123",
            github_api="http://fake",
            transport=gh,
        )
    assert res["reviewed"] is True
    recs = CostLedger(ledger).records()
    assert len(recs) == 1
    assert recs[0].run_id == "7"
    assert recs[0].pr == "12"
    assert recs[0].total_tokens == 12


def test_process_pr_run_without_token_skips_github_post_only() -> None:
    client = FakeScheduler()
    gh = FakeGitHub()
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        res = process_pr_run(
            client,
            make_run(),
            repo_root=tmp,
            github_token="",
            github_api="http://fake",
            transport=gh,
        )
    assert res["reviewed"] is True and res["selected"] is True
    assert res["review_posted"] is False
    assert gh.reviews == []


def test_process_pr_run_dedup_skips_existing_kinds() -> None:
    client = FakeScheduler()
    client.analyses[7] = ["pr_review", "test_selection"]
    gh = FakeGitHub()
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        res = process_pr_run(
            client,
            make_run(),
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
            existing_kinds=frozenset(client.analyses[7]),
        )
    assert res["skipped_review"] is True and res["skipped_selection"] is True
    assert client.posts == []
    assert gh.reviews == []


def test_process_pr_run_diff_failure_raises_and_posts_nothing() -> None:
    client = FakeScheduler()
    gh = FakeGitHub(status=500)
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        with pytest.raises(PRWireError):
            process_pr_run(
                client,
                make_run(),
                repo_root=tmp,
                github_token="t",
                github_api="http://fake",
                transport=gh,
            )
    assert client.posts == []
    assert gh.reviews == []


def test_process_pr_run_missing_pr_metadata_raises() -> None:
    client = FakeScheduler()
    with pytest.raises(PRWireError):
        process_pr_run(client, make_run(pr=0), transport=FakeGitHub())
    with pytest.raises(PRWireError):
        process_pr_run(client, make_run(repo_url=""), transport=FakeGitHub())


# --- poll_pr_runs ------------------------------------------------------------------------


def test_poll_pr_runs_filters_and_counts() -> None:
    runs = [
        make_run(1, status="success", pr=12),  # wired
        make_run(2, status="running", pr=12),  # not terminal
        make_run(3, status="success", pr=0),  # manual, no PR
        make_run(4, status="failed", pr=13, repo_url="https://github.com/octo/widget"),
        make_run(5, status="success", pr=14),  # already wired
    ]
    client = FakeScheduler(runs)
    client.analyses[5] = ["pr_review", "test_selection"]
    gh = FakeGitHub()
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        n = poll_pr_runs(
            client,
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
        )
    assert n == 2
    assert set(client.analyses.keys()) == {1, 4, 5}
    assert client.analyses[1] == ["pr_review", "test_selection"]
    assert len(gh.reviews) == 2


def test_poll_pr_runs_never_raises_on_bad_runs() -> None:
    client = FakeScheduler(runs=[make_run(1)])
    gh = FakeGitHub(status=404)  # diff fetch fails for every run
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        n = poll_pr_runs(
            client,
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
        )
    assert n == 0
    assert client.posts == []


def test_review_diff_records_usage_when_json_parse_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HTTP success + usage, but unparseable reply: degrades to rule result,
    yet the tokens are still billed (ledger row written)."""
    from flowstallion_agent.cost import CostLedger

    class ParseFailTransport:
        def post(
            self,
            url: str,
            headers: dict[str, str],
            data: bytes,
            timeout_s: float,
        ) -> tuple[int, dict[str, str], bytes]:
            body = json.dumps({
                "choices": [{"message": {"content": "this is not json"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 6,
                          "total_tokens": 18},
            }).encode("utf-8")
            return 200, {}, body

    model = llm.LLM(
        llm.LLMConfig(
            base_url="https://llm.example/v1",
            api_key="sk-test",
            model="gpt-4o-mini",
            max_retries=0,
        ),
        transport=ParseFailTransport(),
    )
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(ledger))
    res = review_diff(DIFF_CLEAN, llm_client=model, run_id="9", pr="pr-9")
    assert res.summary == "No rule findings."  # degraded to rule summary
    recs = CostLedger(ledger).records()
    assert len(recs) == 1
    assert recs[0].run_id == "9"
    assert recs[0].pr == "pr-9"
    # The unparseable reply triggers one internal repair pass: both HTTP
    # calls billed, so the ledger row holds the sum of both attempts.
    assert (recs[0].prompt_tokens, recs[0].completion_tokens,
            recs[0].total_tokens) == (24, 12, 36)


def test_review_diff_adopts_reason_alias() -> None:
    """A reply that renames summary to 'reason' still has its text adopted."""
    body = json.dumps({
        "choices": [
            {"message": {"content": json.dumps({
                "reason": "Solid overall; one nit on the retry loop.",
                "verdict": "approve",
            })}}
        ],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2,
                  "total_tokens": 6},
    }).encode("utf-8")

    class AliasTransport:
        def post(
            self,
            url: str,
            headers: dict[str, str],
            data: bytes,
            timeout_s: float,
        ) -> tuple[int, dict[str, str], bytes]:
            return 200, {}, body

    model = llm.LLM(
        llm.LLMConfig(
            base_url="https://llm.example/v1",
            api_key="sk-test",
            model="gpt-4o-mini",
            max_retries=0,
        ),
        transport=AliasTransport(),
    )
    res = review_diff(DIFF_CLEAN, llm_client=model, run_id="10", pr="pr-10")
    assert res.summary == "Solid overall; one nit on the retry loop."
    assert res.verdict == "approve"


def test_review_diff_schema_repair_adopts_followup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wrong-schema reply (findings/patch keys, observed 2026-10-28 on the
    qwen gateway) triggers exactly one repair call; the follow-up
    {summary, verdict} reply is adopted and both attempts are billed."""
    from flowstallion_agent.cost import CostLedger

    wrong = '{"findings": [{"message": "nit"}], "suggested_patch": "x"}'
    right = '{"summary": "LLM says: mostly fine", "verdict": "comment"}'
    transport = _SeqLLMTransport(
        [wrong, right],
        usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    )
    model = llm.LLM(
        llm.LLMConfig(
            base_url="https://llm.example/v1",
            api_key="sk-test",
            model="gpt-4o-mini",
            max_retries=0,
        ),
        transport=transport,
    )
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(ledger))
    res = review_diff(DIFF_CLEAN, llm_client=model, run_id="50", pr="5")
    assert res.summary == "LLM says: mostly fine"
    assert res.verdict == "comment"
    assert len(transport.calls) == 2  # original + one schema repair
    recs = CostLedger(ledger).records()
    assert len(recs) == 1
    assert (recs[0].prompt_tokens, recs[0].completion_tokens,
            recs[0].total_tokens) == (20, 10, 30)


def test_review_diff_schema_repair_failure_keeps_rule_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the repair reply is still off-schema, keep the rule-based summary
    but still bill both LLM calls."""
    from flowstallion_agent.cost import CostLedger

    wrong = '{"findings": [], "suggested_patch": "x"}'
    transport = _SeqLLMTransport(
        [wrong, wrong],
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    )
    model = llm.LLM(
        llm.LLMConfig(
            base_url="https://llm.example/v1",
            api_key="sk-test",
            model="gpt-4o-mini",
            max_retries=0,
        ),
        transport=transport,
    )
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(ledger))
    res = review_diff(DIFF_CLEAN, llm_client=model, run_id="51", pr="6")
    assert res.summary == "No rule findings."
    assert res.verdict == "approve"
    assert len(transport.calls) == 2
    recs = CostLedger(ledger).records()
    assert len(recs) == 1
    assert (recs[0].prompt_tokens, recs[0].completion_tokens,
            recs[0].total_tokens) == (2, 2, 4)


# --- poll skip state (permanent / backoff) --------------------------------------


def test_poll_pr_runs_permanent_skip_never_refetches() -> None:
    """A run whose diff fetch 404s is remembered and never fetched again."""
    runs = [make_run(1, status="success", pr=999)]
    client = FakeScheduler(runs)
    gh = FakeGitHub(status=404)
    st = aiwire.PollSkipState()
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        for _ in range(3):
            n = poll_pr_runs(
                client,
                repo_root=tmp,
                github_token="t",
                github_api="http://fake",
                transport=gh,
                skip_state=st,
            )
            assert n == 0
    assert len(gh.get_urls) == 1  # fetched exactly once, then remembered
    assert 1 in st.permanent


def test_poll_pr_runs_retryable_backoff() -> None:
    """A 5xx failure is not retried inside the backoff window."""
    runs = [make_run(2, status="success", pr=12)]
    client = FakeScheduler(runs)
    gh = FakeGitHub(status=500)
    st = aiwire.PollSkipState()
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        poll_pr_runs(
            client,
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
            skip_state=st,
        )
        assert len(gh.get_urls) == 1
        assert st.should_skip(2)
        # Inside the backoff window: no fetch.
        poll_pr_runs(
            client,
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
            skip_state=st,
        )
        assert len(gh.get_urls) == 1
        # Past the window: fetch again.
        st.retry_at[2] = time.monotonic() - 1.0
        poll_pr_runs(
            client,
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
            skip_state=st,
        )
        assert len(gh.get_urls) == 2


def test_poll_pr_runs_no_skip_state_refetches_each_pass() -> None:
    """Legacy behaviour: without a skip state, every pass re-fetches."""
    runs = [make_run(3, status="failed", pr=999)]
    client = FakeScheduler(runs)
    gh = FakeGitHub(status=404)
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        poll_pr_runs(
            client,
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
        )
        poll_pr_runs(
            client,
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
        )
    assert len(gh.get_urls) == 2


def test_fetch_pr_diff_permanent_flags() -> None:
    for repo, pr in [
        ("https://gitlab.com/o/r", 1),
        ("https://github.com/octo/widget", 0),
        ("not a url", 1),
    ]:
        with pytest.raises(PRWireError) as ei:
            fetch_pr_diff(repo, pr, transport=FakeGitHub())
        assert ei.value.permanent is True, (repo, pr)
    for status in (404, 400, 401):
        with pytest.raises(PRWireError) as ei:
            fetch_pr_diff(
                "https://github.com/octo/widget", 1, transport=FakeGitHub(status=status)
            )
        assert ei.value.permanent is True, status
    for status in (429, 500, 403):
        with pytest.raises(PRWireError) as ei:
            fetch_pr_diff(
                "https://github.com/octo/widget", 1, transport=FakeGitHub(status=status)
            )
        assert ei.value.permanent is False, status


def test_poll_pr_runs_empty_diff_permanent() -> None:
    runs = [make_run(4, status="success", pr=12)]
    client = FakeScheduler(runs)
    st = aiwire.PollSkipState()
    gh = FakeGitHub(diff="")
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        poll_pr_runs(
            client,
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
            skip_state=st,
        )
        poll_pr_runs(
            client,
            repo_root=tmp,
            github_token="t",
            github_api="http://fake",
            transport=gh,
            skip_state=st,
        )
    assert len(gh.get_urls) == 1
    assert 4 in st.permanent


# --- PR head checkout (G1 real-repo test selection) -------------------------------


def _git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, env=env
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {args} failed: {proc.stderr.strip()}")
    return proc.stdout


def make_probe_remote(base: Path) -> str:
    """Local bare remote with probe.py + tests/test_probe.py; returns head sha."""
    work = base / "work"
    work.mkdir()
    (work / "tests").mkdir()
    (work / "probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    (work / "tests" / "test_probe.py").write_text(
        "import probe\n\n\ndef test_value():\n    assert probe.VALUE == 1\n",
        encoding="utf-8",
    )
    _git(work, "init", "-q")
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "init")
    sha = _git(work, "rev-parse", "HEAD").strip()
    (base / "octo").mkdir()
    _git(work, "clone", "-q", "--bare", str(work), str(base / "octo" / "widget.git"))
    return sha


class PRJsonGitHub:
    """Header-aware fake: PR metadata JSON for json Accept, diff otherwise."""

    def __init__(self, diff: str, pr_payload: dict[str, object]) -> None:
        self.diff = diff
        self.pr_payload = pr_payload
        self.reviews: list[tuple[str, dict[str, object]]] = []

    def get(
        self, url: str, headers: dict[str, str], timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        if headers.get("Accept") == "application/vnd.github+json":
            return 200, {}, json.dumps(self.pr_payload).encode("utf-8")
        return 200, {}, self.diff.encode("utf-8")

    def post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_s: float,
    ) -> tuple[int, dict[str, str], bytes]:
        self.reviews.append((url, json.loads(body.decode("utf-8"))))
        return 201, {}, b"{}"


PROBE_DIFF = (
    "diff --git a/probe.py b/probe.py\n"
    "index 111..222 100644\n"
    "--- a/probe.py\n"
    "+++ b/probe.py\n"
    "@@ -1 +1 @@\n"
    "-VALUE = 1\n"
    "+VALUE = 2\n"
)


def test_process_pr_run_uses_pr_head_checkout_for_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With repo_cache set, selection must map against the PR head tree."""
    base = tmp_path / "remotes"
    base.mkdir()
    sha = make_probe_remote(base)
    fallback = tmp_path / "fallback"
    fallback.mkdir()  # empty fallback: only the checkout has tests/
    cache = tmp_path / "cache"
    monkeypatch.setenv("FLOWSTALLION_GIT_CLONE_BASE", str(base))
    monkeypatch.setenv("FLOWSTALLION_GIT_PR_REF", "HEAD")
    client = FakeScheduler()
    gh = PRJsonGitHub(PROBE_DIFF, {"head": {"sha": sha}})
    res = process_pr_run(
        client,
        make_run(),
        repo_root=str(fallback),
        repo_cache=str(cache),
        llm_client=None,
        github_token="t",
        github_api="http://fake",
        transport=gh,
    )
    assert res["selected"] is True
    assert res["tests"] == ["tests/test_probe.py"]
    sel = next(p for p in client.posts if p["kind"] == "test_selection")
    detail = json.loads(str(sel["detail"]))
    assert detail["python_tests"] == ["tests/test_probe.py"]
    assert (cache / sha / "probe.py").read_text(encoding="utf-8") == "VALUE = 1\n"


def test_process_pr_run_checkout_failure_degrades_to_repo_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Broken git binary: selection degrades to repo_root, wiring still succeeds."""
    monkeypatch.setenv("FLOWSTALLION_GIT_BIN", "/nonexistent/git-bin-xyz")
    client = FakeScheduler()
    gh = PRJsonGitHub(DIFF_SAMPLE, {"head": {"sha": "a" * 40}})
    with tempfile.TemporaryDirectory() as tmp:
        make_repo(tmp)
        res = process_pr_run(
            client,
            make_run(),
            repo_root=tmp,
            repo_cache=str(tmp_path / "cache"),
            llm_client=None,
            github_token="t",
            github_api="http://fake",
            transport=gh,
        )
    assert res["selected"] is True
    assert res["tests"] == ["pkg/demo/foo_test.go"]
    sel = next(p for p in client.posts if p["kind"] == "test_selection")
    detail = json.loads(str(sel["detail"]))
    assert detail["go_tests"] == ["pkg/demo/foo_test.go"]


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
