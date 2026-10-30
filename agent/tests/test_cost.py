"""Tests for flowstallion_agent.cost — ledger, pricing, aggregation, CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Mapping

import pytest

from flowstallion_agent.cost import (
    CostLedger,
    CostRecord,
    aggregate,
    cloud_cost_sample,
    maybe_record_llm_usage,
    price_cost,
    record_llm_usage,
)
from flowstallion_agent.llm import LLM, LLMConfig

AGENT_DIR = Path(__file__).resolve().parents[1]


def make_llm(usage: Mapping[str, object] | None, model: str = "gpt-4o-mini") -> LLM:
    """LLM whose fake transport replies once with the given usage block.

    The reply content is a valid triage JSON object so that
    ``triage.analyze(llm=...)`` takes the LLM path (kind == "llm").
    """
    reply = json.dumps(
        {"root_cause": "sample cause", "detail": "d", "suggested_fix": "f"}
    )
    payload: dict[str, object] = {"choices": [{"message": {"content": reply}}]}
    if usage is not None:
        payload["usage"] = usage
    body = json.dumps(payload).encode("utf-8")

    class OnceTransport:
        def post(
            self,
            url: str,
            headers: dict[str, str],
            data: bytes,
            timeout_s: float,
        ) -> tuple[int, dict[str, str], bytes]:
            return 200, {}, body

    return LLM(
        LLMConfig(base_url="https://llm.example/v1", api_key="sk-test", model=model),
        transport=OnceTransport(),
    )


def chat_once(llm: LLM) -> None:
    llm.chat([{"role": "user", "content": "hi"}])


# --- ledger round-trip -------------------------------------------------------

def test_ledger_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "sub" / "ledger.jsonl"
    ledger = CostLedger(p)
    llm_rec = CostRecord(
        ts="2026-10-22T09:00:00Z",
        source="llm",
        run_id="42",
        pr="pr-101",
        team="team-infra",
        model="gpt-4o-mini",
        prompt_tokens=100,
        completion_tokens=50,
        total_tokens=150,
        cost=0.0001,
    )
    cloud_rec = CostRecord(
        ts="2026-10-22T00:00:00Z",
        source="cloud",
        run_id=None,
        pr="pr-101",
        team="team-infra",
        namespace="prod-infra",
        pod="api-1",
        cost=1.5,
    )
    ledger.append(llm_rec)
    ledger.append(cloud_rec)
    got = CostLedger(p).records()
    assert got == [llm_rec, cloud_rec]


def test_records_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    assert CostLedger(p).records() == []


def test_records_malformed_line_has_line_number(tmp_path: Path) -> None:
    p = tmp_path / "bad.jsonl"
    good = CostRecord(ts="t", source="llm", run_id=None)
    p.write_text(
        json.dumps(good.to_dict()) + "\n" + "not json\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="line 2"):
        CostLedger(p).records()


def test_from_dict_type_error(tmp_path: Path) -> None:
    rec = CostRecord(ts="t", source="llm", run_id=None)
    d = rec.to_dict()
    d["prompt_tokens"] = "many"
    with pytest.raises(ValueError, match="prompt_tokens"):
        CostRecord.from_dict(d)


# --- pricing ----------------------------------------------------------------

def test_price_cost_table_values() -> None:
    assert price_cost("gpt-4o-mini", 1_000_000, 0) == pytest.approx(0.15)
    assert price_cost("gpt-4o-mini", 0, 1_000_000) == pytest.approx(0.60)
    assert price_cost("gpt-4o", 1_000_000, 1_000_000) == pytest.approx(12.50)


def test_price_cost_unknown_model_zero() -> None:
    assert price_cost("no-such-model", 123_456, 789) == 0.0


def test_price_cost_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLOWSTALLION_LLM_PRICE_IN", "1.0")
    monkeypatch.setenv("FLOWSTALLION_LLM_PRICE_OUT", "2.0")
    # Env applies to any model, even one in the table.
    assert price_cost("gpt-4o-mini", 1_000_000, 0) == pytest.approx(1.0)
    assert price_cost("whatever", 0, 1_000_000) == pytest.approx(2.0)


def test_price_cost_env_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLOWSTALLION_LLM_PRICE_IN", "3.0")
    # OUT not set -> 0.0.
    assert price_cost("any-model", 1_000_000, 1_000_000) == pytest.approx(3.0)


def test_price_cost_env_unset_no_table_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FLOWSTALLION_LLM_PRICE_IN", raising=False)
    monkeypatch.delenv("FLOWSTALLION_LLM_PRICE_OUT", raising=False)
    assert price_cost("gpt-4o", 1_000_000, 0) == pytest.approx(2.50)


def test_env_price_invalid_value_warns_once(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import flowstallion_agent.cost as cost_mod

    cost_mod._warned_env_prices.clear()
    monkeypatch.setenv("FLOWSTALLION_LLM_PRICE_IN", "abc")
    monkeypatch.delenv("FLOWSTALLION_LLM_PRICE_OUT", raising=False)
    assert price_cost("no-such-model", 1_000_000, 0) == pytest.approx(0.0)
    assert price_cost("no-such-model", 1_000_000, 0) == pytest.approx(0.0)
    err = capsys.readouterr().err
    assert "FLOWSTALLION_LLM_PRICE_IN" in err
    assert err.count("is not a number") == 1


def test_ledger_expands_tilde_in_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    ledger = CostLedger("~/.flowstallion/cost.jsonl")
    assert ledger.path == tmp_path / ".flowstallion" / "cost.jsonl"
    ledger.append(CostRecord(ts="t", source="llm", run_id=None))
    assert ledger.path.is_file()


# --- aggregation --------------------------------------------------------------

def _rec(pr: str, team: str, source: str, prompt: int, completion: int, cost: float) -> CostRecord:
    return CostRecord(
        ts="2026-10-22T00:00:00Z",
        source=source,
        run_id=None,
        pr=pr,
        team=team,
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
        cost=cost,
    )


def test_aggregate_by_pr() -> None:
    records = [
        _rec("pr-1", "team-a", "llm", 1_000, 500, 0.01),
        _rec("pr-1", "team-b", "cloud", 0, 0, 2.5),
        _rec("pr-2", "team-a", "llm", 2_000, 100, 0.005),
        _rec("pr-2", "team-a", "cloud", 0, 0, 0.75),
    ]
    rows = aggregate(records, "pr")
    assert rows == [
        {
            "pr": "pr-1",
            "records": 2,
            "prompt_tokens": 1_000,
            "completion_tokens": 500,
            "total_tokens": 1_500,
            "cost_usd": pytest.approx(2.51),
        },
        {
            "pr": "pr-2",
            "records": 2,
            "prompt_tokens": 2_000,
            "completion_tokens": 100,
            "total_tokens": 2_100,
            "cost_usd": pytest.approx(0.755),
        },
    ]


def test_aggregate_by_team() -> None:
    records = [
        _rec("pr-1", "team-a", "llm", 1_000, 500, 0.01),
        _rec("pr-2", "team-b", "cloud", 0, 0, 2.5),
    ]
    rows = aggregate(records, "team")
    assert [r["team"] for r in rows] == ["team-b", "team-a"]  # cost desc
    assert rows[0]["records"] == 1
    assert rows[0]["cost_usd"] == pytest.approx(2.5)


def test_aggregate_invalid_by() -> None:
    with pytest.raises(ValueError):
        aggregate([], "cost")


# --- cloud sample -------------------------------------------------------------

def test_cloud_sample_deterministic_and_shape() -> None:
    a = cloud_cost_sample()
    b = cloud_cost_sample()
    assert a == b
    assert len(a) == 6
    for r in a:
        assert r.source == "cloud"
        assert r.namespace is not None
        assert r.pod is not None
    prs = {r.pr for r in a}
    teams = {r.team for r in a}
    assert len(prs) == 2
    assert len(teams) == 2


# --- record_llm_usage ---------------------------------------------------------

def test_record_llm_usage_writes_record(tmp_path: Path) -> None:
    usage = {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
    llm = make_llm(usage)
    chat_once(llm)
    p = tmp_path / "ledger.jsonl"
    rec = record_llm_usage(
        llm,
        run_id="42",
        pr="pr-101",
        team="team-infra",
        ledger=CostLedger(p),
    )
    assert rec is not None
    assert rec.source == "llm"
    assert rec.run_id == "42"
    assert rec.pr == "pr-101"
    assert rec.team == "team-infra"
    assert rec.model == "gpt-4o-mini"
    assert (rec.prompt_tokens, rec.completion_tokens, rec.total_tokens) == (100, 50, 150)
    assert rec.cost == pytest.approx(
        price_cost("gpt-4o-mini", 100, 50)
    )
    on_disk = CostLedger(p).records()
    assert len(on_disk) == 1
    assert on_disk[0].prompt_tokens == 100


def test_record_llm_usage_env_ledger_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    p = tmp_path / "env-ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(p))
    llm = make_llm({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})
    chat_once(llm)
    rec = record_llm_usage(llm)
    assert rec is not None
    assert CostLedger(p).records()[0].run_id is None


def test_record_llm_usage_no_usage_returns_none_no_file(tmp_path: Path) -> None:
    p = tmp_path / "ledger.jsonl"
    llm = make_llm(None)  # response has no usage block
    chat_once(llm)
    assert llm.last_usage is None
    assert record_llm_usage(llm, ledger=CostLedger(p)) is None
    assert not p.exists()


def test_record_llm_usage_unwritable_returns_none(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Parent path element is a regular file: mkdir(parents=True) must fail,
    # and record_llm_usage must swallow it (return None, print to stderr).
    blocker = tmp_path / "blocker"
    blocker.write_text("file, not a dir", encoding="utf-8")
    llm = make_llm({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})
    chat_once(llm)
    rec = record_llm_usage(llm, ledger=CostLedger(tmp_path / "blocker" / "ledger.jsonl"))
    assert rec is None
    err = capsys.readouterr().err
    assert "ledger append failed" in err


# --- maybe_record_llm_usage ---------------------------------------------------

def test_maybe_record_llm_usage_writes_when_env_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(p))
    llm = make_llm({"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5})
    chat_once(llm)
    maybe_record_llm_usage(llm, run_id="99", pr="55", team="team-x")
    rec = CostLedger(p).records()[0]
    assert (rec.run_id, rec.pr, rec.team) == ("99", "55", "team-x")


def test_maybe_record_llm_usage_noop_when_env_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("FLOWSTALLION_COST_LEDGER", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))  # default path would land here
    llm = make_llm({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})
    chat_once(llm)
    maybe_record_llm_usage(llm, run_id="1", pr="1", team="t")
    assert not (tmp_path / ".flowstallion").exists()


def test_maybe_record_llm_usage_no_usage_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(p))
    llm = make_llm(None)
    chat_once(llm)
    maybe_record_llm_usage(llm, run_id="1", pr="1", team="t")
    assert not p.exists()


def test_maybe_record_llm_usage_swallows_write_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("file, not a dir", encoding="utf-8")
    monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(tmp_path / "blocker" / "l.jsonl"))
    llm = make_llm({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})
    chat_once(llm)
    maybe_record_llm_usage(llm)  # must not raise
    capsys.readouterr()


# --- CLI ----------------------------------------------------------------------

def _run_cost_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(AGENT_DIR)
    return subprocess.run(
        [sys.executable, "-m", "flowstallion_agent.cost", *args],
        cwd=AGENT_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _sample_expected() -> dict[str, Mapping[str, object]]:
    """Hand-recomputed expectations for the --sample fixture."""
    def llm_cost(p: int, c: int) -> float:
        return p * 0.15 / 1_000_000 + c * 0.60 / 1_000_000

    pr_101 = {
        "records": 3 + 3,
        "tokens": (12_800 + 31_500 + 5_400),
        "cost": llm_cost(12_000, 800) + llm_cost(30_000, 1_500)
        + llm_cost(5_000, 400) + 0.42 + 0.61 + 1.25,
    }
    pr_207 = {
        "records": 2 + 3,
        "tokens": 20_900 + 8_600,
        "cost": llm_cost(20_000, 900) + llm_cost(8_000, 600) + 0.87 + 2.03 + 0.55,
    }
    return {"pr-101": pr_101, "pr-207": pr_207}


def test_cli_sample_and_by_pr_json(tmp_path: Path) -> None:
    out = tmp_path / "sample.jsonl"
    res = _run_cost_cli("--sample", "--out", str(out))
    assert res.returncode == 0, res.stderr
    assert f"wrote 11 records to {out}" in res.stdout
    assert out.is_file()

    res = _run_cost_cli("--ledger", str(out), "--by-pr", "--json")
    assert res.returncode == 0, res.stderr
    rows = json.loads(res.stdout)
    exp = _sample_expected()
    assert len(rows) == 2
    by_key = {r["pr"]: r for r in rows}
    # Sorted by cost desc: pr-101 (~$2.9) > pr-207 (~$3.0)? recompute:
    # pr-101 cost ≈ 0.00312 + 0.0195 + 0.00114 + 2.28 = ~2.28266
    # pr-207 cost ≈ 0.00354 + 0.00156 + 3.45 = ~3.4551
    assert [r["pr"] for r in rows] == ["pr-207", "pr-101"]
    for pr in ("pr-101", "pr-207"):
        e = exp[pr]
        got = by_key[pr]
        assert got["records"] == e["records"]
        assert got["total_tokens"] == e["tokens"]
        assert got["cost_usd"] == pytest.approx(e["cost"], abs=1e-9)


def test_cli_by_pr_table(tmp_path: Path) -> None:
    out = tmp_path / "sample.jsonl"
    assert _run_cost_cli("--sample", "--out", str(out)).returncode == 0
    res = _run_cost_cli("--ledger", str(out), "--by-pr")
    assert res.returncode == 0, res.stderr
    lines = res.stdout.strip().splitlines()
    assert lines[0].startswith("key")
    assert any(line.startswith("TOTAL") for line in lines)
    # 2 PR groups + header + TOTAL
    assert len(lines) == 4


def test_cli_by_team_json(tmp_path: Path) -> None:
    out = tmp_path / "sample.jsonl"
    assert _run_cost_cli("--sample", "--out", str(out)).returncode == 0
    res = _run_cost_cli("--ledger", str(out), "--by-team", "--json")
    assert res.returncode == 0, res.stderr
    rows = json.loads(res.stdout)
    assert {r["team"] for r in rows} == {"team-infra", "team-data"}
    infra = next(r for r in rows if r["team"] == "team-infra")
    # llm: 3 records (pr-101/team-infra); cloud: 2 (pr-101) + 1 (pr-207)
    assert infra["records"] == 6
    assert infra["total_tokens"] == 12_800 + 31_500 + 5_400


def test_cli_source_filter(tmp_path: Path) -> None:
    out = tmp_path / "sample.jsonl"
    assert _run_cost_cli("--sample", "--out", str(out)).returncode == 0
    res = _run_cost_cli("--ledger", str(out), "--by-pr", "--json", "--source", "llm")
    assert res.returncode == 0, res.stderr
    rows = json.loads(res.stdout)
    by_key = {r["pr"]: r for r in rows}
    assert by_key["pr-101"]["records"] == 3
    assert by_key["pr-207"]["records"] == 2
    assert by_key["pr-101"]["total_tokens"] == 12_800 + 31_500 + 5_400


def test_cli_missing_ledger_exit_2() -> None:
    res = _run_cost_cli("--by-pr")
    assert res.returncode == 2
    assert "--ledger" in res.stderr


def test_cli_ledger_not_found_exit_1(tmp_path: Path) -> None:
    res = _run_cost_cli("--ledger", str(tmp_path / "nope.jsonl"), "--by-pr")
    assert res.returncode == 1


def test_cli_malformed_ledger_clean_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.jsonl"
    p.write_text('{"ts": 123, "source": "llm"}\n', encoding="utf-8")
    res = _run_cost_cli("--ledger", str(p), "--by-pr")
    assert res.returncode == 1
    assert "error:" in res.stderr
    assert "Traceback" not in res.stderr
    assert "line 1" in res.stderr
