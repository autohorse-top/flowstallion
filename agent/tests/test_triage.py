"""Tests for flowstallion_agent.triage — rules table, LLM upgrade, and fallback."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import flowstallion_agent.llm as llm_mod
from flowstallion_agent.llm import LLM, LLMConfig
from flowstallion_agent.triage import analyze

CMDS = "make build\necho done"


def _llm(reply_content: str) -> LLM:
    """Build an LLM whose transport replies once with the given content."""
    body = json.dumps(
        {"choices": [{"message": {"content": reply_content}}]}
    ).encode("utf-8")

    class OnceTransport:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str], bytes, float]] = []

        def post(
            self,
            url: str,
            headers: dict[str, str],
            data: bytes,
            timeout_s: float,
        ) -> tuple[int, dict[str, str], bytes]:
            self.calls.append((url, headers, data, timeout_s))
            return 200, {}, body

    return LLM(
        LLMConfig(base_url="https://llm.example/v1", api_key="sk-test", model="m"),
        transport=OnceTransport(),
    )


def _failing_llm(failures: int) -> LLM:
    """Transport that fails ``failures`` times with HTTP 500, then succeeds.

    ``max_retries=2`` means 3 total attempts, so failures=3 exhausts them.
    """
    good = json.dumps(
        {"choices": [{"message": {"content": '{"root_cause": "ok after retry"}'}}]}
    ).encode("utf-8")

    class ScriptedTransport:
        def __init__(self) -> None:
            self.remaining = failures

        def post(
            self,
            url: str,
            headers: dict[str, str],
            data: bytes,
            timeout_s: float,
        ) -> tuple[int, dict[str, str], bytes]:
            if self.remaining > 0:
                self.remaining -= 1
                return 500, {}, b"boom"
            return 200, {}, good

    return LLM(
        LLMConfig(
            base_url="https://llm.example/v1",
            api_key="sk-test",
            model="m",
            max_retries=2,
        ),
        transport=ScriptedTransport(),
    )


class TestRules:
    def test_oom(self) -> None:
        rca = analyze(["[1] 1234 Killed     python heavy.py"], CMDS)
        assert rca.kind == "rule"
        assert "memory" in rca.root_cause.lower()

    def test_command_not_found(self) -> None:
        rca = analyze(["sh: make: command not found"], CMDS)
        assert "not found" in rca.root_cause.lower()

    def test_missing_file(self) -> None:
        rca = analyze(["cat: Dockerfile: No such file or directory"], CMDS)
        assert "missing" in rca.root_cause.lower()

    def test_permission_denied(self) -> None:
        rca = analyze(["ls: cannot open '/root/x': Permission denied"], CMDS)
        assert "permission" in rca.root_cause.lower()

    def test_python_import_error(self) -> None:
        rca = analyze(["ModuleNotFoundError: No module named 'requests'"], CMDS)
        assert "python" in rca.root_cause.lower()

    def test_go_panic(self) -> None:
        rca = analyze(["panic: runtime error: index out of range [3] with length 2"], CMDS)
        assert "panic" in rca.root_cause.lower()

    def test_segfault(self) -> None:
        rca = analyze(["Segmentation fault (core dumped)"], CMDS)
        assert "segv" in rca.root_cause.lower() or "segmentation" in rca.root_cause.lower()

    def test_assertion_failure(self) -> None:
        rca = analyze(["E   AssertionError: assert 1 == 2"], CMDS)
        assert "assertion" in rca.root_cause.lower() or "test" in rca.root_cause.lower()

    def test_nonzero_exit(self) -> None:
        rca = analyze(["the step exited with code 1"], CMDS)
        assert "non-zero" in rca.root_cause.lower()

    def test_fallback_when_no_signature(self) -> None:
        rca = analyze(["just some opaque output"], CMDS)
        assert rca.root_cause == "Step exited with a non-zero status"
        assert "opaque output" in rca.detail
        assert rca.kind == "rule"

    def test_rule_includes_command_and_excerpt(self) -> None:
        rca = analyze(["Killed"], "go test ./...")
        assert rca.command == "go test ./..."
        assert "Killed" in rca.log_excerpt

    def test_log_excerpt_capped(self) -> None:
        lines = [f"line-{i}" for i in range(10_000)]
        rca = analyze(lines, CMDS)
        assert len(rca.log_excerpt) <= 4200
        assert "line-9999" in rca.log_excerpt


class TestLLMUpgrade:
    def test_llm_result_used_when_configured(self, monkeypatch: object) -> None:
        llm_mod._sleep = lambda seconds: None
        llm = _llm('{"root_cause": "bad dep pin", "detail": "d", "suggested_fix": "pin"}')
        rca = analyze(["make: *** Error"], CMDS, llm=llm)
        assert rca.kind == "llm"
        assert rca.root_cause == "bad dep pin"
        assert rca.suggested_fix == "pin"
        assert rca.command == CMDS

    def test_llm_fenced_json(self, monkeypatch: object) -> None:
        llm_mod._sleep = lambda seconds: None
        llm = _llm('```json\n{"root_cause": "x", "detail": "y", "suggested_fix": "z"}\n```')
        rca = analyze(["fail"], CMDS, llm=llm)
        assert rca.kind == "llm"
        assert rca.root_cause == "x"

    def test_llm_total_failure_falls_back_to_rules(self, monkeypatch: object) -> None:
        llm_mod._sleep = lambda seconds: None
        llm = _failing_llm(failures=3)  # 3 attempts, all 500
        rca = analyze(["Killed"], CMDS, llm=llm)
        assert rca.kind == "rule"
        assert "memory" in rca.root_cause.lower()

    def test_llm_transient_failure_then_success(self, monkeypatch: object) -> None:
        llm_mod._sleep = lambda seconds: None
        llm = _failing_llm(failures=2)  # 500, 500, then 200
        rca = analyze(["Killed"], CMDS, llm=llm)
        assert rca.kind == "llm"
        assert rca.root_cause == "ok after retry"

    def test_llm_missing_root_cause_falls_back(self, monkeypatch: object) -> None:
        llm_mod._sleep = lambda seconds: None
        llm = _llm('{"detail": "no root_cause key"}')
        rca = analyze(["Killed"], CMDS, llm=llm)
        assert rca.kind == "rule"

    def test_llm_alias_keys_still_llm(self, monkeypatch: object) -> None:
        llm_mod._sleep = lambda seconds: None
        llm = _llm(
            json.dumps(
                {
                    "likely_cause": "bad dep pin",
                    "evidence": "go.mod drifts",
                    "next_steps": ["bump pin", "re-run"],
                }
            )
        )
        rca = analyze(["make: *** Error"], CMDS, llm=llm)
        assert rca.kind == "llm"
        assert rca.root_cause == "bad dep pin"
        assert rca.detail == "go.mod drifts"
        assert rca.suggested_fix == "bump pin; re-run"

    def test_llm_unrecognised_keys_fall_back_to_rules(self, monkeypatch: object) -> None:
        llm_mod._sleep = lambda seconds: None
        llm = _llm(json.dumps({"mystery_field": "x"}))
        rca = analyze(["Killed"], CMDS, llm=llm)
        assert rca.kind == "rule"
        assert "memory" in rca.root_cause.lower()

    def test_no_llm_uses_rules(self) -> None:
        rca = analyze(["Killed"], CMDS, llm=None)
        assert rca.kind == "rule"


def _llm_with_usage() -> LLM:
    """LLM that replies with valid triage JSON plus a usage block."""
    import flowstallion_agent.cost as cost_mod  # noqa: F401  (env read at call time)
    content = json.dumps({"root_cause": "llm cause", "detail": "d", "suggested_fix": "f"})
    body = json.dumps({
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }).encode("utf-8")

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
        LLMConfig(base_url="https://llm.example/v1", api_key="sk-test", model="gpt-4o-mini"),
        transport=OnceTransport(),
    )


class TestCostWiring:
    def test_analyze_records_usage_when_env_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from flowstallion_agent.cost import CostLedger
        p = tmp_path / "ledger.jsonl"
        monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(p))
        rca = analyze(
            ["Killed     heavy job"],
            CMDS,
            llm=_llm_with_usage(),
            run_id="42",
            pr="pr-1",
            team="team-a",
        )
        assert rca.kind == "llm"
        recs = CostLedger(p).records()
        assert len(recs) == 1
        assert recs[0].run_id == "42"
        assert recs[0].pr == "pr-1"
        assert recs[0].team == "team-a"
        assert recs[0].model == "gpt-4o-mini"
        assert (recs[0].prompt_tokens, recs[0].completion_tokens, recs[0].total_tokens) == (10, 5, 15)

    def test_analyze_no_record_when_env_unset(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("FLOWSTALLION_COST_LEDGER", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))  # default ledger path lands here
        rca = analyze(["Killed     heavy job"], CMDS, llm=_llm_with_usage())
        assert rca.kind == "llm"
        assert not (tmp_path / ".flowstallion").exists()

    def test_analyze_rule_fallback_records_nothing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from flowstallion_agent.cost import CostLedger
        p = tmp_path / "ledger.jsonl"
        monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(p))
        payload = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode("utf-8")

        class Always500:
            def post(
                self,
                url: str,
                headers: dict[str, str],
                data: bytes,
                timeout_s: float,
            ) -> tuple[int, dict[str, str], bytes]:
                return 500, {}, payload

        llm = LLM(
            LLMConfig(
                base_url="https://llm.example/v1",
                api_key="sk-test",
                model="gpt-4o-mini",
                max_retries=0,
            ),
            transport=Always500(),
        )
        rca = analyze(["Killed     heavy job"], CMDS, llm=llm)
        assert rca.kind == "rule"
        assert not p.exists()

    def test_analyze_records_usage_when_llm_reply_garbage(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """HTTP success + usage, but non-JSON content: rule fallback, still billed."""
        from flowstallion_agent.cost import CostLedger
        p = tmp_path / "ledger.jsonl"
        monkeypatch.setenv("FLOWSTALLION_COST_LEDGER", str(p))
        content = "Sure! Here is my analysis of the failure (not JSON)."
        body = json.dumps({
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
        }).encode("utf-8")

        class GarbageTransport:
            def post(
                self,
                url: str,
                headers: dict[str, str],
                data: bytes,
                timeout_s: float,
            ) -> tuple[int, dict[str, str], bytes]:
                return 200, {}, body

        llm = LLM(
            LLMConfig(
                base_url="https://llm.example/v1",
                api_key="sk-test",
                model="gpt-4o-mini",
                max_retries=0,
            ),
            transport=GarbageTransport(),
        )
        rca = analyze(["Killed     heavy job"], CMDS, llm=llm, run_id="7")
        assert rca.kind == "rule"  # garbage reply -> rule fallback
        recs = CostLedger(p).records()
        assert len(recs) == 1  # tokens were billed even though reply rejected
        assert recs[0].run_id == "7"
        # The garbage reply triggers one repair pass, so two HTTP-successful
        # calls were made and both are billed (usage is accumulated).
        assert (recs[0].prompt_tokens, recs[0].completion_tokens, recs[0].total_tokens) == (14, 6, 20)
