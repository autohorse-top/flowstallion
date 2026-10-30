"""Tests for flowstallion_agent.llm — all via a scripted fake transport (no network)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

import flowstallion_agent.llm as llm_mod
from flowstallion_agent.llm import (
    LLM,
    LLMConfig,
    LLMError,
    LLMNotConfigured,
    LLMAuthError,
    LLMHTTPError,
    LLMTimeoutError,
    TokenUsage,
    is_configured,
)

KEY = "sk-test-abc-123"
BASE = "https://llm.example/v1"
MSGS: list[dict[str, str]] = [{"role": "user", "content": "hi"}]


@dataclass
class RecordedCall:
    url: str
    headers: dict[str, str]
    body: bytes
    timeout_s: float


@dataclass
class FakeTransport:
    """Scripted transport: responses are consumed in order (FIFO)."""

    responses: list[tuple[int, dict[str, str], str] | Exception]
    calls: list[RecordedCall] = field(default_factory=list)

    def post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_s: float,
    ) -> tuple[int, dict[str, str], bytes]:
        self.calls.append(RecordedCall(url, headers, body, timeout_s))
        if not self.responses:
            raise AssertionError("FakeTransport: out of scripted responses")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        status, hdrs, text = item
        return status, hdrs, text.encode("utf-8")


def ok_body(content: str) -> str:
    return json.dumps({"choices": [{"message": {"content": content}}]})


def make_client(
    responses: list[tuple[int, dict[str, str], str] | Exception], max_retries: int = 2
) -> tuple[LLM, FakeTransport]:
    fake = FakeTransport(list(responses))
    cfg = LLMConfig(
        base_url=BASE, api_key=KEY, model="m1", max_retries=max_retries
    )
    return LLM(cfg, transport=fake), fake


def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []
    monkeypatch.setattr(llm_mod, "_sleep", lambda s: slept.append(s))
    return slept


# --- happy path / request shape -------------------------------------------

def test_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    slept = no_sleep(monkeypatch)
    client, fake = make_client([(200, {}, ok_body("hello world"))])
    assert client.chat(MSGS) == "hello world"
    assert len(fake.calls) == 1
    assert slept == []


def test_request_shape() -> None:
    client, fake = make_client([(200, {}, ok_body("ok"))])
    client.chat(MSGS, temperature=0.5, max_tokens=128)
    call = fake.calls[0]
    assert call.url == f"{BASE}/chat/completions"
    assert call.headers["Authorization"] == f"Bearer {KEY}"
    assert call.headers["Content-Type"] == "application/json"
    payload = json.loads(call.body)
    assert payload["model"] == "m1"
    assert payload["messages"] == MSGS
    assert payload["temperature"] == 0.5
    assert payload["max_tokens"] == 128


def test_chat_json_sends_json_object_mode_by_default() -> None:
    client, fake = make_client([(200, {}, ok_body('{"a": 1}'))])
    client.chat_json(MSGS)
    payload = json.loads(fake.calls[0].body)
    assert payload["response_format"] == {"type": "json_object"}


def test_chat_plain_omits_json_mode() -> None:
    client, fake = make_client([(200, {}, ok_body("ok"))])
    client.chat(MSGS)
    payload = json.loads(fake.calls[0].body)
    assert "response_format" not in payload


def test_chat_json_json_mode_off() -> None:
    client, fake = make_client([(200, {}, ok_body('{"a": 1}'))])
    client.chat_json(MSGS, json_mode=False)
    payload = json.loads(fake.calls[0].body)
    assert "response_format" not in payload


# --- auth errors (no retry) -------------------------------------------------

def test_401_no_retry() -> None:
    client, fake = make_client([(401, {}, '{"error":"bad key"}')])
    with pytest.raises(LLMAuthError):
        client.chat(MSGS)
    assert len(fake.calls) == 1


def test_403_no_retry_no_key_leak() -> None:
    client, fake = make_client([(403, {}, f'{{"error":"key {KEY} invalid"}}')])
    with pytest.raises(LLMAuthError) as ei:
        client.chat(MSGS)
    assert len(fake.calls) == 1
    assert KEY not in str(ei.value)


# --- retry semantics --------------------------------------------------------

def test_429_retry_then_success(monkeypatch: pytest.MonkeyPatch) -> None:
    slept = no_sleep(monkeypatch)
    client, fake = make_client(
        [
            (429, {"Retry-After": "0.3"}, '{"error":"rate limited"}'),
            (200, {}, ok_body("ok")),
        ]
    )
    assert client.chat(MSGS) == "ok"
    assert len(fake.calls) == 2
    assert slept == [0.3]  # Retry-After honoured


def test_500_retries_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    no_sleep(monkeypatch)
    client, fake = make_client([(500, {}, '{"error":"boom"}')] * 3)
    with pytest.raises(LLMHTTPError) as ei:
        client.chat(MSGS)
    assert ei.value.status == 500
    assert len(fake.calls) == 3  # initial + max_retries(2)


def test_timeout_retries_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    no_sleep(monkeypatch)
    client, fake = make_client([TimeoutError("t")] * 2, max_retries=1)
    with pytest.raises(LLMTimeoutError):
        client.chat(MSGS)
    assert len(fake.calls) == 2


def test_429_honours_retry_after_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    slept = no_sleep(monkeypatch)
    client, fake = make_client([(429, {"Retry-After": "999"}, "")] * 3)
    with pytest.raises(LLMHTTPError):
        client.chat(MSGS)
    assert slept and slept[-1] <= 30.0  # capped


# --- configuration ----------------------------------------------------------

def test_from_env_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FLOWSTALLION_LLM_API_KEY", raising=False)
    assert is_configured() is False
    with pytest.raises(LLMNotConfigured):
        LLM.from_env()


def test_from_env_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLOWSTALLION_LLM_API_KEY", "sk-env-xyz")
    monkeypatch.setenv("FLOWSTALLION_LLM_BASE_URL", "https://my-llm.local/v1/")
    monkeypatch.setenv("FLOWSTALLION_LLM_MODEL", "deepseek-chat")
    monkeypatch.setenv("FLOWSTALLION_LLM_TIMEOUT", "12.5")
    assert is_configured() is True
    client = LLM.from_env()
    assert client.config.api_key == "sk-env-xyz"
    assert client.config.base_url == "https://my-llm.local/v1"
    assert client.config.model == "deepseek-chat"
    assert client.config.timeout_s == 12.5


# --- key redaction ----------------------------------------------------------

def test_key_not_in_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    no_sleep(monkeypatch)
    body = json.dumps({"error": {"message": f"invalid api key {KEY}"}})
    client, fake = make_client([(404, {}, body)])
    with pytest.raises(LLMHTTPError) as ei:
        client.chat(MSGS)
    assert KEY not in str(ei.value)
    assert "***" in str(ei.value)


# --- payload parsing --------------------------------------------------------

def test_malformed_200_raises() -> None:
    client, _ = make_client([(200, {}, "this is not json")])
    with pytest.raises(LLMError):
        client.chat(MSGS)


def test_chat_json_fenced() -> None:
    client, _ = make_client(
        [(200, {}, ok_body('```json\n{"root_cause": "oom"}\n```'))]
    )
    assert client.chat_json(MSGS) == {"root_cause": "oom"}


def test_chat_json_embedded_in_prose() -> None:
    client, _ = make_client(
        [(200, {}, ok_body('Here you go: {"a": 1} hope that helps'))]
    )
    assert client.chat_json(MSGS) == {"a": 1}


def test_chat_json_no_json_raises() -> None:
    client, fake = make_client(
        [
            (200, {}, ok_body("no json here at all")),
            (200, {}, ok_body("still no json")),
        ]
    )
    with pytest.raises(LLMError):
        client.chat_json(MSGS)
    assert len(fake.calls) == 2  # one repair pass, then give up


def test_chat_json_repair_pass_on_prose_reply() -> None:
    """A prose (non-JSON) reply triggers exactly one repair pass that
    re-sends the bad reply and demands bare JSON."""
    client, fake = make_client(
        [
            (200, {}, ok_body("I think the answer is good.")),
            (200, {}, ok_body('{"a": 1}')),
        ]
    )
    assert client.chat_json(MSGS) == {"a": 1}
    assert len(fake.calls) == 2
    repair_payload = json.loads(fake.calls[1].body)
    roles = [m["role"] for m in repair_payload["messages"]]
    assert roles == ["user", "assistant", "user"]
    assert repair_payload["messages"][1]["content"] == "I think the answer is good."
    assert "valid JSON" in repair_payload["messages"][2]["content"]


def test_chat_json_no_repair_when_first_reply_valid() -> None:
    client, fake = make_client([(200, {}, ok_body('{"a": 1}'))])
    assert client.chat_json(MSGS) == {"a": 1}
    assert len(fake.calls) == 1


def test_chat_json_repair_pass_usage_summed() -> None:
    """Token usage spans both attempts: the failed first call is billed too."""
    body1 = usage_body(
        "prose only", {"prompt_tokens": 10, "completion_tokens": 5,
                       "total_tokens": 15}
    )
    body2 = usage_body(
        '{"a": 1}', {"prompt_tokens": 10, "completion_tokens": 3,
                     "total_tokens": 13}
    )
    client, fake = make_client([(200, {}, body1), (200, {}, body2)])
    assert client.chat_json(MSGS) == {"a": 1}
    assert len(fake.calls) == 2
    assert client.last_usage == TokenUsage(
        prompt_tokens=20, completion_tokens=8, total_tokens=28
    )


def test_chat_json_repair_failure_keeps_first_usage() -> None:
    """If the repair call itself fails over HTTP, the first (billed) call's
    usage is preserved so cost accounting is not lost."""
    body1 = usage_body(
        "prose only", {"prompt_tokens": 10, "completion_tokens": 5,
                       "total_tokens": 15}
    )
    client, fake = make_client(
        [(200, {}, body1), (500, {}, '{"error":"boom"}')], max_retries=0
    )
    with pytest.raises(LLMHTTPError):
        client.chat_json(MSGS)
    assert client.last_usage == TokenUsage(
        prompt_tokens=10, completion_tokens=5, total_tokens=15
    )
    assert len(fake.calls) == 2


# --- token usage capture ----------------------------------------------------

def usage_body(content: str, usage: dict[str, object] | None) -> str:
    payload: dict[str, object] = {"choices": [{"message": {"content": content}}]}
    if usage is not None:
        payload["usage"] = usage
    return json.dumps(payload)


def test_usage_captured() -> None:
    body = usage_body("hello", {"prompt_tokens": 11, "completion_tokens": 22,
                                "total_tokens": 33})
    client, _ = make_client([(200, {}, body)])
    assert client.last_usage is None  # before any chat
    assert client.chat(MSGS) == "hello"
    assert client.last_usage == TokenUsage(
        prompt_tokens=11, completion_tokens=22, total_tokens=33
    )


def test_usage_total_derived_when_missing() -> None:
    body = usage_body("hello", {"prompt_tokens": 7, "completion_tokens": 5})
    client, _ = make_client([(200, {}, body)])
    client.chat(MSGS)
    assert client.last_usage == TokenUsage(
        prompt_tokens=7, completion_tokens=5, total_tokens=12
    )


def test_usage_missing_block_is_none() -> None:
    client, _ = make_client([(200, {}, ok_body("hi"))])
    client.chat(MSGS)
    assert client.last_usage is None


def test_usage_reset_after_each_chat() -> None:
    body1 = usage_body("one", {"prompt_tokens": 1, "completion_tokens": 1,
                               "total_tokens": 2})
    client, _ = make_client([(200, {}, body1), (200, {}, ok_body("two"))])
    client.chat(MSGS)
    assert client.last_usage is not None
    client.chat(MSGS)
    assert client.last_usage is None


def test_usage_cleared_when_call_fails() -> None:
    """A failed call must not leave a previous call's usage exposed as the
    current call's usage — otherwise cost accounting would bill a failed
    call against stale tokens."""
    ok = usage_body("one", {"prompt_tokens": 1, "completion_tokens": 1,
                            "total_tokens": 2})
    client, _ = make_client([(200, {}, ok), (500, {}, '{"error":"boom"}')],
                            max_retries=0)
    client.chat(MSGS)
    assert client.last_usage is not None
    with pytest.raises(LLMHTTPError):
        client.chat(MSGS)
    assert client.last_usage is None


def test_usage_overwritten_by_latest() -> None:
    body1 = usage_body("one", {"prompt_tokens": 1, "completion_tokens": 1,
                               "total_tokens": 2})
    body2 = usage_body("two", {"prompt_tokens": 9, "completion_tokens": 8,
                               "total_tokens": 17})
    client, _ = make_client([(200, {}, body1), (200, {}, body2)])
    client.chat(MSGS)
    client.chat(MSGS)
    assert client.last_usage == TokenUsage(
        prompt_tokens=9, completion_tokens=8, total_tokens=17
    )


def test_usage_negative_values_clamped() -> None:
    body = usage_body("hello", {"prompt_tokens": -5, "completion_tokens": 3,
                                "total_tokens": -1})
    client, _ = make_client([(200, {}, body)])
    client.chat(MSGS)
    assert client.last_usage == TokenUsage(
        prompt_tokens=0, completion_tokens=3, total_tokens=3
    )
