"""LLM provider abstraction — OpenAI-compatible chat completions.

The API key is read **only** from the environment (``FLOWSTALLION_LLM_API_KEY``)
and is never persisted nor echoed in error messages (it is redacted to
``***``).  When no key is configured the layer degrades gracefully:
:func:`is_configured` returns ``False`` and :meth:`LLM.from_env` raises
:class:`LLMNotConfigured`, so CI/CD core features stay fully functional
without a model (risk section of TASK.md: "all AI features are bypass services").

HTTP is stdlib-only (``urllib``); the transport is injectable for tests.
"""

from __future__ import annotations

import json
import os
import random
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

__all__ = [
    "ENV_API_KEY",
    "ENV_BASE_URL",
    "ENV_MODEL",
    "ENV_TIMEOUT",
    "LLM",
    "LLMConfig",
    "LLMError",
    "LLMNotConfigured",
    "LLMAuthError",
    "LLMHTTPError",
    "LLMTimeoutError",
    "TokenUsage",
    "Transport",
    "is_configured",
]

ENV_API_KEY = "FLOWSTALLION_LLM_API_KEY"
ENV_BASE_URL = "FLOWSTALLION_LLM_BASE_URL"
ENV_MODEL = "FLOWSTALLION_LLM_MODEL"
ENV_TIMEOUT = "FLOWSTALLION_LLM_TIMEOUT"

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT_S = 60.0
DEFAULT_MAX_RETRIES = 3
_BACKOFF_BASE_S = 0.5
_BACKOFF_CAP_S = 30.0


class LLMError(Exception):
    """Base error for LLM provider failures."""


class LLMNotConfigured(LLMError):
    """No API key is present in the environment (layer disabled)."""


class LLMAuthError(LLMError):
    """The provider rejected the credentials (HTTP 401/403). Not retried."""


class LLMTimeoutError(LLMError):
    """The request timed out on every attempt."""


class LLMHTTPError(LLMError):
    """Non-success HTTP status: 4xx (except 429), or 429/5xx after retries."""

    def __init__(self, status: int, url: str, body: str) -> None:
        snippet = body[:512]
        super().__init__(
            f"LLM request failed: HTTP {status} from {url}: {snippet}"
        )
        self.status: int = status
        self.body: str = snippet
        self.url: str = url


@dataclass(frozen=True)
class LLMConfig:
    """Immutable LLM provider configuration.

    Args:
        base_url: OpenAI-compatible API base (without ``/chat/completions``).
        api_key: Bearer token; must come from the environment and is never
            logged.
        model: Model id passed to the provider.
        timeout_s: Per-request timeout in seconds.
        max_retries: Retries on transient failures (429/5xx/timeout/network),
            in addition to the initial attempt.
    """

    base_url: str
    api_key: str
    model: str
    timeout_s: float = DEFAULT_TIMEOUT_S
    max_retries: int = DEFAULT_MAX_RETRIES


@dataclass(frozen=True)
class TokenUsage:
    """Token accounting for one LLM response (the provider's ``usage`` block).

    Missing ``prompt_tokens``/``completion_tokens`` are treated as 0; a
    missing ``total_tokens`` is derived as prompt + completion.
    """

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class Transport(Protocol):
    """Minimal HTTP POST abstraction; inject a fake in tests."""

    def post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_s: float,
    ) -> tuple[int, dict[str, str], bytes]:
        """Send a POST. Returns ``(status, headers, body_bytes)``.

        Raises:
            TimeoutError: request timed out (transient; retried by :class:`LLM`).
            OSError: transport-level failure (transient; retried by :class:`LLM`).
        """
        ...


class _UrllibTransport:
    """Default stdlib transport (no third-party dependency)."""

    def post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_s: float,
    ) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(
            url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                hdrs = {k: v for k, v in resp.headers.items() if v is not None}
                return resp.status, hdrs, resp.read()
        except urllib.error.HTTPError as exc:
            err_headers = exc.headers
            hdrs = {}
            if err_headers is not None:
                hdrs = {k: v for k, v in err_headers.items() if v is not None}
            return exc.code, hdrs, exc.read()
        except TimeoutError:
            raise
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, TimeoutError) or "timeout" in str(reason).lower():
                raise TimeoutError(f"LLM request to {url} timed out") from exc
            raise OSError(f"LLM network error: {reason!r}") from exc


def _sleep(seconds: float) -> None:
    """Module-level seam so tests can record backoff without sleeping."""
    time.sleep(seconds)


def _backoff_delay(attempt: int, retry_after: float | None) -> float:
    """Exponential backoff with jitter; ``Retry-After`` wins when present."""
    if retry_after is not None:
        return min(_BACKOFF_CAP_S, max(0.0, retry_after))
    base = _BACKOFF_BASE_S * (2.0**attempt)
    return min(_BACKOFF_CAP_S, base + random.uniform(0.0, 0.1 * base))


def _retry_after_s(headers: dict[str, str]) -> float | None:
    for key, value in headers.items():
        if key.lower() == "retry-after":
            try:
                return float(value)
            except ValueError:
                return None
    return None


def _redact(text: str, key: str) -> str:
    return text.replace(key, "***") if key else text


def _extract_payload(
    status: int, body: bytes, url: str
) -> tuple[str, TokenUsage | None]:
    """Decode a 2xx response into ``(content, usage)``.

    ``usage`` is ``None`` when the provider omitted the ``usage`` block
    (or it was not an object) — callers treat that as "unknown", not zero.
    All error semantics from the pre-refactor ``_extract_content`` are
    preserved verbatim.
    """
    try:
        data = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LLMError(
            f"malformed LLM response (HTTP {status}) from {url}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise LLMError(f"malformed LLM payload from {url}: body is not a JSON object")
    try:
        content = data["choices"][0]["message"]["content"]
    except (TypeError, KeyError, IndexError) as exc:
        raise LLMError(
            f"malformed LLM payload from {url}: missing choices[0].message.content"
        ) from exc
    if not isinstance(content, str):
        raise LLMError(f"malformed LLM payload from {url}: content is not a string")
    return content, _parse_usage(data.get("usage"), url)


def _parse_usage(usage: object, url: str) -> TokenUsage | None:
    """Extract :class:`TokenUsage` from the response ``usage`` block.

    Returns ``None`` when the block is absent or not an object: absence means
    the provider did not report usage, which callers must treat as unknown
    rather than zero. Missing individual counts default to 0 and a missing
    ``total_tokens`` is derived as prompt + completion (OpenAI convention).
    """
    if not isinstance(usage, dict):
        return None
    prompt = _usage_int(usage.get("prompt_tokens"))
    completion = _usage_int(usage.get("completion_tokens"))
    total = _usage_int(usage.get("total_tokens"))
    if total == 0 and (prompt != 0 or completion != 0):
        total = prompt + completion
    return TokenUsage(
        prompt_tokens=prompt, completion_tokens=completion, total_tokens=total
    )


def _usage_int(value: object) -> int:
    """Best-effort int coercion for a usage count; non-numeric/negative → 0.

    Negative counts come from a broken provider payload; clamping keeps the
    cost ledger from ever recording negative tokens (or negative cost).
    """
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        return max(0, int(value))
    return 0


_JSON_REPAIR_PROMPT = (
    "Your previous reply was not valid JSON. Reply with exactly one JSON "
    "object and nothing else — no prose, no code fences, and no keys other "
    "than the ones requested."
)


def _extract_json(text: str) -> object:
    """Parse JSON from a model reply: fenced, bare, or embedded-in-prose."""
    candidate = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", candidate, re.DOTALL)
    if fence:
        candidate = fence.group(1).strip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for idx, char in enumerate(candidate):
        if char in "{[":
            try:
                obj, _ = decoder.raw_decode(candidate[idx:])
                return obj
            except json.JSONDecodeError:
                continue
    raise LLMError(f"could not parse JSON from LLM response: {candidate[:200]!r}")


class LLM:
    """OpenAI-compatible chat client with retry + key-redaction semantics."""

    def __init__(
        self,
        config: LLMConfig,
        transport: Transport | None = None,
    ) -> None:
        if not config.base_url:
            raise ValueError("base_url must be non-empty")
        if not config.api_key:
            raise LLMNotConfigured("api_key is empty")
        if config.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        self._config = config
        self._transport: Transport = (
            transport if transport is not None else _UrllibTransport()
        )
        # Usage from the most recent chat() call. Reset to None at the start of
        # every call so a failed call can never surface a stale usage from a
        # previous successful one (cost accounting must reflect the call that
        # was actually billed, if any). None also means "provider did not
        # report a usage block" (honest "unknown").
        self.last_usage: TokenUsage | None = None

    @property
    def config(self) -> LLMConfig:
        """The immutable configuration this client was built with."""
        return self._config

    @classmethod
    def from_env(cls) -> LLM:
        """Build a client from the ``FLOWSTALLION_LLM_*`` environment variables.

        Raises:
            LLMNotConfigured: ``FLOWSTALLION_LLM_API_KEY`` is unset or empty.
        """
        key = os.environ.get(ENV_API_KEY, "").strip()
        if not key:
            raise LLMNotConfigured(
                f"{ENV_API_KEY} is not set; LLM features are disabled "
                "(the key must come from the environment)"
            )
        # An explicitly-set-but-empty base URL must fall back to the default
        # (compose passes ${FLOWSTALLION_LLM_BASE_URL:-}, which expands to "").
        base_url = (os.environ.get(ENV_BASE_URL) or "").strip() or DEFAULT_BASE_URL
        base_url = base_url.rstrip("/")
        model = os.environ.get(ENV_MODEL, "").strip() or DEFAULT_MODEL
        raw_timeout = os.environ.get(ENV_TIMEOUT, "").strip()
        timeout_s = DEFAULT_TIMEOUT_S
        if raw_timeout:
            try:
                timeout_s = float(raw_timeout)
            except ValueError:
                timeout_s = DEFAULT_TIMEOUT_S
        return cls(
            LLMConfig(
                base_url=base_url,
                api_key=key,
                model=model,
                timeout_s=timeout_s,
            )
        )

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> str:
        """Run one chat completion; return the assistant content string.

        Retries 429/5xx, timeouts and transient network errors with
        exponential backoff + jitter (honouring ``Retry-After``).  401/403
        and other 4xx are not retried.

        ``json_mode`` sends OpenAI ``response_format: {"type":
        "json_object"}``, which makes compliant providers return
        syntactically valid JSON.  Providers without the field either ignore
        it or reject the request; rejection surfaces as a normal HTTP error
        and callers degrade per their fallback rules.

        Raises:
            LLMTimeoutError: every attempt timed out.
            LLMAuthError: credentials rejected (401/403).
            LLMHTTPError: other 4xx, or 429/5xx after retries exhausted.
            LLMError: network failure after retries, or malformed payload.
        """
        cfg = self._config
        url = f"{cfg.base_url}/chat/completions"
        payload: dict[str, object] = {
            "model": cfg.model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {cfg.api_key}",
            "Content-Type": "application/json",
        }

        # Clear any stale usage from a previous call before attempting this
        # one: on failure last_usage stays None, so cost accounting can only
        # ever reflect a call that actually succeeded.
        self.last_usage = None
        attempts = cfg.max_retries + 1
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                status, resp_headers, resp_body = self._transport.post(
                    url, headers, body, cfg.timeout_s
                )
            except TimeoutError as exc:
                last = exc
                if attempt + 1 < attempts:
                    _sleep(_backoff_delay(attempt, None))
                    continue
                raise LLMTimeoutError(
                    f"LLM request to {url} timed out after {attempts} attempt(s)"
                ) from exc
            except OSError as exc:
                last = exc
                if attempt + 1 < attempts:
                    _sleep(_backoff_delay(attempt, None))
                    continue
                raise LLMError(
                    f"LLM network error after {attempts} attempt(s): {exc}"
                ) from exc

            if status in (401, 403):
                raise LLMAuthError(
                    f"LLM auth rejected (HTTP {status}) by {url}; "
                    f"check {ENV_API_KEY}"
                )
            text = _redact(
                resp_body.decode("utf-8", "replace"), cfg.api_key
            )
            if status == 429 or 500 <= status < 600:
                last = LLMHTTPError(status, url, text)
                if attempt + 1 < attempts:
                    _sleep(
                        _backoff_delay(attempt, _retry_after_s(resp_headers))
                    )
                    continue
                raise last
            if status >= 400:
                raise LLMHTTPError(status, url, text)

            content, usage = _extract_payload(status, resp_body, url)
            self.last_usage = usage
            return content

        raise LLMError(
            f"LLM request to {url} failed after {attempts} attempt(s)"
        ) from last

    def chat_json(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        json_mode: bool = True,
    ) -> object:
        """Like :meth:`chat` but parses the reply as JSON.

        JSON object mode is on by default: it materially improves reply
        validity with instruction-weak models.  Set ``json_mode=False`` for
        providers that reject the ``response_format`` field.

        Some providers ignore ``response_format`` and still answer in prose
        (observed 2026-10-27 with the qwen gateway).  When parsing fails, a
        single repair pass re-sends the bad reply and asks for bare JSON;
        token usage is accumulated over both attempts so cost accounting
        covers the whole exchange.

        Returns:
            The decoded JSON value (dict/list/...).

        Raises:
            LLMError: when no JSON document can be recovered from the reply
                or from the repair pass.
        """
        text = self.chat(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
        )
        try:
            return _extract_json(text)
        except LLMError:
            print("[llm] [repair] JSON parse failed; retrying with repair pass")
            first_usage = self.last_usage
            repair = list(messages) + [
                {"role": "assistant", "content": text},
                {"role": "user", "content": _JSON_REPAIR_PROMPT},
            ]
            try:
                text = self.chat(
                    repair,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    json_mode=json_mode,
                )
            except LLMError:
                # Keep the first call's usage so cost accounting still covers
                # the call that actually billed tokens.
                self.last_usage = first_usage
                raise
            if first_usage is not None and self.last_usage is not None:
                self.last_usage = TokenUsage(
                    prompt_tokens=first_usage.prompt_tokens
                    + self.last_usage.prompt_tokens,
                    completion_tokens=first_usage.completion_tokens
                    + self.last_usage.completion_tokens,
                    total_tokens=first_usage.total_tokens
                    + self.last_usage.total_tokens,
                )
            try:
                result = _extract_json(text)
            except LLMError:
                raise
            print("[llm] [repair] JSON parse recovered after repair pass")
            return result


def is_configured() -> bool:
    """``True`` when ``FLOWSTALLION_LLM_API_KEY`` is set to a non-empty value."""
    return bool(os.environ.get(ENV_API_KEY, "").strip())
