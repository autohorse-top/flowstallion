"""Failure triage — rule-based first, LLM fallback upgrade.

:func:`analyze` produces a :class:`RCA` (root-cause analysis) for a failed
step.  The deterministic rule table always runs; when an LLM client is
supplied it is used to *upgrade* the report (kind="llm"), and any LLM
failure degrades back to the rule result so the sidecar never blocks the
core pipeline (TASK.md: "all AI features are bypass services").

Cost bookkeeping is opt-in: when ``FLOWSTALLION_COST_LEDGER`` is set, every
LLM call that completes over HTTP appends its token usage to the ledger
(P5) — even when the reply degrades back to the rule result; a failed HTTP
call records nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from flowstallion_agent.llm import LLM, LLMError

__all__ = ["RCA", "RULES", "LOG_TAIL_LINES", "LOG_EXCERPT_CHARS", "analyze"]

# Cap the log tail fed to triage / stored as excerpt.
LOG_TAIL_LINES = 500
LOG_EXCERPT_CHARS = 4000


@dataclass(frozen=True)
class RCA:
    """Root-cause analysis report for one failed run/step."""

    kind: str            # "rule" | "llm"
    root_cause: str
    detail: str
    suggested_fix: str
    command: str
    log_excerpt: str


class _Rule:
    __slots__ = ("pattern", "root_cause", "detail", "suggested_fix")

    def __init__(self, pattern: str, root_cause: str, detail: str, suggested_fix: str) -> None:
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.root_cause = root_cause
        self.detail = detail
        self.suggested_fix = suggested_fix


# Ordered: first match wins. Specific signatures before generic ones.
RULES: list[_Rule] = [
    _Rule(
        r"Killed|out of memory|cannot allocate memory|oom-kill",
        "Out-of-memory (OOM)",
        "The process was killed by the kernel OOM killer or exhausted memory.",
        "Reduce per-step memory (concurrency/batch size) or raise the "
        "container memory limit in the step image/runtime config.",
    ),
    _Rule(
        r"command not found|'[^']*' is not recognized",
        "Command not found",
        "The shell could not locate the executable referenced by the step command.",
        "Check the command name/path; install the tool in the step image or "
        "use an absolute path.",
    ),
    _Rule(
        r"No such file or directory",
        "Missing file or path",
        "A required file, script, or directory does not exist in the container.",
        "Verify the path exists at runtime; check build context, mounted "
        "artifacts, and relative working directory.",
    ),
    _Rule(
        r"Permission denied",
        "Permission denied",
        "The step process lacked file-system or network permissions.",
        "Check file ownership/umask, container user, and required capabilities "
        "(e.g. /var/run/docker.sock access, DNS).",
    ),
    _Rule(
        r"ModuleNotFoundError|ImportError|SyntaxError",
        "Python import/definition error",
        "A Python import or syntax problem aborted the step.",
        "Install the missing package (pin it in the step image) and check the "
        "offending file for syntax errors.",
    ),
    _Rule(
        r"panic:",
        "Go runtime panic",
        "A Go program panicked (nil dereference, index out of range, etc.).",
        "Read the panic goroutine trace in the log and fix the offending code "
        "path; add a regression test.",
    ),
    _Rule(
        r"Segmentation fault|segfault",
        "Segmentation fault",
        "A native crash (SIGSEGV) terminated the process.",
        "Reproduce locally with the same image; check binary/library "
        "compatibility (glibc, arch) and native dependency versions.",
    ),
    _Rule(
        r"\b(FAILED|AssertionError|assert(ion)? (?:equal|is)|E   AssertionError)\b",
        "Test / assertion failure",
        "A test or assertion failed inside the step.",
        "Inspect the failing assertion output; fix the code or update the "
        "stale test expectation.",
    ),
    _Rule(
        r"non-zero exit|exited with (?:code|status) (\d+)|exit status \d+",
        "Non-zero exit code",
        "The step command exited with a non-zero status.",
        "Read the log lines above the exit; the failing command's own error "
        "message is usually the last meaningful line.",
    ),
]


def _tail(lines: list[str], n: int = LOG_TAIL_LINES) -> str:
    tail = lines[-n:] if len(lines) > n else lines
    text = "\n".join(tail)
    if len(text) > LOG_EXCERPT_CHARS:
        text = "…" + text[-LOG_EXCERPT_CHARS:]
    return text


def _rule_match(logs: list[str], command: str) -> tuple[_Rule | None, str]:
    """First matching rule over the full log; returns (rule, matched_line)."""
    for rule in RULES:
        for line in logs:
            if rule.pattern.search(line):
                return rule, line
    return None, ""


def _rule_rca(logs: list[str], command: str) -> RCA:
    rule, matched = _rule_match(logs, command)
    excerpt = _tail(logs)
    if rule is not None:
        return RCA(
            kind="rule",
            root_cause=rule.root_cause,
            detail=f"Pattern matched: {matched.strip()[:300]}",
            suggested_fix=rule.suggested_fix,
            command=command,
            log_excerpt=excerpt,
        )
    last = logs[-1].strip() if logs else ""
    return RCA(
        kind="rule",
        root_cause="Step exited with a non-zero status",
        detail=f"No known failure signature matched. Last log line: {last[:300]}",
        suggested_fix="Inspect the full step log; the failure cause is not in "
        "the standard signature table.",
        command=command,
        log_excerpt=excerpt,
    )


# Reasoning models (e.g. Qwen3) spend thinking tokens from the same
# max_tokens budget as the reply body; 512 was silently exhausted by the
# thinking phase, leaving an empty body and a JSON parse failure. 4096
# keeps headroom for both phases.
_LLM_MAX_TOKENS = 4096

# Probed behaviour (2026-10-27, qwen3.8-27b under response_format=json_object):
# replies are valid JSON but the model frequently renames the requested keys
# (likely_cause / diagnosis / evidence / next_steps / ...). Exact names come
# first; first non-empty value wins. root_cause stays required so a garbage
# reply still degrades to the rule result.
_KEY_ALIASES: dict[str, tuple[str, ...]] = {
    "root_cause": (
        "root_cause",
        "root_cause_analysis",
        "root-cause",
        "rootcause",
        "likely_cause",
        "cause",
        "diagnosis",
    ),
    "detail": (
        "detail",
        "details",
        "description",
        "evidence",
        "analysis",
        "explanation",
    ),
    "suggested_fix": (
        "suggested_fix",
        "suggested_fixes",
        "fix_suggestion",
        "fix",
        "recommendation",
        "recommendations",
        "next_steps",
    ),
}


def _pick_field(obj: dict[str, object], field: str) -> str:
    """First non-empty value among a field's alias keys; '' when absent."""
    for key in _KEY_ALIASES[field]:
        value = obj.get(key)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
        elif isinstance(value, list):
            parts = [str(item).strip() for item in value if str(item).strip()]
            if parts:
                return "; ".join(parts)
    return ""


_LLM_SYSTEM = (
    "You are a CI failure triage engine. Input: a failing step's command and "
    "log tail. Output: a single JSON object with exactly these three string "
    "keys and nothing else:\n"
    '  "root_cause": short label of the failure\n'
    '  "detail": 1-3 sentences citing evidence from the log\n'
    '  "suggested_fix": one concrete action to fix it\n'
    "Do not use any other keys. Example:\n"
    '{"root_cause": "test assertion failure", "detail": "parse_test.go:42 '
    'expected 2, got 5.", "suggested_fix": "Update the parser or the test '
    'expectation."}'
)


def _llm_rca(llm: LLM, command: str, logs: list[str]) -> RCA:
    user = (
        f"Command:\n{command}\n\n"
        f"Log tail (last {LOG_TAIL_LINES} lines):\n{_tail(logs)}"
    )
    data = llm.chat_json(
        [
            {"role": "system", "content": _LLM_SYSTEM},
            {"role": "user", "content": user},
        ],
        temperature=0.1,
        max_tokens=_LLM_MAX_TOKENS,
    )
    if not isinstance(data, dict):
        raise LLMError("LLM triage reply was not a JSON object")
    root = _pick_field(data, "root_cause")
    if not root:
        raise LLMError("LLM triage reply missing root_cause")
    return RCA(
        kind="llm",
        root_cause=root[:300],
        detail=_pick_field(data, "detail")[:2000],
        suggested_fix=_pick_field(data, "suggested_fix")[:2000],
        command=command,
        log_excerpt=_tail(logs),
    )


def _maybe_record_usage(llm: LLM, *, run_id: str | None, pr: str, team: str) -> None:
    """Opt-in FinOps bookkeeping (P5).

    Delegates to :func:`flowstallion_agent.cost.maybe_record_llm_usage`.
    Cost bookkeeping must never affect the returned RCA.
    """
    from flowstallion_agent.cost import maybe_record_llm_usage

    maybe_record_llm_usage(llm, run_id=run_id, pr=pr, team=team)


def analyze(
    logs: list[str],
    command: str,
    llm: LLM | None = None,
    *,
    run_id: str | None = None,
    pr: str = "unknown",
    team: str = "unknown",
) -> RCA:
    """Produce an RCA for a failed step.

    Rules always run. When ``llm`` is provided, the LLM result is used if it
    is valid; any :class:`LLMError` (or network failure) falls back to the
    rule-based report so triage is never blocked by the model.

    FinOps (opt-in): when an LLM call completes over HTTP and the
    environment sets ``FLOWSTALLION_COST_LEDGER``, the call's token usage is
    appended to that ledger (``run_id``/``pr``/``team`` labels) — even if
    the reply is later rejected and the result degrades to the rule RCA
    (the tokens were still billed). A failed HTTP call records nothing.
    Ledger failures are swallowed; env-unset is zero behaviour change.
    """
    base = _rule_rca(logs, command)
    if llm is None:
        return base
    try:
        rca = _llm_rca(llm, command, logs)
    except LLMError as exc:
        rca = base
        print(f"[triage] [degraded] LLM triage unavailable (run {run_id or '?'}): {exc}")
    except Exception as exc:
        # Sidecar robustness: never let triage crash the watch loop.
        rca = base
        print(f"[triage] [degraded] LLM triage failed (run {run_id or '?'}): {exc}")
    # Recording anchor = "the LLM call completed over HTTP" (LLM.last_usage
    # is only set on success and cleared at the start of each call), not
    # "the LLM result was adopted": tokens are billed either way.
    _maybe_record_usage(llm, run_id=run_id, pr=pr, team=team)
    return rca
