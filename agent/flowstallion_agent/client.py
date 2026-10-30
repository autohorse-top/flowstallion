"""Scheduler HTTP client — stdlib-only, for the AI agent.

Talks to the Go scheduler's public API: run listing, run detail with
steps + analysis, per-step logs, and POSTing a root-cause analysis.
Errors surface as :class:`ClientError` (404 → :class:`ClientNotFound`)
so watch loops can distinguish "run gone" from transient failures.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ENV_SERVER",
    "DEFAULT_SERVER",
    "AnalysisReport",
    "ClientError",
    "ClientNotFound",
    "ClientHTTPError",
    "RunInfo",
    "RunStepInfo",
    "SchedulerClient",
]

ENV_SERVER = "FLOWSTALLION_SERVER"
DEFAULT_SERVER = "http://localhost:8080"


class ClientError(Exception):
    """Base error for scheduler client failures."""


class ClientNotFound(ClientError):
    """The requested resource (run/step) does not exist (HTTP 404)."""


class ClientHTTPError(ClientError):
    """Non-404 HTTP failure from the scheduler."""

    def __init__(self, status: int, url: str, body: str) -> None:
        snippet = body[:512]
        super().__init__(f"scheduler request failed: HTTP {status} from {url}: {snippet}")
        self.status: int = status
        self.body: str = snippet
        self.url: str = url


@dataclass(frozen=True)
class RunInfo:
    id: int
    pipeline_id: int
    status: str
    trigger: str
    source_ref: str
    started_at: str
    finished_at: str
    created_at: str
    # P7: GitHub pull_request trigger metadata. pr == 0 means the run was
    # not PR-triggered (push / manual / schedule / canary); refs/URL are
    # empty for those runs.
    pr: int = 0
    base_ref: str = ""
    head_ref: str = ""
    repo_url: str = ""


@dataclass(frozen=True)
class RunStepInfo:
    step_id: str
    step_index: int
    status: str
    image: str
    commands: tuple[str, ...]
    started_at: str
    finished_at: str


@dataclass(frozen=True)
class AnalysisReport:
    """Stored root-cause report (shape of GET /api/runs/{id} → analysis)."""

    step_id: str
    kind: str
    root_cause: str
    detail: str
    suggested_fix: str
    command: str
    log_excerpt: str
    created_at: str


def server_from_env() -> str:
    """Scheduler base URL from ``FLOWSTALLION_SERVER`` (default localhost:8080).

    An explicitly-set-but-empty value falls back to the default.
    """
    raw = os.environ.get(ENV_SERVER, "").strip()
    return raw.rstrip("/") if raw else DEFAULT_SERVER.rstrip("/")


def _run_from_dict(raw: dict[str, Any]) -> RunInfo:
    return RunInfo(
        id=int(raw.get("id", 0)),
        pipeline_id=int(raw.get("pipeline_id", 0)),
        status=str(raw.get("status", "")),
        trigger=str(raw.get("trigger", "")),
        source_ref=str(raw.get("source_ref", "")),
        started_at=str(raw.get("started_at", "")),
        finished_at=str(raw.get("finished_at", "")),
        created_at=str(raw.get("created_at", "")),
        pr=int(raw.get("pr") or 0),
        base_ref=str(raw.get("base_ref") or ""),
        head_ref=str(raw.get("head_ref") or ""),
        repo_url=str(raw.get("repo_url") or ""),
    )


def _step_from_dict(raw: dict[str, Any]) -> RunStepInfo:
    cmds = raw.get("command")
    if isinstance(cmds, list):
        commands: tuple[str, ...] = tuple(str(c) for c in cmds)
    else:
        commands = ()
    return RunStepInfo(
        step_id=str(raw.get("step_id", "")),
        step_index=int(raw.get("step_index", 0)),
        status=str(raw.get("status", "")),
        image=str(raw.get("image", "")),
        commands=commands,
        started_at=str(raw.get("started_at", "")),
        finished_at=str(raw.get("finished_at", "")),
    )


def _analysis_from_dict(raw: dict[str, Any]) -> AnalysisReport:
    return AnalysisReport(
        step_id=str(raw.get("step_id", "")),
        kind=str(raw.get("kind", "")),
        root_cause=str(raw.get("root_cause", "")),
        detail=str(raw.get("detail", "")),
        suggested_fix=str(raw.get("suggested_fix", "")),
        command=str(raw.get("command", "")),
        log_excerpt=str(raw.get("log_excerpt", "")),
        created_at=str(raw.get("created_at", "")),
    )


class SchedulerClient:
    """Minimal typed client for the scheduler REST API."""

    def __init__(
        self,
        base_url: str,
        timeout_s: float = 30.0,
        agent_token: str | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("base_url must be non-empty")
        self.base_url: str = base_url.rstrip("/")
        self.timeout_s: float = timeout_s
        # P7⑥: agent token for the scheduler's requireAgent gate. When None,
        # falls back to the FLOWSTALLION_AGENT_TOKEN environment variable.
        # Empty → no header (auth-less scheduler, e.g. local dev).
        token = (agent_token or os.environ.get("FLOWSTALLION_AGENT_TOKEN", "")).strip()
        self.agent_token: str = token

    # ------------------------------------------------------------------
    # low-level
    # ------------------------------------------------------------------
    def _request(
        self, method: str, path: str, body: bytes | None = None
    ) -> tuple[int, bytes]:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(
            url,
            data=body,
            method=method,
        )
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if self.agent_token:
            req.add_header("X-Agent-Token", self.agent_token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            data = exc.read()
            if exc.code == 404:
                raise ClientNotFound(f"404 from {url}") from exc
            raise ClientHTTPError(exc.code, url, data.decode("utf-8", "replace")) from exc
        except urllib.error.URLError as exc:
            raise ClientError(f"scheduler unreachable at {url}: {exc.reason!r}") from exc

    def _get_json(self, path: str) -> Any:
        status, data = self._request("GET", path)
        if status >= 400:
            raise ClientHTTPError(status, f"{self.base_url}{path}", data.decode("utf-8", "replace"))
        if not data:
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ClientError(f"malformed JSON from {path}: {exc}") from exc

    def _post_json(self, path: str, payload: dict[str, Any]) -> Any:
        body = json.dumps(payload).encode("utf-8")
        status, data = self._request("POST", path, body)
        if status >= 400:
            raise ClientHTTPError(status, f"{self.base_url}{path}", data.decode("utf-8", "replace"))
        if not data:
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ClientError(f"malformed JSON from {path}: {exc}") from exc

    # ------------------------------------------------------------------
    # endpoints
    # ------------------------------------------------------------------
    def list_runs(self, limit: int = 50) -> list[RunInfo]:
        """Latest runs (newest first). No server-side status filter exists,
        callers filter client-side."""
        raw = self._get_json(f"/api/runs?limit={urllib.parse.quote(str(limit))}")
        items: list[Any] = raw if isinstance(raw, list) else []
        return [_run_from_dict(x) for x in items if isinstance(x, dict)]

    def get_run(self, run_id: int) -> tuple[RunInfo, list[RunStepInfo], AnalysisReport | None]:
        """Run detail with steps and the stored analysis (None if absent)."""
        raw = self._get_json(f"/api/runs/{run_id}")
        if not isinstance(raw, dict):
            raise ClientError(f"unexpected run payload for run {run_id}")
        run = _run_from_dict(raw.get("run", {}))
        steps_raw = raw.get("steps")
        steps = [
            _step_from_dict(s)
            for s in (steps_raw if isinstance(steps_raw, list) else [])
            if isinstance(s, dict)
        ]
        analysis_raw = raw.get("analysis")
        analysis = _analysis_from_dict(analysis_raw) if isinstance(analysis_raw, dict) else None
        return run, steps, analysis

    def get_step_logs(
        self, run_id: int, step_id: str, after: int = 0, limit: int = 500
    ) -> list[str]:
        """Log lines for one step (newest ``limit`` lines after ``after`` seq)."""
        q = urllib.parse.urlencode(
            {"step": step_id, "after": after, "limit": limit}
        )
        raw = self._get_json(f"/api/runs/{run_id}/logs?{q}")
        if not isinstance(raw, dict):
            raise ClientError(f"unexpected logs payload for run {run_id}")
        logs_raw = raw.get("logs")
        lines: list[str] = []
        for row in logs_raw if isinstance(logs_raw, list) else []:
            if isinstance(row, dict) and isinstance(row.get("line"), str):
                lines.append(row["line"])
        return lines

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
        """POST an analysis report; 404/400 raise Client*Error."""
        self._post_json(
            f"/api/runs/{run_id}/analysis",
            {
                "step_id": step_id,
                "kind": kind,
                "root_cause": root_cause,
                "detail": detail,
                "suggested_fix": suggested_fix,
                "command": command,
                "log_excerpt": log_excerpt,
            },
        )

    def list_analyses(self, run_id: int) -> list[AnalysisReport]:
        """All stored analyses for a run (all kinds), oldest first."""
        raw = self._get_json(f"/api/runs/{run_id}")
        if not isinstance(raw, dict):
            raise ClientError(f"unexpected run payload for run {run_id}")
        raw_list = raw.get("analyses")
        if not isinstance(raw_list, list):
            return []
        return [
            _analysis_from_dict(e) for e in raw_list if isinstance(e, dict)
        ]
