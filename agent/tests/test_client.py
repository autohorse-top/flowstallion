"""Tests for flowstallion_agent.client against an in-process fake scheduler."""

from __future__ import annotations

import json
import threading
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from flowstallion_agent.client import (
    ClientError,
    ClientNotFound,
    SchedulerClient,
    server_from_env,
)

RUNS_PAYLOAD = [
    {"id": 5, "pipeline_id": 1, "status": "failed", "trigger": "manual",
     "source_ref": "", "started_at": "t1", "finished_at": "t2", "created_at": "t0"},
    {"id": 4, "pipeline_id": 1, "status": "success", "trigger": "manual",
     "source_ref": "", "started_at": "t1", "finished_at": "t2", "created_at": "t0"},
]

RUN_DETAIL = {
    "run": RUNS_PAYLOAD[0],
    "steps": [
        {"id": 1, "step_id": "build", "step_index": 0, "status": "failed",
         "image": "alpine", "command": ["make build"],
         "started_at": "t1", "finished_at": "t2"},
    ],
    "analysis": None,
}

LOGS = {"logs": [
    {"seq": 1, "line": "make[1]: Entering directory", "ts": "t1"},
    {"seq": 2, "line": "make: *** No rule to make target", "ts": "t2"},
]}


class FakeScheduler:
    """State the handler serves; tests can mutate it."""

    def __init__(self) -> None:
        self.analyses: dict[int, dict[str, Any]] = {}


def make_handler(state: FakeScheduler) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # silence
            pass

        def _send(self, code: int, payload: object) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/runs":
                self._send(200, RUNS_PAYLOAD)
            elif parsed.path == "/api/runs/5":
                detail = json.loads(json.dumps(RUN_DETAIL))
                detail["analysis"] = state.analyses.get(5)
                self._send(200, detail)
            elif parsed.path == "/api/runs/5/logs":
                self._send(200, LOGS)
            elif parsed.path.startswith("/api/runs/"):
                self._send(404, {"error": "run not found"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            parsed = urlparse(self.path)
            if parsed.path == "/api/runs/5/analysis":
                state.analyses[5] = body
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not found"})

    return Handler


@pytest.fixture()
def client_and_state() -> Generator[tuple[SchedulerClient, FakeScheduler], None, None]:
    state = FakeScheduler()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    host_s = host.decode() if isinstance(host, bytes) else host
    client = SchedulerClient(base_url=f"http://{host_s}:{port}")
    yield client, state
    server.shutdown()


def test_server_from_env_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FLOWSTALLION_SERVER", raising=False)
    assert server_from_env() == "http://localhost:8080"


def test_server_from_env_trailing_slash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLOWSTALLION_SERVER", "http://host:9000/")
    assert server_from_env() == "http://host:9000"


def test_server_from_env_empty_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLOWSTALLION_SERVER", "   ")
    assert server_from_env() == "http://localhost:8080"


def test_list_runs(client_and_state: tuple[SchedulerClient, FakeScheduler]) -> None:
    client, _ = client_and_state
    runs = client.list_runs(limit=50)
    assert [r.id for r in runs] == [5, 4]
    assert runs[0].status == "failed"


def test_get_run(client_and_state: tuple[SchedulerClient, FakeScheduler]) -> None:
    client, _ = client_and_state
    run, steps, analysis = client.get_run(5)
    assert run.id == 5
    assert len(steps) == 1
    assert steps[0].step_id == "build"
    assert steps[0].commands == ("make build",)
    assert analysis is None


def test_get_run_404(client_and_state: tuple[SchedulerClient, FakeScheduler]) -> None:
    client, _ = client_and_state
    with pytest.raises(ClientNotFound):
        client.get_run(999)


def test_get_step_logs(client_and_state: tuple[SchedulerClient, FakeScheduler]) -> None:
    client, _ = client_and_state
    lines = client.get_step_logs(5, "build")
    assert lines == [LOGS["logs"][0]["line"], LOGS["logs"][1]["line"]]


def test_post_analysis_roundtrip(client_and_state: tuple[SchedulerClient, FakeScheduler]) -> None:
    client, state = client_and_state
    client.post_analysis(
        5, step_id="build", kind="rule", root_cause="boom",
        detail="d", suggested_fix="f", command="make build", log_excerpt="e",
    )
    assert state.analyses[5]["root_cause"] == "boom"
    assert state.analyses[5]["kind"] == "rule"
    assert state.analyses[5]["step_id"] == "build"


def test_post_analysis_unknown_run(client_and_state: tuple[SchedulerClient, FakeScheduler]) -> None:
    client, _ = client_and_state
    with pytest.raises(ClientError):
        client.post_analysis(999, step_id="a", kind="rule", root_cause="x")
