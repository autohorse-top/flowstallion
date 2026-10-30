"""Tests for flowstallion_agent.watch — poll pass, note archiving, idempotency."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from flowstallion_agent import watch
from flowstallion_agent.client import RunStepInfo, SchedulerClient

FAILED_RUN = {
    "id": 5, "pipeline_id": 1, "status": "failed", "trigger": "manual",
    "source_ref": "", "started_at": "t1", "finished_at": "t2", "created_at": "t0",
}
OK_RUN = {
    "id": 4, "pipeline_id": 1, "status": "success", "trigger": "manual",
    "source_ref": "", "started_at": "t1", "finished_at": "t2", "created_at": "t0",
}
FAIL_STEPS = [
    {"id": 1, "step_id": "build", "step_index": 0, "status": "failed",
     "image": "alpine", "command": ["make build"],
     "started_at": "t1", "finished_at": "t2"},
]
LOGS = [
    {"seq": 1, "line": "make[1]: Entering directory", "ts": "t1"},
    {"seq": 2, "line": "sh: make: command not found", "ts": "t2"},
]


class WatchState:
    def __init__(self) -> None:
        self.analyses: dict[int, dict[str, Any]] = {}


def make_handler(state: WatchState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
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
                self._send(200, [OK_RUN, FAILED_RUN])
            elif parsed.path == "/api/runs/5":
                self._send(200, {
                    "run": FAILED_RUN,
                    "steps": FAIL_STEPS,
                    "analysis": state.analyses.get(5),
                })
            elif parsed.path == "/api/runs/5/logs":
                self._send(200, {"logs": LOGS})
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
def watch_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[tuple[SchedulerClient, WatchState, Path], None, None]:
    monkeypatch.delenv("FLOWSTALLION_LLM_API_KEY", raising=False)
    state = WatchState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    host_s = host.decode() if isinstance(host, bytes) else host
    client = SchedulerClient(base_url=f"http://{host_s}:{port}")
    yield client, state, tmp_path
    server.shutdown()


def test_pick_failed_step() -> None:
    ok = RunStepInfo("a", 0, "success", "img", ("x",), "", "")
    bad = RunStepInfo("b", 1, "failed", "img", ("y",), "", "")
    assert watch.pick_failed_step([ok, bad]) is bad
    assert watch.pick_failed_step([ok]) is None
    assert watch.pick_failed_step([]) is None


def test_write_note(tmp_path: Path) -> None:
    from flowstallion_agent.client import RunInfo
    from flowstallion_agent.triage import RCA

    run = RunInfo(5, 1, "failed", "manual", "", "t1", "t2", "t0")
    step = RunStepInfo("build", 0, "failed", "alpine", ("make build",), "", "")
    rca = RCA("rule", "Command not found", "d", "fix", "make build", "excerpt")
    path = watch.write_note(str(tmp_path / "notes"), run, step, rca)
    text = Path(path).read_text(encoding="utf-8")
    assert path == str(tmp_path / "notes" / "run-5.md")
    assert "Run #5" in text
    assert "Command not found" in text
    assert "make build" in text


def test_poll_once_triages_failed_run(
    watch_env: tuple[SchedulerClient, WatchState, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    client, state, tmp_path = watch_env
    notes = str(tmp_path / "notes")
    analyzed = watch.poll_once(client, notes)
    assert analyzed == 1
    assert state.analyses[5]["kind"] == "rule"
    assert state.analyses[5]["step_id"] == "build"
    assert "not found" in state.analyses[5]["root_cause"].lower()
    note = Path(notes, "run-5.md")
    assert note.exists()
    assert "Command not found" in note.read_text(encoding="utf-8")


def test_poll_once_skips_analyzed(
    watch_env: tuple[SchedulerClient, WatchState, Path]
) -> None:
    client, state, tmp_path = watch_env
    assert watch.poll_once(client, str(tmp_path / "notes")) == 1
    # Second pass sees the stored analysis and must not re-post.
    assert watch.poll_once(client, str(tmp_path / "notes")) == 0
    assert len(state.analyses) == 1


def test_poll_once_ignores_success_runs(
    watch_env: tuple[SchedulerClient, WatchState, Path]
) -> None:
    client, state, tmp_path = watch_env
    assert watch.poll_once(client, str(tmp_path / "notes")) == 1
    assert 4 not in state.analyses


def test_poll_once_survives_client_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """An unreachable scheduler must not kill the sidecar pass."""
    client = SchedulerClient(base_url="http://127.0.0.1:1", timeout_s=0.5)
    assert watch.poll_once(client, str(tmp_path / "notes")) == 0


def test_cli_entrypoint_help(tmp_path: Path) -> None:
    """``python -m flowstallion_agent.watch --help`` must actually run main()."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    proc = subprocess.run(
        [sys.executable, "-m", "flowstallion_agent.watch", "--help"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "usage" in proc.stdout.lower()
    assert "--repo-root" in proc.stdout
    assert "--no-ai" in proc.stdout
