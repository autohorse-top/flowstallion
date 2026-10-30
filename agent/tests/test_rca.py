"""Tests for flowstallion_agent.rca (root-cause analysis over the Kuzu graph)."""

import json
import subprocess
import sys
from collections.abc import Generator
from pathlib import Path

import kuzu
import pytest

from flowstallion_agent import collectors, rca
from flowstallion_agent.graph import open_db, upsert_node

C4 = "c4" * 20
C6 = "c6" * 20


@pytest.fixture()
def conn(tmp_path: Path) -> Generator[kuzu.Connection, None, None]:
    c = open_db(str(tmp_path / "flowstallion"))
    collectors.build_sample_data(c)
    yield c
    c.close()


def test_rca_release_full_chain(conn: kuzu.Connection) -> None:
    data = rca.rca(conn, 3)
    assert data["kind"] == "release"
    assert data["incident_key"] == "rel:sample:3"
    assert data["summary"]["name"] == "demoapp"
    assert data["summary"]["state"] == "rolled_back"
    assert "error rate 0.83" in data["summary"]["reason"]
    assert len(data["events"]) == 3
    assert data["events"][0]["state"] == "applying"
    assert data["events"][-1]["state"] == "rolled_back"
    roles = {img["role"]: img["key"] for img in data["images"]}
    assert roles == {
        "canary": "flowstallion/demoapp:v2",
        "stable": "flowstallion/demoapp:v1",
    }
    assert len(data["k8s_objects"]) == 3
    assert data["source_commit"]["key"] == C4
    assert data["source_commit"]["subject"] == "fix: broken change that rolls back"
    # parent chain: c4 -> c3 -> c2 -> c1 (depth cap 5 not reached)
    assert [c["key"] for c in data["parent_chain"]] == [C4, "c3" * 20, "c2" * 20, "c1" * 20]
    assert [r["key"] for r in data["sibling_runs"]] == ["run:sample:2"]
    assert data["sibling_releases"] == []


def test_rca_release_depth_cap(conn: kuzu.Connection) -> None:
    data = rca.rca(conn, 3, depth=1)
    assert [c["key"] for c in data["parent_chain"]] == [C4, "c3" * 20]


def test_rca_run(conn: kuzu.Connection) -> None:
    data = rca.rca(conn, 2)
    assert data["kind"] == "run"
    assert data["incident_key"] == "run:sample:2"
    assert data["summary"]["status"] == "failed"
    assert data["pipeline"]["key"] == "demo"
    assert [s["step_id"] for s in data["steps"]] == ["test"]
    assert data["steps"][0]["status"] == "failed"
    assert data["source_commit"]["key"] == C4
    assert [r["key"] for r in data["sibling_releases"]] == ["rel:sample:3"]
    assert data["sibling_runs"] == []


def test_rca_steps_failed_first(conn: kuzu.Connection) -> None:
    # add an extra (passing) step to the failed run; failed must sort first
    from flowstallion_agent.graph import upsert_node, upsert_rel

    upsert_node(conn, "Step", "step:run:sample:2:build", run_key="run:sample:2",
                step_id="build", status="success", image="alpine:3.20")
    upsert_rel(conn, "RUN_STEP", "Run", "run:sample:2", "Step", "step:run:sample:2:build")
    data = rca.rca(conn, 2)
    assert [s["step_id"] for s in data["steps"]] == ["test", "build"]


def test_rca_unknown_id_raises(conn: kuzu.Connection) -> None:
    with pytest.raises(rca.RCAError):
        rca.rca(conn, 999)


def test_rca_auto_ambiguous_id_raises(conn: kuzu.Connection) -> None:
    """An id matching both a Release and a Run must not silently resolve (m-2)."""
    upsert_node(conn, "Release", "rel:test:7", id=7, name="t", state="promoted")
    upsert_node(conn, "Run", "run:test:7", id=7, status="success")
    with pytest.raises(rca.RCAError, match="both a Release and a Run"):
        rca.rca(conn, 7)


def test_rca_kind_filter(conn: kuzu.Connection) -> None:
    # run 2 is not a release
    with pytest.raises(rca.RCAError):
        rca.rca(conn, 2, kind="release")
    # release 3 is not a run
    with pytest.raises(rca.RCAError):
        rca.rca(conn, 3, kind="run")


def test_format_report_release(conn: kuzu.Connection) -> None:
    report = rca.format_report(rca.rca(conn, 3))
    for frag in (
        "=== RCA: Release rel:sample:3 (demoapp @ flowstallion) ===",
        "state: rolled_back",
        "error rate 0.83",
        "2026-10-22T00:00:10Z",
        "canary: flowstallion/demoapp:v2",
        "stable: flowstallion/demoapp:v1",
        "deployment flowstallion/demoapp-canary",
        "fix: broken change that rolls back",
        "Parent chain (3 more)",
        "run: run:sample:2 (demo, failed)",
    ):
        assert frag in report, frag


def test_format_report_run(conn: kuzu.Connection) -> None:
    report = rca.format_report(rca.rca(conn, 2))
    for frag in (
        "=== RCA: Run run:sample:2 (pipeline demo) ===",
        "status: failed",
        "test  failed  image=alpine:3.20",
        "release: rel:sample:3 (demoapp, rolled_back)",
    ):
        assert frag in report, frag


def _cli(tmp_path: Path, module: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = {"PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    import os

    full = dict(os.environ)
    full.update(env)
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        capture_output=True,
        text=True,
        env=full,
        check=False,
    )


def _build_sample_db(tmp_path: Path) -> None:
    """Build the sample DB in a separate process (avoids Kuzu file-lock carryover)."""
    p = _cli(tmp_path, "flowstallion_agent.collectors",
             "--db", str(tmp_path / "cli"), "--sample")
    assert p.returncode == 0, p.stderr


def test_cli_json_output(tmp_path: Path) -> None:
    _build_sample_db(tmp_path)
    proc = _cli(tmp_path, "flowstallion_agent.rca", "--db", str(tmp_path / "cli"), "3", "--json")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["kind"] == "release"
    assert data["incident_key"] == "rel:sample:3"
    assert len(data["events"]) == 3


def test_cli_text_output(tmp_path: Path) -> None:
    _build_sample_db(tmp_path)
    proc = _cli(tmp_path, "flowstallion_agent.rca", "--db", str(tmp_path / "cli"), "3")
    assert proc.returncode == 0, proc.stderr
    assert "=== RCA: Release rel:sample:3" in proc.stdout


def test_cli_unknown_exit_code(tmp_path: Path) -> None:
    _build_sample_db(tmp_path)
    proc = _cli(tmp_path, "flowstallion_agent.rca", "--db", str(tmp_path / "cli"), "999")
    assert proc.returncode == 2
    assert "no incident" in proc.stderr
