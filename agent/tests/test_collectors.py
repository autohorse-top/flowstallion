"""Tests for flowstallion_agent.collectors (git / REST ingestion + sample fixture)."""

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from kuzu import Connection

from flowstallion_agent import collectors
from flowstallion_agent.graph import count_nodes, count_rels, open_db, upsert_node


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        GIT_AUTHOR_NAME="tester",
        GIT_AUTHOR_EMAIL="tester@example.com",
        GIT_COMMITTER_NAME="tester",
        GIT_COMMITTER_EMAIL="tester@example.com",
    )
    return env


def _git(path: str, *args: str) -> None:
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True, env=_git_env())


def make_fetcher(routes: list[tuple[str, object]]) -> collectors.Fetch:
    """Fake fetcher: routes is a list of (url-substring, json payload); miss -> 404."""

    def fetch(url: str) -> tuple[int, bytes]:
        for needle, payload in routes:
            if needle in url:
                if payload is None:
                    return 404, b'{"error": "not found"}'
                return 200, json.dumps(payload).encode("utf-8")
        return 404, b'{"error": "not found"}'

    return fetch


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------


def test_collect_git(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(str(repo), "init")
    for i in range(1, 4):
        (repo / f"f{i}.txt").write_text(f"content {i}\n")
        _git(str(repo), "add", f"f{i}.txt")
        _git(str(repo), "commit", "-m", f"commit {i}")
    conn = open_db(str(tmp_path / "g"))
    try:
        n = collectors.collect_git(conn, str(repo))
        assert n == 3
        assert count_nodes(conn, "Commit") == 3
        assert count_rels(conn, "HAS_PARENT") == 2
    finally:
        conn.close()


def test_collect_git_missing_repo(tmp_path: Path) -> None:
    conn = open_db(str(tmp_path / "g"))
    try:
        with pytest.raises(RuntimeError):
            collectors.collect_git(conn, str(tmp_path / "nope"))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# REST collectors
# ---------------------------------------------------------------------------


def test_collect_runs(tmp_path: Path) -> None:
    conn = open_db(str(tmp_path / "g"))
    try:
        sha = "a" * 40
        upsert_node(conn, "Commit", sha, subject="tip", author="x", date="2026-01-01")
        fetch = make_fetcher(
            [
                (
                    "/api/pipelines",
                    [{"id": 1, "name": "demo", "created_at": "t", "updated_at": "t"}],
                ),
                (
                    "/api/runs?limit=200",
                    [
                        {"id": 1, "pipeline_id": 1, "status": "success", "trigger": "push",
                         "source_ref": sha, "started_at": "s", "finished_at": "f", "created_at": "c"},
                        {"id": 2, "pipeline_id": 1, "status": "failed", "trigger": "push",
                         "source_ref": "main", "started_at": "s", "finished_at": "f", "created_at": "c"},
                    ],
                ),
                (
                    "/api/runs/1",
                    {"run": {}, "steps": [
                        {"id": 10, "step_id": "build", "step_index": 0, "status": "success",
                         "image": "alpine:3.20", "command": ["sh"], "started_at": "s", "finished_at": "f"},
                    ], "analysis": None},
                ),
                (
                    "/api/runs/2",
                    {"run": {}, "steps": [
                        {"id": 11, "step_id": "test", "step_index": 0, "status": "failed",
                         "image": "alpine:3.20", "command": ["sh"], "started_at": "s", "finished_at": "f"},
                    ], "analysis": None},
                ),
            ]
        )
        n = collectors.collect_runs(conn, "http://localhost:8080", "compose", fetcher=fetch)
        assert n == 2
        assert count_nodes(conn, "Pipeline") == 1
        assert count_nodes(conn, "Run") == 2
        assert count_nodes(conn, "Step") == 2
        assert count_nodes(conn, "Image") == 1
        assert count_rels(conn, "RUN_OF") == 2
        assert count_rels(conn, "RUN_STEP") == 2
        assert count_rels(conn, "STEP_USES_IMAGE") == 2
        # only the 40-hex source_ref with an existing Commit gets an edge
        assert count_rels(conn, "RUN_TRIGGERED_BY") == 1
    finally:
        conn.close()


def test_collect_canaries(tmp_path: Path) -> None:
    conn = open_db(str(tmp_path / "g"))
    try:
        sha = "b" * 40
        upsert_node(conn, "Commit", sha, subject="deployed", author="x", date="2026-01-01")
        canary = {
            "id": 1, "name": "app", "namespace": "prod",
            "stable_image": "img:1", "canary_image": "img:2",
            "replicas": 2, "port": 8080, "threshold": 0.3, "min_samples": 20,
            "warmup_s": 10.0, "observe_s": 20.0,
            "state": "observing", "reason": "", "last_err_rate": 0.0,
            "last_requests": 5, "last_errors": 0, "scrape_failures": 0,
            "canary_start": "2026-01-02T00:00:00Z", "created_at": "2026-01-02T00:00:00Z",
            "finished_at": "", "source_ref": sha,
        }
        fetch = make_fetcher(
            [
                ("/api/canaries/1", {"canary": canary, "events": [
                    {"ts": "2026-01-02T00:00:01Z", "state": "applying", "detail": "created"},
                    {"ts": "2026-01-02T00:00:30Z", "state": "observing", "detail": "warming"},
                    {"ts": "2026-01-02T00:01:00Z", "state": "observing", "detail": "ok"},
                ]}),
                ("/api/canaries", [canary]),
            ]
        )
        n = collectors.collect_canaries(conn, "http://localhost:8090", "cd", fetcher=fetch)
        assert n == 1
        assert count_nodes(conn, "Release") == 1
        assert count_nodes(conn, "K8sObject") == 3
        assert count_nodes(conn, "Event") == 3
        assert count_nodes(conn, "Image") == 2
        assert count_rels(conn, "RELEASE_DEPLOYS") == 2  # role canary + role stable
        assert count_rels(conn, "RELEASE_MANAGES") == 3
        assert count_rels(conn, "RELEASE_EVENT") == 3
        assert count_rels(conn, "RELEASE_TRIGGERED_BY") == 1
    finally:
        conn.close()


def test_collect_canaries_404_is_empty(tmp_path: Path) -> None:
    conn = open_db(str(tmp_path / "g"))
    try:
        fetch = make_fetcher([])  # every URL -> 404
        assert collectors.collect_canaries(conn, "http://localhost:8080", "compose", fetcher=fetch) == 0
        assert count_nodes(conn, "Release") == 0
    finally:
        conn.close()


def test_collect_canaries_same_app_two_releases_keep_roles(tmp_path: Path) -> None:
    """M-2 regression: two releases of the same app (rollback + re-release)
    must keep separate K8sObject nodes with per-release roles (the old shared
    key let the second release overwrite the first's role)."""
    conn = open_db(str(tmp_path / "g"))
    try:
        rolled = {
            "id": 1, "name": "demoapp", "namespace": "prod",
            "stable_image": "img:1", "canary_image": "img:2",
            "state": "rolled_back", "source_ref": "",
        }
        promoted = {
            "id": 2, "name": "demoapp", "namespace": "prod",  # same app, re-release
            "stable_image": "img:2", "canary_image": "img:3",
            "state": "promoted", "source_ref": "",
        }
        fetch = make_fetcher(
            [
                ("/api/canaries/1", {"canary": rolled, "events": []}),
                ("/api/canaries/2", {"canary": promoted, "events": []}),
                ("/api/canaries", [rolled, promoted]),
            ]
        )
        n = collectors.collect_canaries(conn, "http://localhost:8090", "cd", fetcher=fetch)
        assert n == 2
        # 2 releases x 3 objects => 6 distinct nodes, not 3 overwritten ones
        assert count_nodes(conn, "K8sObject") == 6
        assert count_rels(conn, "RELEASE_MANAGES") == 6

        def roles(release_key: str) -> list[str]:
            result: Any = conn.execute(
                f"MATCH (r:Release)-[:RELEASE_MANAGES]->(o:K8sObject) "
                f"WHERE r.key = '{release_key}' RETURN o.role"
            )
            rows = result.get_all()
            return sorted(str(role) for (role,) in rows)

        assert roles("rel:cd:1") == ["canary_deploy", "service", "stable_deploy"]
        assert roles("rel:cd:2") == ["production", "production", "service"]

        # idempotency: re-ingest must not grow the object set
        assert collectors.collect_canaries(conn, "http://localhost:8090", "cd", fetcher=fetch) == 2
        assert count_nodes(conn, "K8sObject") == 6
        assert count_rels(conn, "RELEASE_MANAGES") == 6
    finally:
        conn.close()


def test_k8s_objects_roles() -> None:
    pending = collectors.k8s_objects_for_release("app", "prod", "observing")
    assert pending == [
        ("deployment", "prod", "app", "stable_deploy"),
        ("deployment", "prod", "app-canary", "canary_deploy"),
        ("service", "prod", "app", "service"),
    ]
    promoted = collectors.k8s_objects_for_release("app", "prod", "promoted")
    assert promoted == [
        ("deployment", "prod", "app", "production"),
        ("deployment", "prod", "app-canary", "production"),
        ("service", "prod", "app", "service"),
    ]


# ---------------------------------------------------------------------------
# sample fixture
# ---------------------------------------------------------------------------


def _sample_counts(conn: Connection) -> dict[str, int]:
    out: dict[str, int] = {}
    for label in ("Commit", "Pipeline", "Run", "Step", "Image", "Release", "K8sObject", "Event"):
        out[label] = count_nodes(conn, label)
    for rel in ("HAS_PARENT", "RUN_OF", "RUN_STEP", "STEP_USES_IMAGE", "RUN_TRIGGERED_BY",
                "RELEASE_DEPLOYS", "RELEASE_TRIGGERED_BY", "RELEASE_MANAGES", "RELEASE_EVENT"):
        out[rel] = count_rels(conn, rel)
    return out


def test_build_sample_data(tmp_path: Path) -> None:
    conn = open_db(str(tmp_path / "s"))
    try:
        collectors.build_sample_data(conn)
        assert _sample_counts(conn) == {
            "Commit": 6, "Pipeline": 1, "Run": 2, "Step": 2, "Image": 5,
            "Release": 2, "K8sObject": 6, "Event": 5,
            "HAS_PARENT": 5, "RUN_OF": 2, "RUN_STEP": 2, "STEP_USES_IMAGE": 2,
            "RUN_TRIGGERED_BY": 2, "RELEASE_DEPLOYS": 4, "RELEASE_TRIGGERED_BY": 2,
            "RELEASE_MANAGES": 6, "RELEASE_EVENT": 5,
        }
        # idempotent: rebuilding changes nothing
        collectors.build_sample_data(conn)
        assert _sample_counts(conn)["Commit"] == 6
        assert _sample_counts(conn)["HAS_PARENT"] == 5
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# regression: event window stability (M-3)
# ---------------------------------------------------------------------------


def test_collect_canaries_event_window_slide_is_stable(tmp_path: Path) -> None:
    """The CD API serves a bounded most-recent window; event keys must stay
    stable (by event id) as the window slides, so re-scrapes do not duplicate
    Event nodes (M-3)."""
    conn = open_db(str(tmp_path / "g"))
    try:
        canary: dict[str, Any] = {
            "id": 1, "name": "app", "namespace": "prod",
            "stable_image": "img:1", "canary_image": "img:2",
            "state": "observing", "source_ref": "",
        }

        def make_events(start: int, n: int) -> list[dict[str, Any]]:
            return [
                {
                    "id": start + i,
                    "ts": f"2026-01-02T00:{(start + i) % 60:02d}:00Z",
                    "state": "observing",
                    "detail": f"ev {start + i}",
                }
                for i in range(n)
            ]

        # First scrape: window ids 1..10
        collectors.collect_canaries(
            conn, "http://localhost:8090", "cd",
            fetcher=make_fetcher([
                ("/api/canaries/1", {"canary": canary, "events": make_events(1, 10)}),
                ("/api/canaries", [canary]),
            ]),
        )
        # Second scrape: window slides to ids 6..15
        collectors.collect_canaries(
            conn, "http://localhost:8090", "cd",
            fetcher=make_fetcher([
                ("/api/canaries/1", {"canary": canary, "events": make_events(6, 10)}),
                ("/api/canaries", [canary]),
            ]),
        )
        # ids 1..15 => 15 unique events, no duplicates
        assert count_nodes(conn, "Event") == 15
        assert count_rels(conn, "RELEASE_EVENT") == 15
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# regression: malformed record isolation (m-1)
# ---------------------------------------------------------------------------


def test_collect_runs_isolates_malformed_record(tmp_path: Path) -> None:
    """One malformed run record must not abort collection of the rest (m-1)."""
    conn = open_db(str(tmp_path / "g"))
    try:
        fetch = make_fetcher([
            ("/api/pipelines", []),
            ("/api/runs?limit=200", [
                {"id": "not-an-int"},  # malformed -> should be skipped
                {"id": 1, "pipeline_id": 0, "status": "success", "trigger": "push",
                 "source_ref": "", "started_at": "s", "finished_at": "f", "created_at": "c"},
            ]),
        ])
        n = collectors.collect_runs(conn, "http://localhost:8080", "ci", fetcher=fetch)
        assert n == 1  # only the good record was ingested
        assert count_nodes(conn, "Run") == 1
    finally:
        conn.close()
