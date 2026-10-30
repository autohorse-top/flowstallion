"""Tests for flowstallion_agent.graph (kuzu schema + upsert primitives)."""

from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

import kuzu
from flowstallion_agent import graph
from flowstallion_agent.graph import (
    NODE_TABLES,
    REL_TABLES,
    count_nodes,
    count_rels,
    init_schema,
    open_db,
    upsert_node,
    upsert_rel,
)


def qall(conn: kuzu.Connection, cypher: str) -> list[Any]:
    """Run a query and return all rows (kuzu types execute() as a union)."""
    result: Any = conn.execute(cypher)
    return list(result.get_all())


@pytest.fixture()
def conn(tmp_path: Path) -> Generator[kuzu.Connection, None, None]:
    c = open_db(str(tmp_path / "nested" / "dir" / "flowstallion"))
    yield c
    c.close()


def assert_all_tables_empty(c: kuzu.Connection) -> None:
    for label in NODE_TABLES:
        assert count_nodes(c, label) == 0, label
    for rel in REL_TABLES:
        assert count_rels(c, rel) == 0, rel


def test_open_db_creates_parent_dir_and_all_tables(conn: kuzu.Connection) -> None:
    assert_all_tables_empty(conn)
    assert len(NODE_TABLES) == 8
    assert len(REL_TABLES) == 9


def test_init_schema_is_idempotent(conn: kuzu.Connection) -> None:
    init_schema(conn)
    init_schema(conn)
    init_schema(conn)
    assert_all_tables_empty(conn)


def test_upsert_node_insert_then_update(conn: kuzu.Connection) -> None:
    upsert_node(conn, "Commit", "abc123", subject="first", author="x", date="2026-01-01")
    rows = qall(conn, "MATCH (c:Commit) RETURN c.key, c.subject, c.author, c.date")
    assert rows == [["abc123", "first", "x", "2026-01-01"]]

    upsert_node(conn, "Commit", "abc123", subject="rebased")
    rows = qall(conn, "MATCH (c:Commit) RETURN c.subject, c.author")
    assert rows == [["rebased", "x"]]
    assert count_nodes(conn, "Commit") == 1


def test_upsert_node_key_only_is_idempotent(conn: kuzu.Connection) -> None:
    upsert_node(conn, "Image", "sha256:deadbeef")
    upsert_node(conn, "Image", "sha256:deadbeef")
    assert count_nodes(conn, "Image") == 1


def test_upsert_node_int64_property(conn: kuzu.Connection) -> None:
    upsert_node(conn, "Pipeline", "origin/repo/main", id=42)
    rows = qall(conn, "MATCH (p:Pipeline) RETURN p.id")
    assert rows == [[42]]


def test_upsert_node_validation_errors(conn: kuzu.Connection) -> None:
    with pytest.raises(ValueError, match="unknown node label"):
        upsert_node(conn, "Bogus", "k")
    with pytest.raises(ValueError, match="non-empty string"):
        upsert_node(conn, "Commit", "")
    with pytest.raises(ValueError, match="non-empty string"):
        upsert_node(conn, "Commit", 123)  # type: ignore[arg-type]
    # "key" is a formal parameter, so the binding itself rejects the duplicate
    with pytest.raises(TypeError, match="multiple values for argument 'key'"):
        upsert_node(conn, "Commit", "k", key="other")  # type: ignore[misc]
    with pytest.raises(ValueError, match="unknown property"):
        upsert_node(conn, "Commit", "k", nothere="v")
    with pytest.raises(ValueError, match="expected INT64"):
        upsert_node(conn, "Pipeline", "k", id="42")
    with pytest.raises(ValueError, match="expected STRING"):
        upsert_node(conn, "Commit", "k", subject=42)
    with pytest.raises(ValueError, match="expected INT64"):
        upsert_node(conn, "Pipeline", "k", id=True)


def test_upsert_rel_idempotent(conn: kuzu.Connection) -> None:
    upsert_node(conn, "Run", "r1", id=1)
    upsert_node(conn, "Step", "s1", run_key="r1", step_id="build")
    upsert_rel(conn, "RUN_STEP", "Run", "r1", "Step", "s1")
    upsert_rel(conn, "RUN_STEP", "Run", "r1", "Step", "s1")
    assert count_rels(conn, "RUN_STEP") == 1


def test_upsert_rel_property_distinguishes_edges(conn: kuzu.Connection) -> None:
    upsert_node(conn, "Release", "rel1", id=1, name="v1")
    upsert_node(conn, "Image", "img-canary")
    upsert_node(conn, "Image", "img-stable")
    upsert_rel(conn, "RELEASE_DEPLOYS", "Release", "rel1", "Image", "img-canary", role="canary")
    upsert_rel(conn, "RELEASE_DEPLOYS", "Release", "rel1", "Image", "img-canary", role="canary")
    upsert_rel(conn, "RELEASE_DEPLOYS", "Release", "rel1", "Image", "img-stable", role="stable")
    assert count_rels(conn, "RELEASE_DEPLOYS") == 2


def test_upsert_rel_validation_errors(conn: kuzu.Connection) -> None:
    upsert_node(conn, "Release", "rel1", id=1)
    upsert_node(conn, "Image", "img1")
    with pytest.raises(ValueError, match="unknown relation table"):
        upsert_rel(conn, "BOGUS", "Release", "rel1", "Image", "img1")
    with pytest.raises(ValueError, match="must be Release -> Image"):
        upsert_rel(conn, "RELEASE_DEPLOYS", "Commit", "rel1", "Image", "img1")
    with pytest.raises(ValueError, match="must be Release -> Image"):
        upsert_rel(conn, "RELEASE_DEPLOYS", "Release", "rel1", "Commit", "img1")
    with pytest.raises(ValueError, match="requires property"):
        upsert_rel(conn, "RELEASE_DEPLOYS", "Release", "rel1", "Image", "img1")
    with pytest.raises(ValueError, match="unknown property"):
        upsert_rel(conn, "RELEASE_DEPLOYS", "Release", "rel1", "Image", "img1", role="canary", extra=1)
    with pytest.raises(ValueError, match="expected STRING"):
        upsert_rel(conn, "RELEASE_DEPLOYS", "Release", "rel1", "Image", "img1", role=7)
    with pytest.raises(ValueError, match="non-empty string"):
        upsert_rel(conn, "RUN_STEP", "Run", "", "Step", "s1")


def test_upsert_rel_noop_when_endpoint_missing(conn: kuzu.Connection) -> None:
    upsert_node(conn, "Run", "r1", id=1)
    upsert_rel(conn, "RUN_STEP", "Run", "r1", "Step", "ghost-step")
    assert count_rels(conn, "RUN_STEP") == 0


def test_count_functions_reject_unknown_names(conn: kuzu.Connection) -> None:
    with pytest.raises(ValueError, match="unknown node label"):
        count_nodes(conn, "Bogus")
    with pytest.raises(ValueError, match="unknown relation table"):
        count_rels(conn, "BOGUS")


def test_full_ingestion_scenario(conn: kuzu.Connection) -> None:
    # commit -> run -> step -> image
    upsert_node(conn, "Commit", "sha1", subject="feat: x", author="dev", date="2026-01-01")
    upsert_node(conn, "Commit", "sha0", subject="base", author="dev", date="2025-12-31")
    upsert_rel(conn, "HAS_PARENT", "Commit", "sha1", "Commit", "sha0")

    upsert_node(conn, "Pipeline", "origin/repo/main", id=7)
    upsert_node(conn, "Run", "run-9", id=9, origin="o", pipeline="origin/repo/main",
                status="failed", trigger="push", source_ref="main",
                started_at="2026-01-02T00:00:00Z", finished_at="2026-01-02T00:05:00Z")
    upsert_rel(conn, "RUN_OF", "Run", "run-9", "Pipeline", "origin/repo/main")
    upsert_rel(conn, "RUN_TRIGGERED_BY", "Run", "run-9", "Commit", "sha1")

    upsert_node(conn, "Step", "step-9-0", run_key="run-9", step_id="test", status="failed", image="img-a")
    upsert_rel(conn, "RUN_STEP", "Run", "run-9", "Step", "step-9-0")
    upsert_node(conn, "Image", "img-a")
    upsert_rel(conn, "STEP_USES_IMAGE", "Step", "step-9-0", "Image", "img-a")

    # release side
    upsert_node(conn, "Release", "rel-3", id=3, origin="o", name="v1", namespace="prod",
                state="failed", reason="canary checks failed",
                canary_image="img-a", stable_image="img-b", source_ref="main",
                created_at="2026-01-03T00:00:00Z", finished_at="2026-01-03T01:00:00Z")
    upsert_node(conn, "Image", "img-b")
    upsert_rel(conn, "RELEASE_DEPLOYS", "Release", "rel-3", "Image", "img-a", role="canary")
    upsert_rel(conn, "RELEASE_DEPLOYS", "Release", "rel-3", "Image", "img-b", role="stable")
    upsert_rel(conn, "RELEASE_TRIGGERED_BY", "Release", "rel-3", "Commit", "sha1")
    upsert_node(conn, "K8sObject", "deploy/prod/app", kind="Deployment", namespace="prod",
                name="app", role="canary")
    upsert_rel(conn, "RELEASE_MANAGES", "Release", "rel-3", "K8sObject", "deploy/prod/app")
    upsert_node(conn, "Event", "ev-1", release_key="rel-3", ts="2026-01-03T00:10:00Z",
                state="canary", detail="50% traffic")
    upsert_rel(conn, "RELEASE_EVENT", "Release", "rel-3", "Event", "ev-1")

    # re-ingest the whole batch (idempotence)
    upsert_node(conn, "Run", "run-9", id=9, origin="o", pipeline="origin/repo/main",
                status="failed", trigger="push", source_ref="main",
                started_at="2026-01-02T00:00:00Z", finished_at="2026-01-02T00:05:00Z")
    upsert_rel(conn, "RUN_OF", "Run", "run-9", "Pipeline", "origin/repo/main")

    assert count_nodes(conn, "Commit") == 2
    assert count_nodes(conn, "Pipeline") == 1
    assert count_nodes(conn, "Run") == 1
    assert count_nodes(conn, "Step") == 1
    assert count_nodes(conn, "Image") == 2
    assert count_nodes(conn, "Release") == 1
    assert count_nodes(conn, "K8sObject") == 1
    assert count_nodes(conn, "Event") == 1
    assert count_rels(conn, "HAS_PARENT") == 1
    assert count_rels(conn, "RUN_OF") == 1
    assert count_rels(conn, "RUN_STEP") == 1
    assert count_rels(conn, "STEP_USES_IMAGE") == 1
    assert count_rels(conn, "RUN_TRIGGERED_BY") == 1
    assert count_rels(conn, "RELEASE_DEPLOYS") == 2
    assert count_rels(conn, "RELEASE_TRIGGERED_BY") == 1
    assert count_rels(conn, "RELEASE_MANAGES") == 1
    assert count_rels(conn, "RELEASE_EVENT") == 1
