"""RCA (root-cause analysis) over the FlowStallion Kuzu graph.

Given an incident id (a CD release id or a CI run id), walk the graph and
assemble a structured root-cause report:

* Release incident: state/reason, event timeline, deployed images (with
  roles), managed K8s objects, source commit, parent commit chain (bounded
  depth), and sibling releases / runs triggered by the same source ref.
* Run incident: status, steps (failed first), pipeline, source commit,
  parent chain, sibling releases / runs on the same source ref.

Kuzu notes (v0.11.3): ``execute()`` returns a ``QueryResult`` whose
``get_all()`` yields rows of plain dicts for node RETURNs; inequality is
``<>`` (no ``!=``); undirected incoming-edge patterns are not supported, so
siblings are resolved by ``source_ref`` equality.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import kuzu

from flowstallion_agent.graph import open_db

__all__ = ["DEFAULT_DEPTH", "RCAError", "format_report", "main", "rca"]

DEFAULT_DEPTH = 5


class RCAError(Exception):
    """Raised when an incident id cannot be resolved in the graph."""


# ---------------------------------------------------------------------------
# query helpers
# ---------------------------------------------------------------------------


def _rows(conn: kuzu.Connection, cypher: str, params: dict[str, Any] | None = None) -> list[Any]:
    """Execute *cypher* and return the raw row list (kuzu types execute() as a union)."""
    result: Any = conn.execute(cypher, params)
    return list(result.get_all())


def _node(row: Any) -> dict[str, Any]:
    """Normalize a returned node (dict with _id/_label internals) to clean properties."""
    d = dict(row)
    return {k: v for k, v in d.items() if not k.startswith("_")}


def _find_by_id(conn: kuzu.Connection, label: str, incident_id: int) -> dict[str, Any] | None:
    rows = _rows(conn, f"MATCH (n:{label}) WHERE n.id = $id RETURN n", {"id": incident_id})
    if not rows:
        return None
    return _node(rows[0][0])


def _events_for_release(conn: kuzu.Connection, release_key: str) -> list[dict[str, Any]]:
    rows = _rows(
        conn,
        "MATCH (r:Release {key: $k})-[e:RELEASE_EVENT]->(ev:Event) RETURN ev",
        {"k": release_key},
    )
    events = [_node(r[0]) for r in rows]
    # ts alone is not a total order (events can share a timestamp); fall back
    # to the stable event key so output order is deterministic.
    events.sort(key=lambda e: (str(e.get("ts", "")), str(e.get("key", ""))))
    return events


def _images_for_release(conn: kuzu.Connection, release_key: str) -> list[dict[str, Any]]:
    rows = _rows(
        conn,
        "MATCH (r:Release {key: $k})-[d:RELEASE_DEPLOYS]->(i:Image) RETURN i, d.role",
        {"k": release_key},
    )
    out = []
    for img, role in rows:
        item = _node(img)
        item["role"] = role
        out.append(item)
    return out


def _k8s_objects(conn: kuzu.Connection, release_key: str) -> list[dict[str, Any]]:
    rows = _rows(
        conn,
        "MATCH (r:Release {key: $k})-[m:RELEASE_MANAGES]->(o:K8sObject) RETURN o",
        {"k": release_key},
    )
    return [_node(r[0]) for r in rows]


def _steps_for_run(conn: kuzu.Connection, run_key: str) -> list[dict[str, Any]]:
    rows = _rows(
        conn,
        "MATCH (n:Run {key: $k})-[s:RUN_STEP]->(st:Step) RETURN st",
        {"k": run_key},
    )
    steps = [_node(r[0]) for r in rows]
    # failed steps first, then deterministic order by step_id
    steps.sort(key=lambda s: (0 if s.get("status") == "failed" else 1, s.get("step_id", "")))
    return steps


def _source_commit(conn: kuzu.Connection, rel_table: str, incident_key: str) -> dict[str, Any] | None:
    rel = "RELEASE_TRIGGERED_BY" if rel_table == "Release" else "RUN_TRIGGERED_BY"
    rows = _rows(
        conn,
        f"MATCH (n:{rel_table} {{key: $k}})-[:{rel}]->(c:Commit) RETURN c",
        {"k": incident_key},
    )
    if not rows:
        return None
    return _node(rows[0][0])


def _parent_chain(conn: kuzu.Connection, start: dict[str, Any], depth: int) -> list[dict[str, Any]]:
    """*start* commit first, then up to *depth* ancestors following HAS_PARENT.

    Merge commits have several HAS_PARENT edges; this v1 walker follows the
    first parent returned by the graph (arbitrary among the parents). Full
    merge topology is out of scope for P4.
    """
    chain: list[dict[str, Any]] = [start]
    seen = {start.get("key")}
    current = start
    for _ in range(depth):
        key = current.get("key")
        if not key:
            break
        rows = _rows(
            conn,
            "MATCH (c:Commit {key: $k})-[:HAS_PARENT]->(p:Commit) RETURN p",
            {"k": key},
        )
        if not rows:
            break
        parent = _node(rows[0][0])
        if parent.get("key") in seen:  # loop guard
            break
        chain.append(parent)
        seen.add(parent.get("key"))
        current = parent
    return chain


def _siblings(
    conn: kuzu.Connection, label: str, incident_key: str, source_ref: str
) -> list[dict[str, Any]]:
    """Other *label* nodes sharing the same source_ref (undirected-edge patterns unsupported in kuzu)."""
    rows = _rows(
        conn,
        f"MATCH (o:{label}) WHERE o.source_ref = $ref AND o.key <> $k RETURN o",
        {"ref": source_ref, "k": incident_key},
    )
    return [_node(r[0]) for r in rows]


# ---------------------------------------------------------------------------
# core
# ---------------------------------------------------------------------------


def rca(conn: kuzu.Connection, incident_id: int, kind: str = "auto", depth: int = DEFAULT_DEPTH) -> dict[str, Any]:
    """Resolve *incident_id* as a Release (or Run) and assemble the RCA dict.

    kind: "release" | "run" | "auto". With "auto" an id that matches both a
    Release and a Run raises RCAError (CI run ids and CD release ids are
    independent sequences; disambiguate with an explicit kind).
    Raises RCAError when no matching incident exists.
    """
    if depth < 1:
        depth = 1

    release = _find_by_id(conn, "Release", incident_id) if kind in ("auto", "release") else None
    run = _find_by_id(conn, "Run", incident_id) if kind in ("auto", "run") else None

    if release is not None and run is not None and kind == "auto":
        raise RCAError(
            f"id {incident_id} matches both a Release and a Run; "
            "disambiguate with kind='release' or kind='run'"
        )

    if release is not None:
        key = release.get("key", "")
        source_ref = str(release.get("source_ref", "") or "")
        source = _source_commit(conn, "Release", key)
        out: dict[str, Any] = {
            "kind": "release",
            "incident_key": key,
            "summary": release,
            "events": _events_for_release(conn, key),
            "images": _images_for_release(conn, key),
            "k8s_objects": _k8s_objects(conn, key),
            "source_commit": source,
            "parent_chain": _parent_chain(conn, source, depth) if source else [],
            "sibling_releases": _siblings(conn, "Release", key, source_ref) if source_ref else [],
            "sibling_runs": _siblings(conn, "Run", key, source_ref) if source_ref else [],
        }
        return out

    if run is not None:
        key = run.get("key", "")
        source_ref = str(run.get("source_ref", "") or "")
        source = _source_commit(conn, "Run", key)
        pipeline_rows = _rows(
            conn, "MATCH (n:Run {key: $k})-[p:RUN_OF]->(pl:Pipeline) RETURN pl", {"k": key}
        )
        pipeline = _node(pipeline_rows[0][0]) if pipeline_rows else None
        return {
            "kind": "run",
            "incident_key": key,
            "summary": run,
            "pipeline": pipeline,
            "steps": _steps_for_run(conn, key),
            "source_commit": source,
            "parent_chain": _parent_chain(conn, source, depth) if source else [],
            "sibling_releases": _siblings(conn, "Release", key, source_ref) if source_ref else [],
            "sibling_runs": _siblings(conn, "Run", key, source_ref) if source_ref else [],
        }

    scope = kind if kind in ("release", "run") else "release or run"
    raise RCAError(f"no incident of type {scope} with id {incident_id} in the graph")


# ---------------------------------------------------------------------------
# human-readable report
# ---------------------------------------------------------------------------


def _commit_line(c: dict[str, Any]) -> str:
    sha = str(c.get("key", ""))[:12]
    return f"{sha}  {c.get('subject', '')} ({c.get('author', '')} @ {c.get('date', '')})"


def _brief(node: dict[str, Any]) -> str:
    key = str(node.get("key", ""))
    if key.startswith("rel:"):
        return f"{key} ({node.get('name', '')}, {node.get('state', '')})"
    if key.startswith("run:"):
        return f"{key} ({node.get('pipeline', '')}, {node.get('status', '')})"
    return key


def format_report(data: dict[str, Any]) -> str:
    lines: list[str] = []
    kind = data.get("kind")
    summary = data.get("summary", {})

    if kind == "release":
        name = summary.get("name", "")
        ns = summary.get("namespace", "")
        lines.append(f"=== RCA: Release {data.get('incident_key', '')} ({name} @ {ns}) ===")
        lines.append(f"state: {summary.get('state', '')}")
        if summary.get("reason"):
            lines.append(f"reason: {summary.get('reason')}")
        if summary.get("created_at") or summary.get("finished_at"):
            lines.append(f"window: {summary.get('created_at', '?')} .. {summary.get('finished_at', '?')}")
        events = data.get("events") or []
        if events:
            lines.append("")
            lines.append("Timeline:")
            for ev in events:
                lines.append(f"  - {ev.get('ts', '')}  {str(ev.get('state', ''))[:12]:<12} {ev.get('detail', '')}")
        images = data.get("images") or []
        if images:
            lines.append("")
            lines.append("Images:")
            for img in images:
                lines.append(f"  - {img.get('role', '')}: {img.get('key', '')}")
        k8s = data.get("k8s_objects") or []
        if k8s:
            lines.append("")
            lines.append("K8s objects:")
            for o in k8s:
                lines.append(f"  - {o.get('kind', '')} {o.get('namespace', '')}/{o.get('name', '')} ({o.get('role', '')})")
    else:
        status = summary.get("status", "")
        lines.append(f"=== RCA: Run {data.get('incident_key', '')} (pipeline {summary.get('pipeline', '')}) ===")
        lines.append(f"status: {status}")
        lines.append(f"trigger: {summary.get('trigger', '')}")
        if summary.get("started_at") or summary.get("finished_at"):
            lines.append(f"window: {summary.get('started_at', '?')} .. {summary.get('finished_at', '?')}")
        steps = data.get("steps") or []
        if steps:
            lines.append("")
            lines.append("Steps (failed first):")
            for s in steps:
                lines.append(f"  - {s.get('step_id', '')}  {s.get('status', '')}  image={s.get('image', '')}")

    src = data.get("source_commit")
    if src:
        lines.append("")
        lines.append(f"Source commit: {_commit_line(src)}")
    chain = data.get("parent_chain") or []
    if len(chain) > 1:
        lines.append(f"Parent chain ({len(chain) - 1} more):")
        for c in chain[1:]:
            lines.append(f"  <- {_commit_line(c)}")

    sibs_r = data.get("sibling_releases") or []
    sibs_n = data.get("sibling_runs") or []
    if sibs_r or sibs_n:
        lines.append("")
        lines.append("Also on this source ref:")
        if sibs_r:
            for r in sibs_r:
                lines.append(f"  release: {_brief(r)}")
        if sibs_n:
            for r in sibs_n:
                lines.append(f"  run: {_brief(r)}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="flowstallion-agent-rca",
        description="Root-cause analysis over the FlowStallion Kuzu graph.",
    )
    parser.add_argument("incident_id", type=int, help="release id or run id")
    parser.add_argument("--db", required=True, help="Kuzu database path")
    parser.add_argument("--kind", choices=["release", "run", "auto"], default="auto")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help="max parent-chain depth (default 5)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a text report")
    args = parser.parse_args(argv)

    conn = open_db(args.db)
    try:
        data = rca(conn, args.incident_id, kind=args.kind, depth=args.depth)
    except RCAError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    finally:
        conn.close()

    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
    else:
        print(format_report(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
