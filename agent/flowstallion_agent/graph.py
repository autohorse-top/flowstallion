"""Kuzu graph store for FlowStallion — schema bootstrap and idempotent upserts.

Layout (8 node tables, 9 relation tables):

    Commit --HAS_PARENT--> Commit
    Run --RUN_OF--> Pipeline
    Run --RUN_STEP--> Step
    Step --STEP_USES_IMAGE--> Image
    Run --RUN_TRIGGERED_BY--> Commit
    Release --RELEASE_DEPLOYS(role)--> Image
    Release --RELEASE_TRIGGERED_BY--> Commit
    Release --RELEASE_MANAGES--> K8sObject
    Release --RELEASE_EVENT--> Event

Every key is a STRING primary key chosen by the caller (e.g. commit SHA,
run id, "origin/name").  All writes are MERGE-based, so repeated ingestion
of the same object is a no-op (upsert semantics).
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

import kuzu

__all__ = [
    "NODE_TABLES",
    "REL_TABLES",
    "open_db",
    "init_schema",
    "upsert_node",
    "upsert_rel",
    "count_nodes",
    "count_rels",
]

# label -> property name -> Kuzu type ("key" is always the primary key).
NODE_TABLES: dict[str, dict[str, str]] = {
    "Commit": {
        "key": "STRING",
        "subject": "STRING",
        "author": "STRING",
        "date": "STRING",
    },
    "Pipeline": {
        "key": "STRING",
        "id": "INT64",
    },
    "Run": {
        "key": "STRING",
        "id": "INT64",
        "origin": "STRING",
        "pipeline": "STRING",
        "status": "STRING",
        "trigger": "STRING",
        "source_ref": "STRING",
        "started_at": "STRING",
        "finished_at": "STRING",
    },
    "Step": {
        "key": "STRING",
        "run_key": "STRING",
        "step_id": "STRING",
        "status": "STRING",
        "image": "STRING",
    },
    "Image": {
        "key": "STRING",
    },
    "Release": {
        "key": "STRING",
        "id": "INT64",
        "origin": "STRING",
        "name": "STRING",
        "namespace": "STRING",
        "state": "STRING",
        "reason": "STRING",
        "canary_image": "STRING",
        "stable_image": "STRING",
        "source_ref": "STRING",
        "created_at": "STRING",
        "finished_at": "STRING",
    },
    "K8sObject": {
        "key": "STRING",
        "kind": "STRING",
        "namespace": "STRING",
        "name": "STRING",
        "role": "STRING",
    },
    "Event": {
        "key": "STRING",
        "release_key": "STRING",
        "ts": "STRING",
        "state": "STRING",
        "detail": "STRING",
    },
}

# rel table -> (from_label, to_label, {property: type}).
REL_TABLES: dict[str, tuple[str, str, dict[str, str]]] = {
    "HAS_PARENT": ("Commit", "Commit", {}),
    "RUN_OF": ("Run", "Pipeline", {}),
    "RUN_STEP": ("Run", "Step", {}),
    "STEP_USES_IMAGE": ("Step", "Image", {}),
    "RUN_TRIGGERED_BY": ("Run", "Commit", {}),
    "RELEASE_DEPLOYS": ("Release", "Image", {"role": "STRING"}),
    "RELEASE_TRIGGERED_BY": ("Release", "Commit", {}),
    "RELEASE_MANAGES": ("Release", "K8sObject", {}),
    "RELEASE_EVENT": ("Release", "Event", {}),
}


def open_db(path: str) -> kuzu.Connection:
    """Open (creating parent dir as needed) the Kuzu database at *path*.

    The schema is (re)applied via :func:`init_schema`, so this is safe to
    call on both fresh and existing databases.  Returns a ready-to-use
    connection; close it when done.
    """
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    db = kuzu.Database(path)
    conn = kuzu.Connection(db)
    init_schema(conn)
    return conn


def init_schema(conn: kuzu.Connection) -> None:
    """Create all node and relation tables if they do not exist yet."""
    for label, props in NODE_TABLES.items():
        cols = ", ".join(
            f"{name} {typ} PRIMARY KEY" if name == "key" else f"{name} {typ}"
            for name, typ in props.items()
        )
        conn.execute(f"CREATE NODE TABLE IF NOT EXISTS {label}({cols})")
    for rel, (from_label, to_label, props) in REL_TABLES.items():
        stmt = f"CREATE REL TABLE IF NOT EXISTS {rel}( FROM {from_label} TO {to_label}"
        if props:
            stmt += ", " + ", ".join(f"{name} {typ}" for name, typ in props.items()) + " "
        conn.execute(stmt + ")")


def _check_prop(table: str, name: str, value: Any, ctype: str) -> None:
    where = f"{table}.{name}"
    if ctype == "STRING":
        if not isinstance(value, str):
            raise ValueError(f"{where}: expected STRING, got {type(value).__name__}")
    elif ctype == "INT64":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{where}: expected INT64, got {type(value).__name__}")
    else:  # pragma: no cover - schema is internal
        raise ValueError(f"{where}: unsupported column type {ctype!r}")


def _check_key(key: Any, table: str) -> None:
    if not isinstance(key, str) or not key:
        raise ValueError(f"{table}.key must be a non-empty string, got {key!r}")


def upsert_node(conn: kuzu.Connection, label: str, key: str, **props: Any) -> None:
    """Insert or update a node of *label* by its string *key*.

    Existing nodes are updated with the given properties (MERGE + SET);
    unknown labels/properties or type mismatches raise ``ValueError``
    before anything is executed.
    """
    schema = NODE_TABLES.get(label)
    if schema is None:
        raise ValueError(f"unknown node label {label!r} (allowed: {sorted(NODE_TABLES)})")
    _check_key(key, label)
    if "key" in props:
        raise ValueError("pass the key via the key argument, not as a property")
    for name, value in props.items():
        if name not in schema:
            raise ValueError(f"unknown property {name!r} for {label} (allowed: {sorted(schema)})")
        _check_prop(label, name, value, schema[name])
    cypher = f"MERGE (n:{label} {{key: $key}})"
    if props:
        cypher += " SET " + ", ".join(f"n.{name} = ${name}" for name in props)
    conn.execute(cypher, {"key": key, **props})


def upsert_rel(
    conn: kuzu.Connection,
    rel_table: str,
    from_label: str,
    from_key: str,
    to_label: str,
    to_key: str,
    **props: Any,
) -> None:
    """Insert or update a relation of *rel_table* between two existing nodes.

    Both endpoints must already exist (upsert the nodes first); the call is
    a documented no-op if either endpoint is missing.  Relation properties
    declared in the schema (e.g. ``RELEASE_DEPLOYS.role``) must all be
    supplied.  Wrong table names, wrong endpoint labels, or type mismatches
    raise ``ValueError``.
    """
    entry = REL_TABLES.get(rel_table)
    if entry is None:
        raise ValueError(f"unknown relation table {rel_table!r} (allowed: {sorted(REL_TABLES)})")
    from_declared, to_declared, rel_props = entry
    if from_label != from_declared or to_label != to_declared:
        raise ValueError(
            f"relation {rel_table} must be {from_declared} -> {to_declared}, "
            f"got {from_label} -> {to_label}"
        )
    _check_key(from_key, from_label)
    _check_key(to_key, to_label)
    for name in rel_props:
        if name not in props:
            raise ValueError(f"relation {rel_table} requires property {name!r}")
    for name, value in props.items():
        if name not in rel_props:
            raise ValueError(f"unknown property {name!r} for {rel_table} (allowed: {sorted(rel_props)})")
        _check_prop(rel_table, name, value, rel_props[name])
    match = (
        f"MATCH (a:{from_label} {{key: $from_key}}), (b:{to_label} {{key: $to_key}}) "
    )
    merge = f"MERGE (a)-[r:{rel_table}"
    if props:
        merge += " {" + ", ".join(f"{name}: ${name}" for name in props) + "}"
    merge += "]->(b)"
    conn.execute(match + merge, {"from_key": from_key, "to_key": to_key, **props})


def count_nodes(conn: kuzu.Connection, label: str) -> int:
    """Return the number of nodes of *label* (0 if the label is empty)."""
    if label not in NODE_TABLES:
        raise ValueError(f"unknown node label {label!r} (allowed: {sorted(NODE_TABLES)})")
    result: Any = conn.execute(f"MATCH (n:{label}) RETURN count(n)")
    rows = result.get_all()
    return int(rows[0][0]) if rows else 0


def count_rels(conn: kuzu.Connection, rel_table: str) -> int:
    """Return the number of relations in *rel_table* (0 if none exist)."""
    if rel_table not in REL_TABLES:
        raise ValueError(f"unknown relation table {rel_table!r} (allowed: {sorted(REL_TABLES)})")
    result: Any = conn.execute(f"MATCH ()-[r:{rel_table}]->() RETURN count(r)")
    rows = result.get_all()
    return int(rows[0][0]) if rows else 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: open a graph and inspect node/relation counts."""
    parser = argparse.ArgumentParser(
        prog="flowstallion-agent-graph",
        description="Open (and initialise) a FlowStallion Kuzu graph and report counts.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_open = sub.add_parser("open", help="open/create the graph and print all counts")
    p_open.add_argument("path", help="Kuzu database path")

    p_count = sub.add_parser("count", help="print the count of one node or relation table")
    p_count.add_argument("path", help="Kuzu database path")
    p_count.add_argument("kind", choices=["node", "rel"])
    p_count.add_argument("name", help="table name")

    args = parser.parse_args(argv)
    conn = open_db(args.path)
    try:
        if args.cmd == "open":
            total = 0
            for label in NODE_TABLES:
                n = count_nodes(conn, label)
                total += n
                print(f"node {label}: {n}")
            for rel in REL_TABLES:
                n = count_rels(conn, rel)
                total += n
                print(f"rel  {rel}: {n}")
            print(f"total: {total}")
        else:
            n = count_nodes(conn, args.name) if args.kind == "node" else count_rels(conn, args.name)
            print(f"{args.kind} {args.name}: {n}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
