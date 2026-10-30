"""Collectors: ingest git history, CI runs and canary releases into the Kuzu graph.

Data sources (all read-only):
  * local git repository -> Commit nodes + HAS_PARENT edges
  * CI scheduler REST    -> Pipeline/Run/Step nodes (P1 build events)
  * CD scheduler REST    -> Release/Event/K8sObject nodes (P3 deploy events)

Every write goes through graph.upsert_node / graph.upsert_rel (MERGE-based),
so re-running a collector against the same database is idempotent.

Known v1 gaps (documented, not silently faked):
  * run.source_ref / release.source_ref are only linked to a Commit node when
    the ref is a full 40-hex SHA that already exists in the graph (i.e. the
    git collector has run first).  Branch names are kept as attributes but not
    resolved to commits here (collectors are repo-agnostic by design).
  * steps store the *execution* image (container the step ran in), not a
    "built image" relation; P1 does not record build artifacts.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from flowstallion_agent.graph import count_nodes, open_db, upsert_node, upsert_rel

__all__ = [
    "build_sample_data",
    "collect_canaries",
    "collect_git",
    "collect_runs",
    "k8s_objects_for_release",
]

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")

Fetch = Callable[[str], tuple[int, bytes]]


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _default_fetch(url: str) -> tuple[int, bytes]:
    """urllib GET returning (status, body). 404 is a normal answer, not an error."""
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return int(resp.status), resp.read()
    except urllib.error.HTTPError as e:
        return int(e.code), e.read()
    except urllib.error.URLError as e:
        raise RuntimeError(f"cannot fetch {url}: {e.reason}") from e


def _get_json(fetch: Fetch, url: str) -> Any:
    """GET *url* as JSON. 404 -> None; non-2xx / bad JSON -> RuntimeError."""
    code, body = fetch(url)
    if code == 404:
        return None
    if code < 200 or code >= 300:
        raise RuntimeError(f"GET {url} -> HTTP {code}: {body[:200]!r}")
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"GET {url} -> invalid JSON: {e}; body[:200]={body[:200]!r}") from e


def _commit_exists(conn: Any, sha: str) -> bool:
    rows = conn.execute("MATCH (c:Commit {key: $k}) RETURN c.key", {"k": sha}).get_all()
    return bool(rows)


# ---------------------------------------------------------------------------
# collectors
# ---------------------------------------------------------------------------


def collect_git(conn: Any, repo_path: str) -> int:
    """Ingest the full history (all refs) of *repo_path* as Commit nodes."""
    try:
        proc = subprocess.run(
            ["git", "log", "--all", "--format=%H%x00%P%x00%an%x00%aI%x00%s"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
        detail = ""
        if isinstance(e, subprocess.CalledProcessError) and e.stderr:
            detail = e.stderr.strip()[:200]
        raise RuntimeError(f"git log failed in {repo_path!r}: {detail or e}") from e
    commits: list[tuple[str, list[str], str, str, str]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\x00")
        if len(parts) < 5:
            continue
        sha, parents, author, date, subject = (
            parts[0],
            parts[1].split(),
            parts[2],
            parts[3],
            parts[4],
        )
        commits.append((sha, parents, author, date, subject))
    for sha, _parents, author, date, subject in commits:
        upsert_node(conn, "Commit", sha, subject=subject, author=author, date=date)
    for sha, parents, _author, _date, _subject in commits:
        for parent in parents:
            upsert_rel(conn, "HAS_PARENT", "Commit", sha, "Commit", parent)
    return len(commits)


def collect_runs(conn: Any, base_url: str, origin: str, fetcher: Fetch | None = None) -> int:
    """Ingest pipelines, runs and steps from a CI scheduler REST API."""
    f = fetcher or _default_fetch
    base = base_url.rstrip("/")
    pipelines = _get_json(f, f"{base}/api/pipelines") or []
    pname: dict[str, str] = {}
    for p in pipelines:
        name = str(p.get("name", ""))
        pid = str(p.get("id", ""))
        if name and pid:
            pname[pid] = name
            upsert_node(conn, "Pipeline", name, id=int(pid))

    runs = _get_json(f, f"{base}/api/runs?limit=200") or []
    count = 0
    for r in runs:
        try:
            rid = int(r.get("id", 0))
            run_key = f"run:{origin}:{rid}"
            pid = str(r.get("pipeline_id", ""))
            pipeline_name = pname.get(pid, pid)
            if pid.isdigit() and pipeline_name:
                upsert_node(conn, "Pipeline", pipeline_name, id=int(pid))
            source_ref = str(r.get("source_ref", "") or "")
            upsert_node(
                conn,
                "Run",
                run_key,
                id=rid,
                origin=origin,
                pipeline=pipeline_name,
                status=str(r.get("status", "")),
                trigger=str(r.get("trigger", "")),
                source_ref=source_ref,
                started_at=str(r.get("started_at", "") or ""),
                finished_at=str(r.get("finished_at", "") or ""),
            )
            if pipeline_name:
                upsert_rel(conn, "RUN_OF", "Run", run_key, "Pipeline", pipeline_name)

            detail = _get_json(f, f"{base}/api/runs/{rid}")
            if isinstance(detail, dict):
                for s in detail.get("steps") or []:
                    sid = str(s.get("step_id", "") or "")
                    if not sid:
                        continue
                    step_key = f"step:{run_key}:{sid}"
                    upsert_node(
                        conn,
                        "Step",
                        step_key,
                        run_key=run_key,
                        step_id=sid,
                        status=str(s.get("status", "") or ""),
                        image=str(s.get("image", "") or ""),
                    )
                    upsert_rel(conn, "RUN_STEP", "Run", run_key, "Step", step_key)
                    img = str(s.get("image", "") or "")
                    if img:
                        upsert_node(conn, "Image", img)
                        upsert_rel(conn, "STEP_USES_IMAGE", "Step", step_key, "Image", img)
            if SHA40_RE.match(source_ref) and _commit_exists(conn, source_ref):
                upsert_rel(conn, "RUN_TRIGGERED_BY", "Run", run_key, "Commit", source_ref)
            count += 1
        except Exception as e:
            # Isolate one bad record: a malformed run must not abort the
            # whole collection (m-1).
            print(f"warning: skipping malformed run record: {e}", file=sys.stderr)
    return count


def k8s_objects_for_release(name: str, namespace: str, state: str) -> list[tuple[str, str, str, str]]:
    """K8s objects a release manages, per P3 manifest rules.

    pending/observing: stable deployment + canary deployment + stable service.
    promoted: the canary deployment *is* the production deployment.
    """
    promoted = state == "promoted"
    stable_role = "production" if promoted else "stable_deploy"
    canary_role = "production" if promoted else "canary_deploy"
    return [
        ("deployment", namespace, name, stable_role),
        ("deployment", namespace, f"{name}-canary", canary_role),
        ("service", namespace, name, "service"),
    ]


def collect_canaries(conn: Any, base_url: str, origin: str, fetcher: Fetch | None = None) -> int:
    """Ingest canary releases (and their events) from a CD scheduler REST API."""
    f = fetcher or _default_fetch
    base = base_url.rstrip("/")
    releases = _get_json(f, f"{base}/api/canaries")
    if releases is None:
        return 0
    count = 0
    for c in releases:
        try:
            cid = int(c.get("id", 0))
            release_key = f"rel:{origin}:{cid}"
            name = str(c.get("name", "") or "")
            ns = str(c.get("namespace", "") or "")
            state = str(c.get("state", "") or "")
            canary_image = str(c.get("canary_image", "") or "")
            stable_image = str(c.get("stable_image", "") or "")
            source_ref = str(c.get("source_ref", "") or "")
            upsert_node(
                conn,
                "Release",
                release_key,
                id=cid,
                origin=origin,
                name=name,
                namespace=ns,
                state=state,
                reason=str(c.get("reason", "") or ""),
                canary_image=canary_image,
                stable_image=stable_image,
                source_ref=source_ref,
                created_at=str(c.get("created_at", "") or ""),
                finished_at=str(c.get("finished_at", "") or ""),
            )
            for img, role in ((canary_image, "canary"), (stable_image, "stable")):
                if img:
                    upsert_node(conn, "Image", img)
                    upsert_rel(conn, "RELEASE_DEPLOYS", "Release", release_key, "Image", img, role=role)
            for kind, kns, kname, role in k8s_objects_for_release(name, ns, state):
                # Per-release key: different releases managing the same live
                # object (e.g. rollback + re-release) keep separate nodes with
                # their own role, instead of overwriting each other (M-2).
                kkey = f"{release_key}/{kind}/{kns}/{kname}"
                upsert_node(conn, "K8sObject", kkey, kind=kind, namespace=kns, name=kname, role=role)
                upsert_rel(conn, "RELEASE_MANAGES", "Release", release_key, "K8sObject", kkey)
            detail = _get_json(f, f"{base}/api/canaries/{cid}")
            if isinstance(detail, dict):
                for i, ev in enumerate(detail.get("events") or []):
                    ts = str(ev.get("ts", "") or "")
                    # Stable key: prefer the API's event id (the API serves a
                    # bounded most-recent window, so position-based keys would
                    # drift as the window slides, M-3). Fall back to ts+index
                    # for fixtures without ids.
                    eid = ev.get("id")
                    if isinstance(eid, int) and not isinstance(eid, bool):
                        ekey = f"ev:{release_key}:{eid}"
                    else:
                        ekey = f"ev:{release_key}:{ts}:{i}"
                    upsert_node(
                        conn,
                        "Event",
                        ekey,
                        release_key=release_key,
                        ts=ts,
                        state=str(ev.get("state", "") or ""),
                        detail=str(ev.get("detail", "") or ""),
                    )
                    upsert_rel(conn, "RELEASE_EVENT", "Release", release_key, "Event", ekey)
            if SHA40_RE.match(source_ref) and _commit_exists(conn, source_ref):
                upsert_rel(conn, "RELEASE_TRIGGERED_BY", "Release", release_key, "Commit", source_ref)
            count += 1
        except Exception as e:
            # Isolate one bad record: a malformed release must not abort the
            # whole collection (m-1).
            print(f"warning: skipping malformed canary record: {e}", file=sys.stderr)
    return count


# ---------------------------------------------------------------------------
# deterministic sample fixture (for reproducible acceptance / tests)
# ---------------------------------------------------------------------------

_SAMPLE_COMMITS: list[tuple[str, str]] = [
    ("c1" * 20, "feat: step 1"),
    ("c2" * 20, "feat: step 2"),
    ("c3" * 20, "feat: step 3"),
    ("c4" * 20, "fix: broken change that rolls back"),
    ("c5" * 20, "feat: step 5"),
    ("c6" * 20, "feat: step 6"),
]


def build_sample_data(conn: Any) -> None:
    """Populate the graph with a small deterministic fixture.

    Layout: 6-commit chain (c1..c6, c4 is the "bad" commit), one pipeline
    "demo", 2 runs (run 1 success @ c6, run 2 failed @ c4) and 2 releases
    (release 3 rolled_back @ c4, release 4 promoted @ c6).  Ids are chosen
    so release ids (3,4) never collide with run ids (1,2).
    """
    for i, (sha, subject) in enumerate(_SAMPLE_COMMITS, start=1):
        upsert_node(conn, "Commit", sha, subject=subject, author="dev@example.com", date=f"2026-10-0{i}T00:00:00Z")
    for child, parent in zip(_SAMPLE_COMMITS[1:], _SAMPLE_COMMITS):
        upsert_rel(conn, "HAS_PARENT", "Commit", child[0], "Commit", parent[0])

    upsert_node(conn, "Pipeline", "demo", id=1)

    runs = [
        (1, "success", "c6" * 20, "2026-10-20T08:00:00Z", "2026-10-20T08:02:00Z", "build", "success"),
        (2, "failed", "c4" * 20, "2026-10-21T09:00:00Z", "2026-10-21T09:03:00Z", "test", "failed"),
    ]
    for rid, status, ref, t0, t1, sid, step_status in runs:
        run_key = f"run:sample:{rid}"
        upsert_node(
            conn, "Run", run_key,
            id=rid, origin="sample", pipeline="demo", status=status, trigger="push",
            source_ref=ref, started_at=t0, finished_at=t1,
        )
        upsert_rel(conn, "RUN_OF", "Run", run_key, "Pipeline", "demo")
        step_key = f"step:{run_key}:{sid}"
        upsert_node(conn, "Step", step_key, run_key=run_key, step_id=sid, status=step_status, image="alpine:3.20")
        upsert_rel(conn, "RUN_STEP", "Run", run_key, "Step", step_key)
        upsert_node(conn, "Image", "alpine:3.20")
        upsert_rel(conn, "STEP_USES_IMAGE", "Step", step_key, "Image", "alpine:3.20")
        upsert_rel(conn, "RUN_TRIGGERED_BY", "Run", run_key, "Commit", ref)

    releases = [
        (3, "demoapp", "rolled_back", "error rate 0.83 > threshold 0.30 (61 req, 51 err)",
         "flowstallion/demoapp:v2", "flowstallion/demoapp:v1", "c4" * 20,
         [
             ("2026-10-22T00:00:10Z", "applying", "created canary deployment demoapp-canary (image flowstallion/demoapp:v2)"),
             ("2026-10-22T00:02:00Z", "observing", "err_rate 0.000 (0 req, 0 err)"),
             ("2026-10-22T00:05:00Z", "rolled_back", "error rate 0.83 > threshold 0.30 (61 req, 51 err)"),
         ]),
        (4, "demoapp2", "promoted", "promoted: observation window complete",
         "flowstallion/demoapp2:v2", "flowstallion/demoapp2:v1", "c6" * 20,
         [
             ("2026-10-22T01:00:10Z", "applying", "created canary deployment demoapp2-canary (image flowstallion/demoapp2:v2)"),
             ("2026-10-22T01:05:00Z", "promoted", "promoted: observation window complete"),
         ]),
    ]
    for rid, name, state, reason, canary_img, stable_img, ref, events in releases:
        release_key = f"rel:sample:{rid}"
        upsert_node(
            conn, "Release", release_key,
            id=rid, origin="sample", name=name, namespace="flowstallion", state=state,
            reason=reason, canary_image=canary_img, stable_image=stable_img,
            source_ref=ref,
            created_at="2026-10-22T00:00:00Z" if rid == 3 else "2026-10-22T01:00:00Z",
            finished_at="2026-10-22T00:05:00Z" if rid == 3 else "2026-10-22T01:05:00Z",
        )
        for img, role in ((canary_img, "canary"), (stable_img, "stable")):
            upsert_node(conn, "Image", img)
            upsert_rel(conn, "RELEASE_DEPLOYS", "Release", release_key, "Image", img, role=role)
        for kind, kns, kname, role in k8s_objects_for_release(name, "flowstallion", state):
            kkey = f"{release_key}/{kind}/{kns}/{kname}"
            upsert_node(conn, "K8sObject", kkey, kind=kind, namespace=kns, name=kname, role=role)
            upsert_rel(conn, "RELEASE_MANAGES", "Release", release_key, "K8sObject", kkey)
        for i, (ts, ev_state, ev_detail) in enumerate(events):
            ekey = f"ev:{release_key}:{ts}:{i}"
            upsert_node(conn, "Event", ekey, release_key=release_key, ts=ts, state=ev_state, detail=ev_detail)
            upsert_rel(conn, "RELEASE_EVENT", "Release", release_key, "Event", ekey)
        upsert_rel(conn, "RELEASE_TRIGGERED_BY", "Release", release_key, "Commit", ref)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _origin_from_url(url: str | None) -> str:
    if not url:
        return "local"
    host = urllib.parse.urlparse(url).hostname
    return host or "local"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="flowstallion-agent-collectors",
        description="Ingest git history / CI runs / canary releases into a Kuzu graph.",
    )
    parser.add_argument("--db", required=True, help="Kuzu database path")
    parser.add_argument("--sample", action="store_true", help="build the deterministic sample fixture")
    parser.add_argument("--repo", default=None, help="git repository path to ingest")
    parser.add_argument("--runs", default=None, help="CI scheduler base URL (e.g. http://localhost:8080)")
    parser.add_argument("--canaries", default=None, help="CD scheduler base URL (e.g. http://localhost:8090)")
    parser.add_argument("--origin", default=None, help="data-source label (default: derived from URL host)")
    args = parser.parse_args(argv)

    if not (args.sample or args.repo or args.runs or args.canaries):
        parser.error("nothing to do: pass --sample, --repo, --runs and/or --canaries")

    origin = args.origin or _origin_from_url(args.runs or args.canaries)
    conn = open_db(args.db)
    try:
        if args.sample:
            build_sample_data(conn)
            print(f"sample: built fixture (Commit={count_nodes(conn, 'Commit')}, "
                  f"Run={count_nodes(conn, 'Run')}, Release={count_nodes(conn, 'Release')})")
        if args.repo:
            print(f"git: {collect_git(conn, args.repo)} commits from {args.repo}")
        if args.runs:
            print(f"runs: {collect_runs(conn, args.runs, origin)} runs from {args.runs}")
        if args.canaries:
            print(f"canaries: {collect_canaries(conn, args.canaries, origin)} releases from {args.canaries}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
