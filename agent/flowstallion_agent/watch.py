"""RCA watch loop — poll failed runs, triage, POST analysis, archive a note.

P7⑥: the same loop now runs a second phase (``aiwire.poll_pr_runs``) that
wires terminal PR runs: PR review (kind=pr_review) + smart test selection
(kind=test_selection), stored as run-level analyses; when a GitHub token is
configured the review is also posted to GitHub.

The sidecar never blocks the core pipeline: every per-run failure is
logged and skipped, and LLM problems fall back to rule-based triage. PR
wiring additionally carries a process-wide :class:`aiwire.PollSkipState`
so permanently-doomed runs are fetched at most once and retryable
failures are backed off between polls.
"""

from __future__ import annotations

import argparse
import os
import time
from typing import Optional

from flowstallion_agent import aiwire, llm
from flowstallion_agent.repocheck import ENV_REPO_CACHE
from flowstallion_agent.client import (
    ClientError,
    RunInfo,
    RunStepInfo,
    SchedulerClient,
    server_from_env,
)
from flowstallion_agent.triage import RCA, analyze

__all__ = [
    "DEFAULT_NOTES_DIR",
    "DEFAULT_POLL_S",
    "pick_failed_step",
    "write_note",
    "poll_once",
    "run",
    "main",
]

ENV_NOTES_DIR = "FLOWSTALLION_NOTES_DIR"
ENV_POLL_S = "FLOWSTALLION_RCA_POLL_S"
ENV_REPO_ROOT = "FLOWSTALLION_REPO_ROOT"
DEFAULT_NOTES_DIR = "notes"
DEFAULT_POLL_S = 15.0
DEFAULT_REPO_ROOT = "."
RUN_LIMIT = 100
LOG_LIMIT = 500


def build_llm() -> Optional[llm.LLM]:
    """LLM client when configured; None otherwise (rule-only triage)."""
    if not llm.is_configured():
        return None
    try:
        return llm.LLM.from_env()
    except llm.LLMError:
        return None


def pick_failed_step(steps: list[RunStepInfo]) -> Optional[RunStepInfo]:
    """First failed step; None if the run has no failed step."""
    for st in steps:
        if st.status == "failed":
            return st
    return None


def write_note(notes_dir: str, run: RunInfo, step: RunStepInfo, rca: RCA) -> str:
    """Write notes/run-<id>.md; returns the file path."""
    os.makedirs(notes_dir, exist_ok=True)
    path = os.path.join(notes_dir, f"run-{run.id}.md")
    body = "\n".join(
        [
            f"# Run #{run.id} failure analysis",
            "",
            f"- Pipeline: #{run.pipeline_id}",
            f"- Failed step: {step.step_id} (image {step.image})",
            f"- Kind: {rca.kind}",
            f"- Root cause: {rca.root_cause}",
            f"- Command: {rca.command or '(none recorded)'}",
            f"- Suggested fix: {rca.suggested_fix or '(none)'}",
            "",
            "## Detail",
            rca.detail,
            "",
            "## Log excerpt",
            "```",
            rca.log_excerpt or "(no logs)",
            "```",
            "",
        ]
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return path


def _poll_s_from_env() -> float:
    raw = os.environ.get(ENV_POLL_S, "").strip()
    if not raw:
        return DEFAULT_POLL_S
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_POLL_S
    return value if value > 0 else DEFAULT_POLL_S


def poll_once(
    client: SchedulerClient,
    notes_dir: str = DEFAULT_NOTES_DIR,
    *,
    use_llm: bool = True,
) -> int:
    """One poll pass: triage newly-failed runs, return the count analyzed.

    Per-run errors are logged and skipped; the pass never raises.
    """
    llm_client = build_llm() if use_llm else None
    analyzed = 0
    try:
        runs = client.list_runs(limit=RUN_LIMIT)
    except ClientError as exc:
        print(f"[rca] list runs failed: {exc}")
        return 0
    for run in runs:
        if run.status != "failed":
            continue
        try:
            _, steps, existing = client.get_run(run.id)
        except ClientError as exc:
            print(f"[rca] skip run {run.id}: {exc}")
            continue
        if existing is not None:
            continue
        step = pick_failed_step(steps)
        if step is None:
            print(f"[rca] run {run.id} failed but has no failed step; skipping")
            continue
        try:
            logs = client.get_step_logs(run.id, step.step_id, limit=LOG_LIMIT)
        except ClientError as exc:
            print(f"[rca] skip run {run.id}: fetch logs: {exc}")
            continue
        command = "\n".join(step.commands)
        rca = analyze(logs, command, llm=llm_client, run_id=str(run.id))
        try:
            client.post_analysis(
                run.id,
                step_id=step.step_id,
                kind=rca.kind,
                root_cause=rca.root_cause,
                detail=rca.detail,
                suggested_fix=rca.suggested_fix,
                command=rca.command,
                log_excerpt=rca.log_excerpt,
            )
        except ClientError as exc:
            print(f"[rca] skip run {run.id}: post analysis: {exc}")
            continue
        try:
            path = write_note(notes_dir, run, step, rca)
        except OSError as exc:
            print(f"[rca] note write failed for run {run.id}: {exc}")
            path = ""
        analyzed += 1
        suffix = f" (note: {path})" if path else ""
        print(f"[rca] run {run.id} step {step.step_id}: {rca.kind} -> {rca.root_cause}{suffix}")
    return analyzed


def run(
    server: str,
    notes_dir: str,
    poll_s: float,
    once: bool,
    *,
    use_llm: bool = True,
    repo_root: str = DEFAULT_REPO_ROOT,
    repo_cache: str = "",
    ai_enabled: bool = True,
) -> int:
    """Watch loop; returns the process exit code (0 = clean stop)."""
    client = SchedulerClient(base_url=server)
    print(f"[rca] watching {server} (poll {poll_s:.0f}s, notes={notes_dir})")
    # Process-wide skip state for PR wiring: permanent failures are
    # remembered for the lifetime of this process; retryable failures are
    # backed off (see aiwire.PollSkipState).
    pr_skip_state = aiwire.PollSkipState()
    while True:
        try:
            analyzed = poll_once(client, notes_dir, use_llm=use_llm)
            if analyzed:
                print(f"[rca] analyzed {analyzed} new run(s)")
        except Exception as exc:  # sidecar must stay alive past surprises
            print(f"[rca] poll error: {exc}")
        if ai_enabled:
            try:
                llm_client = build_llm() if use_llm else None
                wired = aiwire.poll_pr_runs(
                    client,
                    repo_root=repo_root,
                    repo_cache=repo_cache,
                    llm_client=llm_client,
                    github_token=os.environ.get(aiwire.ENV_GITHUB_TOKEN, "").strip(),
                    github_api=os.environ.get(aiwire.ENV_GITHUB_API, "").strip(),
                    skip_state=pr_skip_state,
                )
                if wired:
                    print(f"[aiwire] wired {wired} new PR run(s)")
            except Exception as exc:  # sidecar must stay alive past surprises
                print(f"[aiwire] poll error: {exc}")
        if once:
            return 0
        time.sleep(poll_s)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="flowstallion-agent",
        description="FlowStallion AI agent - RCA watch loop",
    )
    parser.add_argument("--server", default=None, help="scheduler base URL (env FLOWSTALLION_SERVER)")
    parser.add_argument("--notes-dir", default=None, help=f"notes dir (env {ENV_NOTES_DIR}, default {DEFAULT_NOTES_DIR})")
    parser.add_argument("--poll-s", type=float, default=None, help=f"poll interval in seconds (env {ENV_POLL_S})")
    parser.add_argument("--once", action="store_true", help="run a single poll pass and exit")
    parser.add_argument("--repo-root", default=None, help=f"repo checkout dir for test selection (env {ENV_REPO_ROOT}, default .)")
    parser.add_argument("--repo-cache", default=None, help=f"PR head checkout cache dir (env {ENV_REPO_CACHE})")
    parser.add_argument("--no-ai", action="store_true", help="disable PR AI wiring (RCA only)")
    args = parser.parse_args(argv)

    server = args.server or server_from_env()
    notes_dir = (args.notes_dir or os.environ.get(ENV_NOTES_DIR, "").strip() or DEFAULT_NOTES_DIR)
    poll_s = args.poll_s if args.poll_s is not None else _poll_s_from_env()
    repo_root = args.repo_root or os.environ.get(ENV_REPO_ROOT, "").strip() or DEFAULT_REPO_ROOT
    repo_cache = args.repo_cache or os.environ.get(ENV_REPO_CACHE, "").strip()
    return run(server, notes_dir, poll_s, once=args.once, repo_root=repo_root, repo_cache=repo_cache, ai_enabled=not args.no_ai)


if __name__ == "__main__":
    raise SystemExit(main())
