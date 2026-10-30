"""FinOps cost ledger — LLM token and cloud cost accounting.

One JSONL ledger (one :class:`CostRecord` per line) is the unit of
accounting; records are tagged ``source`` "llm" or "cloud" and carry
``pr``/``team`` labels so cost can be aggregated per PR or per team.

LLM records are opt-in and sidecar-safe: :func:`record_llm_usage` only
writes what the provider actually reported (no usage block -> no record)
and never raises, so cost bookkeeping can never block triage.

Token counting note: for reasoning models (e.g. Qwen3), thinking tokens
are billed inside ``completion_tokens`` — the ``usage`` block reported by
OpenAI-compatible gateways already includes reasoning tokens, so the
ledger overstates nothing and under-states nothing (we never try to
subtract thinking tokens out of the reported figures).

CLI (``python -m flowstallion_agent.cost``)::

    --sample --out F                    write a deterministic sample ledger
    --ledger F --by-pr [--json] [--source llm|cloud]
    --ledger F --by-team [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flowstallion_agent.llm import LLM

__all__ = [
    "ENV_LEDGER",
    "ENV_PRICE_IN",
    "ENV_PRICE_OUT",
    "DEFAULT_LEDGER",
    "PRICE_PER_MTOK",
    "CostRecord",
    "CostLedger",
    "price_cost",
    "record_llm_usage",
    "maybe_record_llm_usage",
    "aggregate",
    "cloud_cost_sample",
    "main",
]

ENV_LEDGER = "FLOWSTALLION_COST_LEDGER"
ENV_PRICE_IN = "FLOWSTALLION_LLM_PRICE_IN"
ENV_PRICE_OUT = "FLOWSTALLION_LLM_PRICE_OUT"
DEFAULT_LEDGER = "~/.flowstallion/cost-ledger.jsonl"

# Approximate list prices as of 2026-10, USD per 1M tokens, (input, output).
# Override with FLOWSTALLION_LLM_PRICE_IN/OUT (USD/1M); unknown models are
# still counted (token fields) but priced at 0.0 by design.
PRICE_PER_MTOK: dict[str, tuple[float, float]] = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-haiku": (0.25, 1.25),
}


@dataclass
class CostRecord:
    """One cost event: an LLM usage line or a cloud resource line item.

    Cloud line items fold cpu/mem charges into ``cost`` (no separate
    resource fields). ``pr``/``team`` default to "unknown" so every record
    always aggregates.
    """

    ts: str  # ISO8601 UTC
    source: str  # "llm" | "cloud"
    run_id: str | None
    pr: str = "unknown"
    team: str = "unknown"
    model: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost: float = 0.0
    namespace: str | None = None
    pod: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """All fields as a plain dict (JSON-serializable)."""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CostRecord:
        """Build a record from a dict; missing fields fall back to defaults.

        Raises:
            ValueError: when a present field has the wrong type.
        """
        if not isinstance(d, dict):
            raise ValueError(
                f"CostRecord.from_dict: expected object, got {type(d).__name__}"
            )

        def str_field(name: str, default: str) -> str:
            v = d.get(name, default)
            if not isinstance(v, str):
                raise ValueError(
                    f"CostRecord.{name}: expected str, got {type(v).__name__}"
                )
            return v

        def opt_str_field(name: str) -> str | None:
            v = d.get(name)
            if v is None:
                return None
            if not isinstance(v, str):
                raise ValueError(
                    f"CostRecord.{name}: expected str or null, got {type(v).__name__}"
                )
            return v

        def int_field(name: str, default: int) -> int:
            v = d.get(name, default)
            if isinstance(v, bool) or not isinstance(v, int):
                raise ValueError(
                    f"CostRecord.{name}: expected int, got {type(v).__name__}"
                )
            return v

        def float_field(name: str, default: float) -> float:
            v = d.get(name, default)
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError(
                    f"CostRecord.{name}: expected number, got {type(v).__name__}"
                )
            return float(v)

        return cls(
            ts=str_field("ts", ""),
            source=str_field("source", ""),
            run_id=opt_str_field("run_id"),
            pr=str_field("pr", "unknown"),
            team=str_field("team", "unknown"),
            model=opt_str_field("model"),
            prompt_tokens=int_field("prompt_tokens", 0),
            completion_tokens=int_field("completion_tokens", 0),
            total_tokens=int_field("total_tokens", 0),
            cost=float_field("cost", 0.0),
            namespace=opt_str_field("namespace"),
            pod=opt_str_field("pod"),
        )


class CostLedger:
    """Append-only JSONL cost ledger (one :class:`CostRecord` per line)."""

    def __init__(self, path: str | Path) -> None:
        # Expand "~" so env/CLI values like "~/cost.jsonl" land in the user's
        # home directory instead of a literal "./~" under the CWD.
        self._path = Path(os.path.expanduser(str(path)))

    @property
    def path(self) -> Path:
        return self._path

    def append(self, record: CostRecord) -> None:
        """Append one record as a JSON line; creates parent dirs; flushes."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict()) + "\n")
            f.flush()

    def append_many(self, records: list[CostRecord]) -> None:
        """Append several records in one open/flush."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record.to_dict()) + "\n")
            f.flush()

    def records(self) -> list[CostRecord]:
        """Read all records (strict mode).

        Empty file -> ``[]``; blank lines are skipped.

        Raises:
            ValueError: malformed JSON or a field with a wrong type,
                reported with the 1-based line number.
        """
        out: list[CostRecord] = []
        with open(self._path, "r", encoding="utf-8") as f:
            for n, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"line {n}: malformed JSON at column {exc.pos}: {exc.msg}"
                    ) from exc
                try:
                    out.append(CostRecord.from_dict(data))
                except ValueError as exc:
                    raise ValueError(f"line {n}: {exc}") from exc
        return out


_warned_env_prices: set[str] = set()


def _env_price(name: str) -> float:
    """USD per 1M tokens from env ``name``; 0.0 when unset.

    An unparseable value also yields 0.0, but a one-time stderr warning is
    printed so a typo cannot silently turn the whole ledger into "free".
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return 0.0
    try:
        return float(raw)
    except ValueError:
        if name not in _warned_env_prices:
            _warned_env_prices.add(name)
            print(
                f"[cost] {name}={raw!r} is not a number; using 0.0",
                file=sys.stderr,
            )
        return 0.0


def price_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """USD cost of one usage, from the env override or the price table.

    If ``FLOWSTALLION_LLM_PRICE_IN`` or ``FLOWSTALLION_LLM_PRICE_OUT`` is set,
    **both** prices come from the environment (an unset one counts as 0.0,
    as does an unparseable value).  Otherwise the table is consulted;
    unknown models price at 0.0 — their tokens are still counted, only the
    cost is unknown-by-convention.
    """
    if ENV_PRICE_IN in os.environ or ENV_PRICE_OUT in os.environ:
        pin, pout = _env_price(ENV_PRICE_IN), _env_price(ENV_PRICE_OUT)
    else:
        pin, pout = PRICE_PER_MTOK.get(model, (0.0, 0.0))
    return (
        prompt_tokens * pin / 1_000_000.0
        + completion_tokens * pout / 1_000_000.0
    )


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def record_llm_usage(
    llm: LLM,
    *,
    run_id: str | None = None,
    pr: str = "unknown",
    team: str = "unknown",
    ledger: CostLedger | None = None,
) -> CostRecord | None:
    """Append the LLM's last reported usage to a cost ledger.

    Returns ``None`` without writing when ``llm.last_usage`` is ``None``
    (the provider reported no usage — we do not fabricate numbers).
    Ledger resolution: explicit ``ledger`` arg > ``FLOWSTALLION_COST_LEDGER``
    env > ``~/.flowstallion/cost-ledger.jsonl``.

    Never raises: a ledger failure (bad path, permission, ...) prints one
    stderr line and returns ``None`` so cost bookkeeping can never block
    triage.
    """
    try:
        usage = llm.last_usage
        if usage is None:
            return None
        model = llm.config.model
        if ledger is None:
            raw = os.environ.get(ENV_LEDGER, "").strip()
            ledger = CostLedger(
                raw if raw else os.path.expanduser(DEFAULT_LEDGER)
            )
        record = CostRecord(
            ts=_utc_now_iso(),
            source="llm",
            run_id=run_id,
            pr=pr,
            team=team,
            model=model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            cost=price_cost(
                model, usage.prompt_tokens, usage.completion_tokens
            ),
        )
        ledger.append(record)
        return record
    except Exception as exc:  # documented broad catch: sidecar robustness
        print(f"[cost] ledger append failed: {exc}", file=sys.stderr)
        return None


def maybe_record_llm_usage(
    llm: LLM,
    *,
    run_id: str | None = None,
    pr: str = "unknown",
    team: str = "unknown",
) -> None:
    """Opt-in, sidecar-safe bookkeeping for one LLM call.

    Appends ``llm.last_usage`` to the ledger named by ``FLOWSTALLION_COST_LEDGER``
    when that variable is set.  Does nothing when the variable is unset or the
    provider reported no usage.  Never raises: cost bookkeeping must not affect
    callers such as triage or PR review.
    """
    ledger_path = os.environ.get(ENV_LEDGER, "").strip()
    if not ledger_path:
        return
    try:
        record_llm_usage(
            llm,
            run_id=run_id,
            pr=pr,
            team=team,
            ledger=CostLedger(ledger_path),
        )
    except Exception:
        pass


def aggregate(records: list[CostRecord], by: str) -> list[dict[str, Any]]:
    """Aggregate records by ``"pr"`` or ``"team"``.

    Returns one dict per key —
    ``{<by>: key, "records": n, "prompt_tokens", "completion_tokens",
    "total_tokens", "cost_usd"}`` — sorted by ``cost_usd`` descending.

    Raises:
        ValueError: when ``by`` is not "pr" or "team".
    """
    if by not in ("pr", "team"):
        raise ValueError(f"aggregate: by must be 'pr' or 'team', got {by!r}")
    groups: dict[str, dict[str, Any]] = {}
    for r in records:
        key = r.pr if by == "pr" else r.team
        g = groups.get(key)
        if g is None:
            g = {
                by: key,
                "records": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "cost_usd": 0.0,
            }
            groups[key] = g
        g["records"] += 1
        g["prompt_tokens"] += r.prompt_tokens
        g["completion_tokens"] += r.completion_tokens
        g["total_tokens"] += r.total_tokens
        g["cost_usd"] += r.cost
    out = list(groups.values())
    out.sort(key=lambda g: g["cost_usd"], reverse=True)
    return out


def _sample_llm_records() -> list[CostRecord]:
    """Deterministic LLM usage sample: gpt-4o-mini, two PRs, two teams."""
    rows: list[tuple[str, str, str, str, int, int]] = [
        ("2026-10-22T09:00:00Z", "42", "pr-101", "team-infra", 12_000, 800),
        ("2026-10-22T10:30:00Z", "43", "pr-101", "team-infra", 30_000, 1_500),
        ("2026-10-22T14:15:00Z", "47", "pr-101", "team-infra", 5_000, 400),
        ("2026-10-22T09:45:00Z", "51", "pr-207", "team-data", 20_000, 900),
        ("2026-10-22T16:20:00Z", "55", "pr-207", "team-data", 8_000, 600),
    ]
    out: list[CostRecord] = []
    for ts, run_id, pr, team, prompt, completion in rows:
        out.append(
            CostRecord(
                ts=ts,
                source="llm",
                run_id=run_id,
                pr=pr,
                team=team,
                model="gpt-4o-mini",
                prompt_tokens=prompt,
                completion_tokens=completion,
                total_tokens=prompt + completion,
                cost=price_cost("gpt-4o-mini", prompt, completion),
            )
        )
    return out


def cloud_cost_sample() -> list[CostRecord]:
    """Deterministic cloud-cost sample (fixed values, no randomness).

    Six line items across 2 PRs x 2 teams with distinct namespaces/pods;
    cpu/mem charges are folded into ``cost``.  Recomputable byte-for-byte.
    """
    return [
        CostRecord(
            ts="2026-10-22T00:00:00Z",
            source="cloud",
            run_id=None,
            pr="pr-101",
            team="team-infra",
            namespace="prod-infra",
            pod="api-7d9f4c6",
            cost=0.42,
        ),
        CostRecord(
            ts="2026-10-22T06:00:00Z",
            source="cloud",
            run_id=None,
            pr="pr-101",
            team="team-infra",
            namespace="prod-infra",
            pod="worker-2b8e1",
            cost=0.61,
        ),
        CostRecord(
            ts="2026-10-22T00:00:00Z",
            source="cloud",
            run_id=None,
            pr="pr-101",
            team="team-data",
            namespace="data-lake",
            pod="etl-9c3f7",
            cost=1.25,
        ),
        CostRecord(
            ts="2026-10-22T00:00:00Z",
            source="cloud",
            run_id=None,
            pr="pr-207",
            team="team-infra",
            namespace="prod-search",
            pod="index-5f1a2",
            cost=0.87,
        ),
        CostRecord(
            ts="2026-10-22T06:00:00Z",
            source="cloud",
            run_id=None,
            pr="pr-207",
            team="team-data",
            namespace="data-lake",
            pod="etl-4d7b8",
            cost=2.03,
        ),
        CostRecord(
            ts="2026-10-22T12:00:00Z",
            source="cloud",
            run_id=None,
            pr="pr-207",
            team="team-data",
            namespace="data-lake",
            pod="spark-8e2c4",
            cost=0.55,
        ),
    ]


def _print_table(rows: list[dict[str, Any]], by: str) -> None:
    total_records = 0
    total_tokens = 0
    total_cost = 0.0
    print(f"{'key':<20} {'records':>8} {'tokens':>10} {'cost_usd':>10}")
    for row in rows:
        print(
            f"{str(row[by]):<20} {row['records']:>8} "
            f"{row['total_tokens']:>10} {row['cost_usd']:>10.4f}"
        )
        total_records += row["records"]
        total_tokens += row["total_tokens"]
        total_cost += row["cost_usd"]
    print(f"{'TOTAL':<20} {total_records:>8} {total_tokens:>10} {total_cost:>10.4f}")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(
        prog="python -m flowstallion_agent.cost",
        description="FlowStallion FinOps cost ledger: aggregate LLM + cloud "
        "cost by PR or team",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--by-pr", action="store_true", help="aggregate by PR")
    group.add_argument("--by-team", action="store_true", help="aggregate by team")
    parser.add_argument("--ledger", default=None, help="ledger file (JSONL)")
    parser.add_argument(
        "--source",
        choices=["llm", "cloud"],
        default=None,
        help="only aggregate records of this source",
    )
    parser.add_argument("--json", action="store_true", help="print a JSON array")
    parser.add_argument(
        "--sample",
        action="store_true",
        help="write a deterministic sample ledger to --out and exit",
    )
    parser.add_argument("--out", default=None, help="output path for --sample")
    args = parser.parse_args(argv)

    if args.sample:
        if not args.out:
            parser.error("--sample requires --out")
        records = _sample_llm_records() + cloud_cost_sample()
        CostLedger(args.out).append_many(records)
        print(f"wrote {len(records)} records to {args.out}")
        return 0

    if not (args.by_pr or args.by_team):
        parser.error("choose --by-pr or --by-team (or use --sample)")
    if not args.ledger:
        parser.error("--ledger is required")
    path = Path(os.path.expanduser(args.ledger))
    if not path.is_file():
        print(f"error: ledger file not found: {path}", file=sys.stderr)
        return 1
    try:
        records = CostLedger(path).records()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.source:
        records = [r for r in records if r.source == args.source]
    by = "pr" if args.by_pr else "team"
    rows = aggregate(records, by)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    _print_table(rows, by)
    return 0


if __name__ == "__main__":
    sys.exit(main())
