"""Policy gateway mirror — risk classification and autonomy decisions.

This module mirrors ``pkg/policy`` in the Go codebase, which is the
authoritative enforcement point (the scheduler holds runs for approval
before any step executes). The Python mirror exists so agent-side tooling
can reason about the same rules without a Go dependency.

Keep both implementations in sync: they are verified against the shared
vectors in ``testdata/policy-vectors.json`` (Go table test
``pkg/policy`` and ``agent/tests/test_policy.py``).

Autonomy levels (v1):

- L0 — fully manual: every step requires approval.
- L1 — high + critical steps require approval.
- L2 — only critical steps require approval (default).

Risk classes (v1 rule set):

- ``"critical"`` — step id suggests deployment/release AND env marks
  production (e.g. ``environment: production``).
- ``"high"`` — step targets a production env, or its id suggests a
  destructive operation (migrate/drop/delete/...).
- ``"low"`` — everything else.
"""

from __future__ import annotations

import re

__all__ = [
    "is_production_env",
    "step_risk",
    "needs_approval",
    "any_step_requires_approval",
    "parse_level",
]

# Env keys (lower-cased) that mark the target environment.
_PROD_KEYS = {"environment", "env", "target", "flowstallion_env"}
# Env values (lower-cased) that mean "production".
_PROD_VALUES = {"production", "prod"}
# Substrings in a step id that mark a destructive operation.
_HIGH_KEYWORDS = (
    "migrate",
    "destroy",
    "drop",
    "delete",
    "remove",
    "purge",
    "publish",
    "prune",
)
# Substrings in a step id that mark a deployment/release operation.
_DEPLOY_KEYWORDS = ("deploy", "release")

_LEVEL_RE = re.compile(r"^[012]$")


def is_production_env(env: dict[str, str] | None) -> bool:
    """Return True when env marks the production environment.

    Key and value matching are case-insensitive; an empty/None env is
    never production.
    """
    if not env:
        return False
    for key, value in env.items():
        if key.lower() in _PROD_KEYS and value.lower() in _PROD_VALUES:
            return True
    return False


def step_risk(step_id: str, env: dict[str, str] | None = None) -> str:
    """Classify a step as ``"critical"``, ``"high"`` or ``"low"``.

    Mirrors ``policy.StepRisk`` in Go: a deploy/release step targeting
    production is critical; a production target or a destructive id is
    high; anything else is low.
    """
    low_id = step_id.lower()
    prod = is_production_env(env)
    if prod and any(kw in low_id for kw in _DEPLOY_KEYWORDS):
        return "critical"
    if prod:
        return "high"
    for kw in _HIGH_KEYWORDS:
        if kw in low_id:
            return "high"
    return "low"


def needs_approval(risk: str, level: int) -> bool:
    """Return True when a step with the given risk needs approval at L``level``.

    Mirrors ``policy.NeedsApproval`` in Go. Unknown levels fail safe to the
    critical-only rule (L2 behaviour).
    """
    if level == 0:
        return True
    if level == 1:
        return risk in ("high", "critical")
    return risk == "critical"


def any_step_requires_approval(steps: list[dict[str, object]], level: int) -> bool:
    """Return True when any step of the pipeline must be approved at L``level``.

    Each step dict needs ``"id"`` and may carry ``"env"`` (dict or None),
    matching the merged pipeline+step env view used by the Go scheduler.
    """
    for step in steps:
        step_id = str(step.get("id", ""))
        env = step.get("env")
        env_map: dict[str, str] = {}
        if isinstance(env, dict):
            env_map = {str(k): str(v) for k, v in env.items()}
        if needs_approval(step_risk(step_id, env_map), level):
            return True
    return False


def parse_level(raw: str) -> int:
    """Parse an autonomy level from a string; empty/invalid yields L2.

    Mirrors ``policy.ParseLevel`` in Go (the v1 default is L2).
    """
    value = raw.strip()
    if _LEVEL_RE.match(value):
        return int(value)
    return 2
