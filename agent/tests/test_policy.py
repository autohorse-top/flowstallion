"""Tests for the policy mirror (agent/flowstallion_agent/policy.py).

The decision matrix is shared with the Go implementation
(pkg/policy) via testdata/policy-vectors.json. The negative
acceptance case required by TASK.md: an unapproved production deploy
must be held (approval required) — verified below as a standalone
assertion in addition to the shared vectors.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flowstallion_agent import policy

_VECTORS_PATH = Path(__file__).resolve().parents[2] / "testdata" / "policy-vectors.json"


def _load_vectors() -> list[dict[str, Any]]:
    data = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data, "policy vectors file missing or empty"
    return data


def test_shared_vector_matrix() -> None:
    for i, v in enumerate(_load_vectors()):
        env: dict[str, str] = {str(k): str(x) for k, x in v["env"].items()}
        risk = policy.step_risk(str(v["step_id"]), env)
        got = policy.needs_approval(risk, int(v["level"]))
        want = bool(v["approval"])
        assert got is want, (
            f"vector {i}: step_id={v['step_id']!r} env={env!r} level={v['level']} "
            f"risk={risk} -> needs_approval={got}, want {want}"
        )


def test_prod_deploy_held_without_approval() -> None:
    """Negative acceptance: unapproved production deploy is blocked at L2."""
    risk = policy.step_risk("deploy-prod", {"environment": "production"})
    assert risk == "critical"
    assert policy.needs_approval(risk, 2) is True
    assert policy.needs_approval(risk, 1) is True
    assert policy.needs_approval(risk, 0) is True


def test_prod_deploy_not_held_for_staging() -> None:
    risk = policy.step_risk("deploy-prod", {"environment": "staging"})
    assert risk == "low"
    assert policy.needs_approval(risk, 2) is False
    assert policy.needs_approval(risk, 1) is False


def test_l0_holds_everything() -> None:
    assert policy.needs_approval("low", 0) is True
    assert policy.needs_approval("high", 0) is True
    assert policy.needs_approval("critical", 0) is True


def test_l1_holds_high_and_critical() -> None:
    assert policy.needs_approval("low", 1) is False
    assert policy.needs_approval("high", 1) is True
    assert policy.needs_approval("critical", 1) is True


def test_l2_holds_only_critical() -> None:
    assert policy.needs_approval("low", 2) is False
    assert policy.needs_approval("high", 2) is False
    assert policy.needs_approval("critical", 2) is True


def test_parse_level_defaults_to_l2() -> None:
    assert policy.parse_level("0") == 0
    assert policy.parse_level("1") == 1
    assert policy.parse_level("2") == 2
    assert policy.parse_level("") == 2
    assert policy.parse_level("bogus") == 2
    assert policy.parse_level(" 1 ") == 1


def test_is_production_env_case_insensitive() -> None:
    assert policy.is_production_env({"environment": "production"}) is True
    assert policy.is_production_env({"ENV": "PROD"}) is True
    assert policy.is_production_env({"target": "Production"}) is True
    assert policy.is_production_env({"flowstallion_env": "prod"}) is True
    assert policy.is_production_env({"environment": "staging"}) is False
    assert policy.is_production_env({}) is False
    assert policy.is_production_env(None) is False


def test_any_step_requires_approval() -> None:
    steps: list[dict[str, object]] = [
        {"id": "build", "env": {}},
        {"id": "deploy-prod", "env": {"environment": "production"}},
    ]
    assert policy.any_step_requires_approval(steps, 2) is True
    safe: list[dict[str, object]] = [{"id": "build", "env": {"environment": "staging"}}]
    assert policy.any_step_requires_approval(safe, 2) is False
    assert policy.any_step_requires_approval(safe, 0) is True
