"""Table-driven tests for flowstallion_agent.autonomy.validate_level."""

import pytest

from flowstallion_agent.autonomy import AutonomyLevel, validate_level


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (0, "L0 manual: fully human-driven, no AI actions"),
        (1, "L1 AI suggests, human executes"),
        (2, "L2 AI executes, human approves before merge"),
        (3, "L3 full autonomy: unattended end-to-end"),
    ],
    ids=["L0-manual", "L1-suggest", "L2-execute-approve", "L3-full-auto"],
)
def test_validate_level_returns_label(level: int, expected: str) -> None:
    """Each valid level (0-3) maps to its documented label."""
    assert validate_level(level) == expected


@pytest.mark.parametrize(
    "level",
    [-1, 4, 99],
    ids=["negative", "just-above", "far-above"],
)
def test_validate_level_rejects_invalid(level: int) -> None:
    """Levels outside 0-3 raise ValueError with a descriptive message."""
    with pytest.raises(ValueError, match="invalid autonomy level"):
        validate_level(level)


@pytest.mark.parametrize(
    "level",
    [True, False, 1.0],
    ids=["bool-true", "bool-false", "float"],
)
def test_validate_level_rejects_non_int_types(level: object) -> None:
    """bool and integral floats are rejected (hash-equal to valid levels)."""
    with pytest.raises(ValueError, match="invalid autonomy level"):
        validate_level(level)  # type: ignore[arg-type]


def test_autonomy_level_enum_constants() -> None:
    """Enum constants match the documented L0-L3 numbering."""
    assert AutonomyLevel.L0_MANUAL.value == 0
    assert AutonomyLevel.L1_AI_SUGGEST.value == 1
    assert AutonomyLevel.L2_AI_EXECUTE_HUMAN_APPROVE.value == 2
    assert AutonomyLevel.L3_FULL_AUTO.value == 3
