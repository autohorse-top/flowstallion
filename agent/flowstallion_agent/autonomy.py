"""Autonomy level definitions (L0-L3)."""

from enum import IntEnum


class AutonomyLevel(IntEnum):
    """Autonomy levels supported by the FlowStallion agent."""

    L0_MANUAL = 0
    L1_AI_SUGGEST = 1
    L2_AI_EXECUTE_HUMAN_APPROVE = 2
    L3_FULL_AUTO = 3


_LEVEL_LABELS: dict[AutonomyLevel, str] = {
    AutonomyLevel.L0_MANUAL: "L0 manual: fully human-driven, no AI actions",
    AutonomyLevel.L1_AI_SUGGEST: "L1 AI suggests, human executes",
    AutonomyLevel.L2_AI_EXECUTE_HUMAN_APPROVE: "L2 AI executes, human approves before merge",
    AutonomyLevel.L3_FULL_AUTO: "L3 full autonomy: unattended end-to-end",
}


def validate_level(level: int) -> str:
    """Return the human-readable label for an autonomy level.

    Args:
        level: Autonomy level in 0..3 (L0_MANUAL .. L3_FULL_AUTO). Must be
            a plain ``int``; ``bool`` and ``float`` are rejected even when
            hash-equal to a valid level.

    Returns:
        A human-readable label describing the level.

    Raises:
        ValueError: If ``level`` is not a plain int in 0..3.
    """
    if type(level) is not int:
        raise ValueError(
            f"invalid autonomy level {level!r}: expected an int in 0..3"
        )
    try:
        return _LEVEL_LABELS[AutonomyLevel(level)]
    except ValueError as exc:
        raise ValueError(
            f"invalid autonomy level {level!r}: expected an int in 0..3"
        ) from exc
