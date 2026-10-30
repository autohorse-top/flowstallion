"""FlowStallion AI Agent — failure triage, PR review, smart test selection."""

from flowstallion_agent.autonomy import AutonomyLevel, validate_level
from flowstallion_agent.client import (
    AnalysisReport,
    ClientError,
    ClientHTTPError,
    ClientNotFound,
    RunInfo,
    RunStepInfo,
    SchedulerClient,
    server_from_env,
)
from flowstallion_agent.llm import (
    LLM,
    LLMConfig,
    LLMError,
    LLMNotConfigured,
    LLMAuthError,
    LLMHTTPError,
    LLMTimeoutError,
    TokenUsage,
    Transport,
    is_configured,
)
from flowstallion_agent.policy import (
    any_step_requires_approval,
    is_production_env,
    needs_approval,
    parse_level,
    step_risk,
)
from flowstallion_agent.prreview import (
    PRReviewError,
    PRReviewHTTPError,
    ReviewFinding,
    build_review_payload,
    post_pr_review,
    review,
)
from flowstallion_agent.testselect import TestSelection, select_tests
from flowstallion_agent.triage import RCA, analyze
from flowstallion_agent.watch import poll_once

__all__ = [
    "AutonomyLevel",
    "validate_level",
    "AnalysisReport",
    "ClientError",
    "ClientHTTPError",
    "ClientNotFound",
    "RunInfo",
    "RunStepInfo",
    "SchedulerClient",
    "server_from_env",
    "LLM",
    "LLMConfig",
    "LLMError",
    "LLMNotConfigured",
    "LLMAuthError",
    "LLMHTTPError",
    "LLMTimeoutError",
    "TokenUsage",
    "Transport",
    "is_configured",
    "any_step_requires_approval",
    "is_production_env",
    "needs_approval",
    "parse_level",
    "step_risk",
    "PRReviewError",
    "PRReviewHTTPError",
    "ReviewFinding",
    "build_review_payload",
    "post_pr_review",
    "review",
    "RCA",
    "analyze",
    "poll_once",
    "TestSelection",
    "select_tests",
]

__version__: str = "0.0.1"
