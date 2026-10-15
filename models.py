
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


IncidentCategory = Literal[
    "account",
    "vpn",
    "network",
    "device",
    "security",
    "unknown",
]

IncidentSeverity = Literal[
    "low",
    "medium",
    "high",
    "critical",
]

WorkerName = Literal[
    "account",
    "network",
    "device",
]


class IncidentReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(
        min_length=1,
        max_length=100,
        description="Unique identifier for the incident",
    )

    description: str = Field(
        min_length=10,
        max_length=3000,
        description="The problem reported by the user",
    )

    affected_service: str = Field(
        min_length=1,
        max_length=100,
        description="The service or system affected",
    )


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: IncidentCategory = Field(
        description="The classified incident category",
    )

    severity: IncidentSeverity = Field(
        description="The estimated incident severity",
    )

    reasoning: str = Field(
        min_length=10,
        max_length=1000,
        description="Evidence-based explanation for the classification",
    )

    suggested_workers: list[WorkerName] = Field(
        min_length=1,
        max_length=3,
        description="Workers recommended for investigation",
    )

    needs_human_review: bool = Field(
        description="Whether human review is recommended",
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in the classification, from 0 to 1",
    )


class InvestigationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(
        min_length=10,
        max_length=2000,
        description="Summary of the investigation findings",
    )

    evidence: list[str] = Field(
        max_length=20,
        description=(
            "Evidence actually obtained during investigation; "
            "may be empty if no evidence was found"
        ),
    )

    recommendation: str = Field(
        min_length=10,
        max_length=1500,
        description=(
            "Recommended next step based on the available evidence"
        ),
    )

    requires_human_review: bool = Field(
        description="Whether the investigation needs human review",
    )


class EvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: bool = Field(
        description=(
            "Whether the investigation result meets the evaluation criteria"
        ),
    )

    score: float = Field(
        ge=0.0,
        le=1.0,
        description="Evaluation score between 0 and 1",
    )

    feedback: str = Field(
        min_length=5,
        max_length=1000,
        description="Explanation of the evaluation decision",
    )

    needs_revision: bool = Field(
        description="Whether another investigation attempt is recommended",
    )

    needs_human_review: bool = Field(
        description="Whether a human must review the result",
    )
