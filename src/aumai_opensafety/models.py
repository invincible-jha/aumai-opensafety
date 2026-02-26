"""Pydantic models for aumai-opensafety."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IncidentSeverity(str, Enum):
    """Severity classification for AI safety incidents."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class IncidentCategory(str, Enum):
    """Category classification for AI safety incidents."""

    model_failure = "model_failure"
    data_leak = "data_leak"
    bias = "bias"
    misuse = "misuse"
    safety_bypass = "safety_bypass"
    hallucination = "hallucination"
    other = "other"


class SafetyIncident(BaseModel):
    """Represents a single AI safety incident or near-miss."""

    incident_id: str = Field(..., description="Unique identifier for the incident")
    title: str = Field(..., description="Short descriptive title")
    description: str = Field(..., description="Full incident description")
    severity: IncidentSeverity
    category: IncidentCategory
    source: str = Field(..., description="URL or name of the reporting source")
    reported_date: datetime
    affected_systems: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    verified: bool = Field(default=False)


class IncidentTimeline(BaseModel):
    """A chronologically sorted collection of safety incidents with summary stats."""

    incidents: list[SafetyIncident] = Field(default_factory=list)
    total_count: int = 0
    earliest_date: datetime | None = None
    latest_date: datetime | None = None
    period_description: str = ""

    def sorted_incidents(self) -> list[SafetyIncident]:
        """Return incidents sorted by reported_date ascending."""
        return sorted(self.incidents, key=lambda i: i.reported_date)


class DashboardStats(BaseModel):
    """Aggregate statistics for the safety incident dashboard."""

    total_incidents: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    trend_30d: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Daily incident counts for last 30 days: [{date, count}]",
    )
    verified_count: int = 0
    unverified_count: int = 0


__all__ = [
    "IncidentSeverity",
    "IncidentCategory",
    "SafetyIncident",
    "IncidentTimeline",
    "DashboardStats",
]
