"""Core logic: incident collection, classification, storage, and analysis."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from aumai_opensafety.models import (
    DashboardStats,
    IncidentCategory,
    IncidentSeverity,
    IncidentTimeline,
    SafetyIncident,
)

# ---------------------------------------------------------------------------
# Keyword rule tables used by IncidentClassifier
# ---------------------------------------------------------------------------

_SEVERITY_KEYWORDS: dict[IncidentSeverity, list[str]] = {
    IncidentSeverity.critical: [
        "critical", "catastrophic", "mass harm", "widespread", "breach",
        "exfiltration", "remote code execution", "rce", "zero-day",
    ],
    IncidentSeverity.high: [
        "high", "severe", "significant", "dangerous", "exploit",
        "unauthorized access", "data leak", "exposure", "injection",
    ],
    IncidentSeverity.medium: [
        "medium", "moderate", "partial", "limited", "degraded",
        "incorrect output", "misleading", "bias detected",
    ],
    IncidentSeverity.low: [
        "low", "minor", "minimal", "edge case", "cosmetic",
    ],
    IncidentSeverity.informational: [
        "informational", "observation", "note", "fyi", "awareness",
    ],
}

_CATEGORY_KEYWORDS: dict[IncidentCategory, list[str]] = {
    IncidentCategory.model_failure: [
        "model failure", "model crash", "inference error", "output error",
        "model broke", "performance degradation",
    ],
    IncidentCategory.data_leak: [
        "data leak", "data exfiltration", "pii exposed", "training data",
        "memorization", "exposure", "leaked", "privacy",
    ],
    IncidentCategory.bias: [
        "bias", "discriminatory", "unfair", "stereotype", "disparity",
        "demographic", "representation",
    ],
    IncidentCategory.misuse: [
        "misuse", "abuse", "adversarial", "weaponized", "scam",
        "disinformation", "deepfake", "fraud",
    ],
    IncidentCategory.safety_bypass: [
        "jailbreak", "bypass", "prompt injection", "guardrail", "override",
        "circumvent", "safety filter", "restriction removed",
    ],
    IncidentCategory.hallucination: [
        "hallucination", "fabricated", "invented", "made up", "false fact",
        "incorrect citation", "fictional",
    ],
}


class IncidentClassifier:
    """Classify safety incidents by severity and category using keyword rules."""

    def classify_severity(self, incident: SafetyIncident) -> IncidentSeverity:
        """Infer severity from title + description text via keyword matching."""
        text = (incident.title + " " + incident.description).lower()
        for severity in (
            IncidentSeverity.critical,
            IncidentSeverity.high,
            IncidentSeverity.medium,
            IncidentSeverity.low,
            IncidentSeverity.informational,
        ):
            for keyword in _SEVERITY_KEYWORDS[severity]:
                if keyword in text:
                    return severity
        return IncidentSeverity.informational

    def classify_category(self, incident: SafetyIncident) -> IncidentCategory:
        """Infer category from title + description via keyword matching."""
        text = (incident.title + " " + incident.description).lower()
        for category in IncidentCategory:
            for keyword in _CATEGORY_KEYWORDS.get(category, []):
                if keyword in text:
                    return category
        return IncidentCategory.other

    def reclassify(self, incident: SafetyIncident) -> SafetyIncident:
        """Return a new incident with severity and category auto-set."""
        return incident.model_copy(
            update={
                "severity": self.classify_severity(incident),
                "category": self.classify_category(incident),
            }
        )


class IncidentCollector:
    """Collect and deduplicate safety incidents."""

    def __init__(self) -> None:
        self._incidents: dict[str, SafetyIncident] = {}

    def add(self, incident: SafetyIncident) -> bool:
        """Add a single incident. Returns True if new, False if duplicate."""
        if incident.incident_id in self._incidents:
            return False
        self._incidents[incident.incident_id] = incident
        return True

    def bulk_import(self, incidents: list[SafetyIncident]) -> int:
        """Add a list of incidents; return count of newly added."""
        before = len(self._incidents)
        for incident in incidents:
            self.add(incident)
        return len(self._incidents) - before

    def bulk_import_json(self, data: list[dict[str, Any]]) -> int:
        """Deserialize and import incidents from a JSON array."""
        incidents = [SafetyIncident.model_validate(item) for item in data]
        return self.bulk_import(incidents)

    def all_incidents(self) -> list[SafetyIncident]:
        """Return all stored incidents."""
        return list(self._incidents.values())

    @property
    def count(self) -> int:
        """Total number of collected incidents."""
        return len(self._incidents)


class IncidentStore:
    """In-memory store with query, filter, and search capabilities."""

    def __init__(self) -> None:
        self._data: dict[str, SafetyIncident] = {}

    def add(self, incident: SafetyIncident) -> None:
        """Insert or overwrite an incident."""
        self._data[incident.incident_id] = incident

    def get(self, incident_id: str) -> SafetyIncident | None:
        """Retrieve a single incident by ID."""
        return self._data.get(incident_id)

    def all(self) -> list[SafetyIncident]:
        """Return all stored incidents."""
        return list(self._data.values())

    def filter_by_severity(self, severity: IncidentSeverity) -> list[SafetyIncident]:
        """Return incidents with the given severity."""
        return [i for i in self._data.values() if i.severity == severity]

    def filter_by_category(self, category: IncidentCategory) -> list[SafetyIncident]:
        """Return incidents with the given category."""
        return [i for i in self._data.values() if i.category == category]

    def filter_verified(self, verified: bool = True) -> list[SafetyIncident]:
        """Return incidents filtered by verification status."""
        return [i for i in self._data.values() if i.verified == verified]

    def search(self, query: str) -> list[SafetyIncident]:
        """Full-text search across title, description, and tags."""
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        results: list[SafetyIncident] = []
        for incident in self._data.values():
            target = " ".join(
                [incident.title, incident.description] + incident.tags
            )
            if pattern.search(target):
                results.append(incident)
        return results

    def paginate(
        self,
        page: int = 1,
        page_size: int = 20,
        severity: IncidentSeverity | None = None,
        category: IncidentCategory | None = None,
        verified: bool | None = None,
    ) -> tuple[list[SafetyIncident], int]:
        """Return a page of incidents with total count.

        Filters are applied before pagination.
        Returns (items, total_count).
        """
        items = self.all()
        if severity is not None:
            items = [i for i in items if i.severity == severity]
        if category is not None:
            items = [i for i in items if i.category == category]
        if verified is not None:
            items = [i for i in items if i.verified == verified]

        items.sort(key=lambda i: i.reported_date, reverse=True)
        total = len(items)
        start = (page - 1) * page_size
        return items[start : start + page_size], total

    @property
    def count(self) -> int:
        """Total number of stored incidents."""
        return len(self._data)


class TimelineAnalyzer:
    """Temporal analysis of incident data."""

    def build_timeline(self, incidents: list[SafetyIncident]) -> IncidentTimeline:
        """Build a sorted timeline from a list of incidents."""
        if not incidents:
            return IncidentTimeline(period_description="No incidents")

        sorted_incidents = sorted(incidents, key=lambda i: i.reported_date)
        earliest = sorted_incidents[0].reported_date
        latest = sorted_incidents[-1].reported_date
        delta_days = (latest - earliest).days

        return IncidentTimeline(
            incidents=sorted_incidents,
            total_count=len(sorted_incidents),
            earliest_date=earliest,
            latest_date=latest,
            period_description=(
                f"{len(sorted_incidents)} incidents over {delta_days} days"
            ),
        )

    def incidents_per_day(
        self, incidents: list[SafetyIncident]
    ) -> dict[str, int]:
        """Count incidents per calendar day (ISO date string keys)."""
        counts: Counter[str] = Counter()
        for incident in incidents:
            day_key = incident.reported_date.strftime("%Y-%m-%d")
            counts[day_key] += 1
        return dict(sorted(counts.items()))

    def trending_categories(
        self,
        incidents: list[SafetyIncident],
        days: int = 30,
    ) -> list[tuple[str, int]]:
        """Return category counts for incidents in the last N days, sorted descending."""
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)
        recent = [i for i in incidents if i.reported_date >= cutoff]
        counts: Counter[str] = Counter(i.category.value for i in recent)
        return counts.most_common()

    def build_dashboard_stats(
        self, incidents: list[SafetyIncident]
    ) -> DashboardStats:
        """Aggregate all statistics for the dashboard."""
        by_severity: Counter[str] = Counter(i.severity.value for i in incidents)
        by_category: Counter[str] = Counter(i.category.value for i in incidents)
        verified_count = sum(1 for i in incidents if i.verified)

        now = datetime.now(tz=timezone.utc)
        day_counts: dict[str, int] = defaultdict(int)
        for incident in incidents:
            if (now - incident.reported_date).days <= 30:
                day_key = incident.reported_date.strftime("%Y-%m-%d")
                day_counts[day_key] += 1

        trend_30d = [
            {"date": day, "count": count}
            for day, count in sorted(day_counts.items())
        ]

        return DashboardStats(
            total_incidents=len(incidents),
            by_severity=dict(by_severity),
            by_category=dict(by_category),
            trend_30d=trend_30d,
            verified_count=verified_count,
            unverified_count=len(incidents) - verified_count,
        )


__all__ = [
    "IncidentClassifier",
    "IncidentCollector",
    "IncidentStore",
    "TimelineAnalyzer",
]
