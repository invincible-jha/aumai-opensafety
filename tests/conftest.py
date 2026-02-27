"""Shared test fixtures for aumai-opensafety."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aumai_opensafety.core import (
    IncidentClassifier,
    IncidentCollector,
    IncidentStore,
    TimelineAnalyzer,
)
from aumai_opensafety.models import (
    IncidentCategory,
    IncidentSeverity,
    SafetyIncident,
)

# ---------------------------------------------------------------------------
# Datetime helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=UTC)


def _dt(days_ago: int = 0) -> datetime:
    """Return a timezone-aware datetime N days in the past."""
    return _NOW - timedelta(days=days_ago)


# ---------------------------------------------------------------------------
# Canonical incident factories
# ---------------------------------------------------------------------------


def make_incident(
    incident_id: str = "INC-001",
    title: str = "Test incident",
    description: str = "A test incident description.",
    severity: IncidentSeverity = IncidentSeverity.medium,
    category: IncidentCategory = IncidentCategory.other,
    source: str = "https://example.com/incident",
    reported_date: datetime | None = None,
    affected_systems: list[str] | None = None,
    tags: list[str] | None = None,
    verified: bool = False,
) -> SafetyIncident:
    """Factory for creating SafetyIncident objects with sensible defaults."""
    return SafetyIncident(
        incident_id=incident_id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        source=source,
        reported_date=reported_date or _dt(0),
        affected_systems=affected_systems or [],
        tags=tags or [],
        verified=verified,
    )


# ---------------------------------------------------------------------------
# Fixtures: individual incidents
# ---------------------------------------------------------------------------


@pytest.fixture()
def critical_incident() -> SafetyIncident:
    """A critical-severity data-leak incident."""
    return make_incident(
        incident_id="INC-CRIT-001",
        title="Mass data breach via prompt injection",
        description=(
            "A critical data exfiltration attack exposed PII of thousands of users "
            "through a prompt injection vulnerability in a customer-facing LLM."
        ),
        severity=IncidentSeverity.critical,
        category=IncidentCategory.data_leak,
        source="https://security.example.com/breach-report",
        verified=True,
        tags=["llm", "prompt-injection", "pii"],
        affected_systems=["customer-chat-api", "user-database"],
    )


@pytest.fixture()
def high_incident() -> SafetyIncident:
    """A high-severity safety-bypass incident."""
    return make_incident(
        incident_id="INC-HIGH-001",
        title="Jailbreak bypass discovered in production model",
        description=(
            "Researchers identified a jailbreak technique that circumvents the "
            "safety guardrails of the deployed language model."
        ),
        severity=IncidentSeverity.high,
        category=IncidentCategory.safety_bypass,
        source="https://research.example.com/jailbreak",
        verified=True,
        tags=["jailbreak", "guardrail"],
    )


@pytest.fixture()
def medium_incident() -> SafetyIncident:
    """A medium-severity bias incident."""
    return make_incident(
        incident_id="INC-MED-001",
        title="Bias detected in hiring recommendation model",
        description=(
            "A medium severity bias was detected in the model's outputs when "
            "processing demographic information, producing discriminatory outcomes."
        ),
        severity=IncidentSeverity.medium,
        category=IncidentCategory.bias,
        source="https://fairness.example.com/report",
        reported_date=_dt(5),
        tags=["bias", "hiring", "fairness"],
    )


@pytest.fixture()
def low_incident() -> SafetyIncident:
    """A low-severity hallucination incident."""
    return make_incident(
        incident_id="INC-LOW-001",
        title="Minor hallucination in citation generation",
        description=(
            "The model produced a fabricated citation with incorrect journal name. "
            "Low severity edge case affecting academic use."
        ),
        severity=IncidentSeverity.low,
        category=IncidentCategory.hallucination,
        source="https://reports.example.com/hallucination",
        reported_date=_dt(10),
        tags=["hallucination", "citations"],
    )


@pytest.fixture()
def informational_incident() -> SafetyIncident:
    """An informational-severity observation."""
    return make_incident(
        incident_id="INC-INFO-001",
        title="Informational: model performance observation",
        description="FYI — slight performance degradation noted during peak load.",
        severity=IncidentSeverity.informational,
        category=IncidentCategory.model_failure,
        source="https://ops.example.com/observation",
        reported_date=_dt(20),
    )


@pytest.fixture()
def verified_incident() -> SafetyIncident:
    """A verified incident."""
    return make_incident(
        incident_id="INC-VERIFIED-001",
        title="Verified remote code execution via model plugin",
        description="Confirmed RCE via a malicious plugin loaded by the model runtime.",
        severity=IncidentSeverity.critical,
        category=IncidentCategory.safety_bypass,
        source="https://cve.example.com/rce",
        verified=True,
        reported_date=_dt(2),
    )


@pytest.fixture()
def unverified_incident() -> SafetyIncident:
    """An unverified incident."""
    return make_incident(
        incident_id="INC-UNVERIFIED-001",
        title="Unconfirmed data leak report",
        description="Community report of potential data leak, not yet confirmed.",
        severity=IncidentSeverity.high,
        category=IncidentCategory.data_leak,
        source="https://forum.example.com/thread/123",
        verified=False,
        reported_date=_dt(1),
    )


@pytest.fixture()
def old_incident() -> SafetyIncident:
    """An incident from 60 days ago (outside the 30-day trend window)."""
    return make_incident(
        incident_id="INC-OLD-001",
        title="Historical model failure",
        description="An old model failure from 60 days ago.",
        severity=IncidentSeverity.low,
        category=IncidentCategory.model_failure,
        source="https://archive.example.com/old",
        reported_date=_dt(60),
    )


# ---------------------------------------------------------------------------
# Fixtures: collections
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_incidents(
    critical_incident: SafetyIncident,
    high_incident: SafetyIncident,
    medium_incident: SafetyIncident,
    low_incident: SafetyIncident,
    informational_incident: SafetyIncident,
) -> list[SafetyIncident]:
    """A list of five incidents covering all severity levels."""
    return [
        critical_incident,
        high_incident,
        medium_incident,
        low_incident,
        informational_incident,
    ]


@pytest.fixture()
def populated_store(sample_incidents: list[SafetyIncident]) -> IncidentStore:
    """An IncidentStore pre-loaded with sample incidents."""
    store = IncidentStore()
    for incident in sample_incidents:
        store.add(incident)
    return store


# ---------------------------------------------------------------------------
# Fixtures: core components
# ---------------------------------------------------------------------------


@pytest.fixture()
def classifier() -> IncidentClassifier:
    """A fresh IncidentClassifier instance."""
    return IncidentClassifier()


@pytest.fixture()
def collector() -> IncidentCollector:
    """A fresh IncidentCollector instance."""
    return IncidentCollector()


@pytest.fixture()
def store() -> IncidentStore:
    """A fresh empty IncidentStore instance."""
    return IncidentStore()


@pytest.fixture()
def analyzer() -> TimelineAnalyzer:
    """A fresh TimelineAnalyzer instance."""
    return TimelineAnalyzer()


# ---------------------------------------------------------------------------
# Fixtures: FastAPI test client
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_client(sample_incidents: list[SafetyIncident]) -> TestClient:
    """A TestClient backed by a freshly-seeded dashboard app."""
    from aumai_opensafety.dashboard import create_app

    fresh_app = create_app(initial_incidents=sample_incidents)
    return TestClient(fresh_app)


@pytest.fixture()
def empty_api_client() -> TestClient:
    """A TestClient backed by an empty dashboard app."""
    from aumai_opensafety.dashboard import create_app

    fresh_app = create_app()
    return TestClient(fresh_app)


# ---------------------------------------------------------------------------
# Fixtures: JSON / file helpers
# ---------------------------------------------------------------------------


def incident_to_dict(incident: SafetyIncident) -> dict[str, Any]:
    """Serialize a SafetyIncident to a JSON-compatible dict."""
    return json.loads(incident.model_dump_json())


@pytest.fixture()
def sample_incidents_json(
    sample_incidents: list[SafetyIncident],
) -> list[dict[str, Any]]:
    """Raw JSON-serializable list of sample incidents."""
    return [incident_to_dict(i) for i in sample_incidents]


@pytest.fixture()
def incidents_json_file(
    tmp_path: Path,
    sample_incidents_json: list[dict[str, Any]],
) -> Path:
    """A temporary JSON file containing sample incidents."""
    file = tmp_path / "incidents.json"
    file.write_text(json.dumps(sample_incidents_json), encoding="utf-8")
    return file


@pytest.fixture()
def invalid_json_file(tmp_path: Path) -> Path:
    """A temporary JSON file containing an object (not an array)."""
    file = tmp_path / "invalid.json"
    file.write_text(json.dumps({"not": "an array"}), encoding="utf-8")
    return file
