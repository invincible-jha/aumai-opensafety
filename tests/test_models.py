"""Tests for aumai_opensafety.models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aumai_opensafety.models import (
    DashboardStats,
    IncidentCategory,
    IncidentSeverity,
    IncidentTimeline,
    SafetyIncident,
)

# ---------------------------------------------------------------------------
# IncidentSeverity
# ---------------------------------------------------------------------------


class TestIncidentSeverity:
    """Tests for the IncidentSeverity enum."""

    def test_all_members_are_strings(self) -> None:
        for member in IncidentSeverity:
            assert isinstance(member.value, str)

    def test_members_exist(self) -> None:
        assert IncidentSeverity.critical == "critical"
        assert IncidentSeverity.high == "high"
        assert IncidentSeverity.medium == "medium"
        assert IncidentSeverity.low == "low"
        assert IncidentSeverity.informational == "informational"

    def test_five_severity_levels(self) -> None:
        assert len(IncidentSeverity) == 5

    def test_constructible_from_string(self) -> None:
        assert IncidentSeverity("critical") is IncidentSeverity.critical


# ---------------------------------------------------------------------------
# IncidentCategory
# ---------------------------------------------------------------------------


class TestIncidentCategory:
    """Tests for the IncidentCategory enum."""

    def test_all_members_are_strings(self) -> None:
        for member in IncidentCategory:
            assert isinstance(member.value, str)

    def test_seven_categories(self) -> None:
        assert len(IncidentCategory) == 7

    def test_expected_categories_present(self) -> None:
        expected = {
            "model_failure",
            "data_leak",
            "bias",
            "misuse",
            "safety_bypass",
            "hallucination",
            "other",
        }
        assert {m.value for m in IncidentCategory} == expected

    def test_constructible_from_string(self) -> None:
        assert IncidentCategory("bias") is IncidentCategory.bias


# ---------------------------------------------------------------------------
# SafetyIncident
# ---------------------------------------------------------------------------


class TestSafetyIncident:
    """Tests for the SafetyIncident Pydantic model."""

    def test_minimal_construction(self) -> None:
        now = datetime.now(tz=UTC)
        incident = SafetyIncident(
            incident_id="INC-001",
            title="Test",
            description="Desc",
            severity=IncidentSeverity.low,
            category=IncidentCategory.other,
            source="https://example.com",
            reported_date=now,
        )
        assert incident.incident_id == "INC-001"
        assert incident.verified is False
        assert incident.affected_systems == []
        assert incident.tags == []

    def test_defaults_for_list_fields(self) -> None:
        now = datetime.now(tz=UTC)
        incident = SafetyIncident(
            incident_id="X",
            title="T",
            description="D",
            severity=IncidentSeverity.low,
            category=IncidentCategory.other,
            source="src",
            reported_date=now,
        )
        # Mutable defaults must not be shared between instances
        other = SafetyIncident(
            incident_id="Y",
            title="T",
            description="D",
            severity=IncidentSeverity.low,
            category=IncidentCategory.other,
            source="src",
            reported_date=now,
        )
        incident.affected_systems.append("system-a")
        assert other.affected_systems == []

    def test_full_construction(self) -> None:
        now = datetime.now(tz=UTC)
        incident = SafetyIncident(
            incident_id="INC-FULL",
            title="Full incident",
            description="Full description",
            severity=IncidentSeverity.critical,
            category=IncidentCategory.data_leak,
            source="https://source.example.com",
            reported_date=now,
            affected_systems=["api", "db"],
            tags=["pii", "breach"],
            verified=True,
        )
        assert incident.verified is True
        assert incident.affected_systems == ["api", "db"]
        assert incident.tags == ["pii", "breach"]

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            SafetyIncident(  # type: ignore[call-arg]
                title="No ID",
                description="Desc",
                severity=IncidentSeverity.low,
                category=IncidentCategory.other,
                source="src",
                reported_date=datetime.now(tz=UTC),
            )

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(ValidationError):
            SafetyIncident(
                incident_id="INC-BAD",
                title="Bad severity",
                description="Desc",
                severity="not_a_severity",  # type: ignore[arg-type]
                category=IncidentCategory.other,
                source="src",
                reported_date=datetime.now(tz=UTC),
            )

    def test_invalid_category_raises(self) -> None:
        with pytest.raises(ValidationError):
            SafetyIncident(
                incident_id="INC-BAD",
                title="Bad category",
                description="Desc",
                severity=IncidentSeverity.low,
                category="not_a_category",  # type: ignore[arg-type]
                source="src",
                reported_date=datetime.now(tz=UTC),
            )

    def test_model_copy_preserves_original(self) -> None:
        now = datetime.now(tz=UTC)
        original = SafetyIncident(
            incident_id="INC-COPY",
            title="Original",
            description="Desc",
            severity=IncidentSeverity.low,
            category=IncidentCategory.other,
            source="src",
            reported_date=now,
        )
        updated = original.model_copy(update={"severity": IncidentSeverity.critical})
        assert original.severity == IncidentSeverity.low
        assert updated.severity == IncidentSeverity.critical
        assert updated.incident_id == "INC-COPY"

    def test_serialization_round_trip(self) -> None:

        now = datetime.now(tz=UTC)
        incident = SafetyIncident(
            incident_id="INC-SERIAL",
            title="Serial",
            description="Desc",
            severity=IncidentSeverity.high,
            category=IncidentCategory.misuse,
            source="https://example.com",
            reported_date=now,
            tags=["ai", "misuse"],
        )
        json_str = incident.model_dump_json()
        restored = SafetyIncident.model_validate_json(json_str)
        assert restored.incident_id == incident.incident_id
        assert restored.severity == incident.severity
        assert restored.tags == incident.tags

    def test_model_validate_from_dict(self) -> None:
        import json

        now = datetime.now(tz=UTC)
        incident = SafetyIncident(
            incident_id="INC-VAL",
            title="Validate",
            description="Desc",
            severity=IncidentSeverity.medium,
            category=IncidentCategory.hallucination,
            source="src",
            reported_date=now,
        )
        raw = json.loads(incident.model_dump_json())
        restored = SafetyIncident.model_validate(raw)
        assert restored.incident_id == "INC-VAL"


# ---------------------------------------------------------------------------
# IncidentTimeline
# ---------------------------------------------------------------------------


class TestIncidentTimeline:
    """Tests for the IncidentTimeline model."""

    def test_empty_timeline_defaults(self) -> None:
        timeline = IncidentTimeline()
        assert timeline.incidents == []
        assert timeline.total_count == 0
        assert timeline.earliest_date is None
        assert timeline.latest_date is None
        assert timeline.period_description == ""

    def test_sorted_incidents_returns_chronological_order(self) -> None:
        now = datetime.now(tz=UTC)
        from datetime import timedelta

        dates = [now - timedelta(days=d) for d in (10, 1, 5, 0, 20)]
        incidents = [
            SafetyIncident(
                incident_id=f"INC-{i}",
                title="T",
                description="D",
                severity=IncidentSeverity.low,
                category=IncidentCategory.other,
                source="src",
                reported_date=dt,
            )
            for i, dt in enumerate(dates)
        ]
        timeline = IncidentTimeline(incidents=incidents, total_count=len(incidents))
        sorted_list = timeline.sorted_incidents()
        for earlier, later in zip(sorted_list, sorted_list[1:], strict=False):
            assert earlier.reported_date <= later.reported_date

    def test_sorted_incidents_empty_list(self) -> None:
        timeline = IncidentTimeline()
        assert timeline.sorted_incidents() == []

    def test_sorted_incidents_single_element(self) -> None:
        now = datetime.now(tz=UTC)
        incident = SafetyIncident(
            incident_id="INC-SINGLE",
            title="T",
            description="D",
            severity=IncidentSeverity.low,
            category=IncidentCategory.other,
            source="src",
            reported_date=now,
        )
        timeline = IncidentTimeline(incidents=[incident], total_count=1)
        assert timeline.sorted_incidents() == [incident]


# ---------------------------------------------------------------------------
# DashboardStats
# ---------------------------------------------------------------------------


class TestDashboardStats:
    """Tests for the DashboardStats model."""

    def test_empty_defaults(self) -> None:
        stats = DashboardStats()
        assert stats.total_incidents == 0
        assert stats.by_severity == {}
        assert stats.by_category == {}
        assert stats.trend_30d == []
        assert stats.verified_count == 0
        assert stats.unverified_count == 0

    def test_construction_with_values(self) -> None:
        stats = DashboardStats(
            total_incidents=10,
            by_severity={"critical": 2, "high": 3, "medium": 5},
            by_category={"data_leak": 4, "other": 6},
            trend_30d=[{"date": "2025-01-01", "count": 3}],
            verified_count=7,
            unverified_count=3,
        )
        assert stats.total_incidents == 10
        assert stats.by_severity["critical"] == 2
        assert stats.verified_count == 7
        assert len(stats.trend_30d) == 1
