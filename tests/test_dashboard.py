"""Tests for aumai_opensafety.dashboard — FastAPI routes and helpers."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aumai_opensafety.dashboard import create_app, load_into_store
from aumai_opensafety.models import (
    IncidentCategory,
    IncidentSeverity,
    SafetyIncident,
)
from tests.conftest import incident_to_dict, make_incident

# ===========================================================================
# GET /api/incidents — list with pagination and filters
# ===========================================================================


class TestListIncidents:
    """Tests for GET /api/incidents."""

    def test_returns_200(self, api_client: TestClient) -> None:
        response = api_client.get("/api/incidents")
        assert response.status_code == 200

    def test_response_schema(self, api_client: TestClient) -> None:
        data = api_client.get("/api/incidents").json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data

    def test_total_matches_seeded_count(
        self, api_client: TestClient, sample_incidents: list[SafetyIncident]
    ) -> None:
        data = api_client.get("/api/incidents").json()
        assert data["total"] == len(sample_incidents)

    def test_default_page_and_page_size(self, api_client: TestClient) -> None:
        data = api_client.get("/api/incidents").json()
        assert data["page"] == 1
        assert data["page_size"] == 20

    def test_custom_page_size(self, api_client: TestClient) -> None:
        data = api_client.get("/api/incidents?page_size=2").json()
        assert data["page_size"] == 2
        assert len(data["items"]) == 2

    def test_page_2_returns_remaining_items(
        self, api_client: TestClient, sample_incidents: list[SafetyIncident]
    ) -> None:
        total = len(sample_incidents)
        page_size = 2
        data = api_client.get(
            f"/api/incidents?page=2&page_size={page_size}"
        ).json()
        # Page 2 holds items [page_size..2*page_size), capped at total.
        expected_on_page_2 = min(page_size, total - page_size)
        assert len(data["items"]) == expected_on_page_2

    def test_filter_by_severity(self, api_client: TestClient) -> None:
        data = api_client.get(
            "/api/incidents?severity=critical"
        ).json()
        assert all(
            item["severity"] == "critical" for item in data["items"]
        )

    def test_filter_by_category(self, api_client: TestClient) -> None:
        data = api_client.get(
            "/api/incidents?category=data_leak"
        ).json()
        assert all(
            item["category"] == "data_leak" for item in data["items"]
        )

    def test_filter_verified_true(self, api_client: TestClient) -> None:
        data = api_client.get("/api/incidents?verified=true").json()
        assert all(item["verified"] is True for item in data["items"])

    def test_filter_verified_false(self, api_client: TestClient) -> None:
        data = api_client.get("/api/incidents?verified=false").json()
        assert all(item["verified"] is False for item in data["items"])

    def test_page_less_than_1_returns_422(self, api_client: TestClient) -> None:
        response = api_client.get("/api/incidents?page=0")
        assert response.status_code == 422

    def test_page_size_greater_than_100_returns_422(
        self, api_client: TestClient
    ) -> None:
        response = api_client.get("/api/incidents?page_size=101")
        assert response.status_code == 422

    def test_invalid_severity_value_returns_422(
        self, api_client: TestClient
    ) -> None:
        response = api_client.get("/api/incidents?severity=not_a_severity")
        assert response.status_code == 422

    def test_empty_store_returns_zero_total(
        self, empty_api_client: TestClient
    ) -> None:
        data = empty_api_client.get("/api/incidents").json()
        assert data["total"] == 0
        assert data["items"] == []


# ===========================================================================
# GET /api/incidents/{incident_id}
# ===========================================================================


class TestGetIncident:
    """Tests for GET /api/incidents/{incident_id}."""

    def test_returns_correct_incident(
        self,
        api_client: TestClient,
        critical_incident: SafetyIncident,
    ) -> None:
        response = api_client.get(f"/api/incidents/{critical_incident.incident_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["incident_id"] == critical_incident.incident_id

    def test_returns_all_fields(
        self,
        api_client: TestClient,
        critical_incident: SafetyIncident,
    ) -> None:
        response = api_client.get(f"/api/incidents/{critical_incident.incident_id}")
        data = response.json()
        assert "incident_id" in data
        assert "title" in data
        assert "description" in data
        assert "severity" in data
        assert "category" in data
        assert "source" in data
        assert "reported_date" in data
        assert "verified" in data

    def test_not_found_returns_404(self, api_client: TestClient) -> None:
        response = api_client.get("/api/incidents/NONEXISTENT-ID-999")
        assert response.status_code == 404

    def test_404_detail_contains_incident_id(self, api_client: TestClient) -> None:
        response = api_client.get("/api/incidents/MISSING-ID")
        data = response.json()
        assert "MISSING-ID" in data["detail"]


# ===========================================================================
# POST /api/incidents
# ===========================================================================


class TestCreateIncident:
    """Tests for POST /api/incidents."""

    def test_create_incident_returns_201(
        self, empty_api_client: TestClient
    ) -> None:
        incident = make_incident(incident_id="INC-NEW-001")
        payload = {
            "incident": incident_to_dict(incident),
            "auto_classify": False,
        }
        response = empty_api_client.post("/api/incidents", json=payload)
        assert response.status_code == 201

    def test_created_incident_is_retrievable(
        self, empty_api_client: TestClient
    ) -> None:
        incident = make_incident(incident_id="INC-POST-001")
        payload = {
            "incident": incident_to_dict(incident),
            "auto_classify": False,
        }
        empty_api_client.post("/api/incidents", json=payload)
        response = empty_api_client.get("/api/incidents/INC-POST-001")
        assert response.status_code == 200

    def test_auto_classify_true_reclassifies_severity(
        self, empty_api_client: TestClient
    ) -> None:
        # Incident text strongly matches "critical" but original severity is low.
        incident = make_incident(
            incident_id="INC-AUTOCLASSIFY",
            title="Critical zero-day breach detected",
            description="Remote code execution via exfiltration.",
            severity=IncidentSeverity.low,
            category=IncidentCategory.other,
        )
        payload = {
            "incident": incident_to_dict(incident),
            "auto_classify": True,
        }
        response = empty_api_client.post("/api/incidents", json=payload)
        assert response.status_code == 201
        data = response.json()
        # After auto-classification, severity should be upgraded.
        assert data["severity"] == "critical"

    def test_auto_classify_false_preserves_original_severity(
        self, empty_api_client: TestClient
    ) -> None:
        incident = make_incident(
            incident_id="INC-NOCLASSIFY",
            title="Critical breach",
            description="Remote code execution.",
            severity=IncidentSeverity.low,
        )
        payload = {
            "incident": incident_to_dict(incident),
            "auto_classify": False,
        }
        response = empty_api_client.post("/api/incidents", json=payload)
        data = response.json()
        assert data["severity"] == "low"

    def test_response_body_matches_stored_incident(
        self, empty_api_client: TestClient
    ) -> None:
        incident = make_incident(
            incident_id="INC-BODY-MATCH",
            title="Test match",
            tags=["tag1", "tag2"],
        )
        payload = {
            "incident": incident_to_dict(incident),
            "auto_classify": False,
        }
        post_response = empty_api_client.post("/api/incidents", json=payload)
        get_response = empty_api_client.get("/api/incidents/INC-BODY-MATCH")
        assert post_response.json()["incident_id"] == get_response.json()["incident_id"]

    def test_missing_required_fields_returns_422(
        self, empty_api_client: TestClient
    ) -> None:
        response = empty_api_client.post(
            "/api/incidents",
            json={"incident": {"title": "Missing fields"}},
        )
        assert response.status_code == 422

    def test_create_with_all_severity_levels(
        self, empty_api_client: TestClient
    ) -> None:
        for i, severity in enumerate(IncidentSeverity):
            incident = make_incident(
                incident_id=f"INC-SEV-{i}",
                severity=severity,
                # Title/description must not match any keyword to keep severity
                title="No keyword whatsoever",
                description="Nothing special.",
            )
            payload = {
                "incident": incident_to_dict(incident),
                "auto_classify": False,
            }
            response = empty_api_client.post("/api/incidents", json=payload)
            assert response.status_code == 201
            assert response.json()["severity"] == severity.value


# ===========================================================================
# GET /api/stats
# ===========================================================================


class TestGetStats:
    """Tests for GET /api/stats."""

    def test_returns_200(self, api_client: TestClient) -> None:
        assert api_client.get("/api/stats").status_code == 200

    def test_response_schema(self, api_client: TestClient) -> None:
        data = api_client.get("/api/stats").json()
        assert "total_incidents" in data
        assert "by_severity" in data
        assert "by_category" in data
        assert "trend_30d" in data
        assert "verified_count" in data
        assert "unverified_count" in data

    def test_total_incidents_matches_seed(
        self, api_client: TestClient, sample_incidents: list[SafetyIncident]
    ) -> None:
        data = api_client.get("/api/stats").json()
        assert data["total_incidents"] == len(sample_incidents)

    def test_verified_plus_unverified_equals_total(
        self, api_client: TestClient
    ) -> None:
        data = api_client.get("/api/stats").json()
        assert (
            data["verified_count"] + data["unverified_count"]
            == data["total_incidents"]
        )

    def test_by_severity_is_dict_of_ints(self, api_client: TestClient) -> None:
        data = api_client.get("/api/stats").json()
        for value in data["by_severity"].values():
            assert isinstance(value, int)

    def test_trend_30d_is_list_of_dicts(self, api_client: TestClient) -> None:
        data = api_client.get("/api/stats").json()
        assert isinstance(data["trend_30d"], list)

    def test_empty_store_returns_zeros(
        self, empty_api_client: TestClient
    ) -> None:
        data = empty_api_client.get("/api/stats").json()
        assert data["total_incidents"] == 0
        assert data["verified_count"] == 0
        assert data["unverified_count"] == 0


# ===========================================================================
# GET /api/timeline
# ===========================================================================


class TestGetTimeline:
    """Tests for GET /api/timeline."""

    def test_returns_200(self, api_client: TestClient) -> None:
        assert api_client.get("/api/timeline").status_code == 200

    def test_response_schema(self, api_client: TestClient) -> None:
        data = api_client.get("/api/timeline").json()
        assert "incidents" in data
        assert "total_count" in data
        assert "period_description" in data

    def test_total_count_matches_seed(
        self, api_client: TestClient, sample_incidents: list[SafetyIncident]
    ) -> None:
        data = api_client.get("/api/timeline").json()
        assert data["total_count"] == len(sample_incidents)

    def test_incidents_sorted_ascending_by_date(
        self, api_client: TestClient
    ) -> None:
        data = api_client.get("/api/timeline").json()
        dates = [item["reported_date"] for item in data["incidents"]]
        assert dates == sorted(dates)

    def test_empty_store_returns_no_incidents(
        self, empty_api_client: TestClient
    ) -> None:
        data = empty_api_client.get("/api/timeline").json()
        assert data["incidents"] == []
        assert data["total_count"] == 0


# ===========================================================================
# GET /api/search
# ===========================================================================


class TestSearchIncidents:
    """Tests for GET /api/search."""

    def test_search_returns_matching_incidents(
        self, api_client: TestClient, critical_incident: SafetyIncident
    ) -> None:
        # Search for a term from the critical incident's title
        query_term = "prompt injection"
        response = api_client.get(f"/api/search?query={query_term}")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_search_no_results_returns_empty_list(
        self, api_client: TestClient
    ) -> None:
        response = api_client.get("/api/search?query=xyzzy_no_match_99999")
        assert response.status_code == 200
        assert response.json() == []

    def test_search_missing_query_returns_422(
        self, api_client: TestClient
    ) -> None:
        response = api_client.get("/api/search")
        assert response.status_code == 422

    def test_search_empty_query_returns_422(
        self, api_client: TestClient
    ) -> None:
        # min_length=1 enforced by Query param
        response = api_client.get("/api/search?query=")
        assert response.status_code == 422

    def test_search_returns_list_type(self, api_client: TestClient) -> None:
        response = api_client.get("/api/search?query=model")
        assert isinstance(response.json(), list)

    def test_search_results_contain_incident_fields(
        self, api_client: TestClient
    ) -> None:
        response = api_client.get("/api/search?query=breach")
        data = response.json()
        if data:
            item = data[0]
            assert "incident_id" in item
            assert "title" in item
            assert "severity" in item


# ===========================================================================
# create_app factory
# ===========================================================================


class TestCreateAppFactory:
    """Tests for the create_app factory function."""

    def test_create_app_returns_fastapi_instance(self) -> None:
        from fastapi import FastAPI

        fresh_app = create_app()
        assert isinstance(fresh_app, FastAPI)

    def test_create_app_with_initial_incidents(
        self, sample_incidents: list[SafetyIncident]
    ) -> None:
        fresh_app = create_app(initial_incidents=sample_incidents)
        client = TestClient(fresh_app)
        data = client.get("/api/incidents").json()
        assert data["total"] == len(sample_incidents)

    def test_create_app_no_incidents_starts_empty(self) -> None:
        fresh_app = create_app()
        client = TestClient(fresh_app)
        data = client.get("/api/incidents").json()
        assert data["total"] == 0

    def test_create_app_resets_store_between_calls(
        self, sample_incidents: list[SafetyIncident]
    ) -> None:
        # First app seeded with data.
        create_app(initial_incidents=sample_incidents)
        # Second call with no incidents — store must be empty.
        fresh_app = create_app()
        client = TestClient(fresh_app)
        data = client.get("/api/incidents").json()
        assert data["total"] == 0

    def test_create_app_deduplicates_initial_incidents(self) -> None:
        incident = make_incident(incident_id="INC-DEDUP")
        # Passing the same incident twice — must not double-count.
        fresh_app = create_app(initial_incidents=[incident, incident])
        client = TestClient(fresh_app)
        data = client.get("/api/incidents").json()
        assert data["total"] == 1


# ===========================================================================
# load_into_store helper
# ===========================================================================


class TestLoadIntoStore:
    """Tests for the load_into_store helper."""

    def test_load_valid_incidents_returns_count(
        self, sample_incidents_json: list[dict]
    ) -> None:
        # Ensure the store starts fresh for this test.
        create_app()
        count = load_into_store(sample_incidents_json)
        assert count == len(sample_incidents_json)

    def test_load_empty_list_returns_zero(self) -> None:
        create_app()
        assert load_into_store([]) == 0

    def test_load_invalid_schema_raises(self) -> None:
        from pydantic import ValidationError

        create_app()
        with pytest.raises(ValidationError):
            load_into_store([{"invalid": "data"}])
