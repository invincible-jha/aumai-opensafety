"""FastAPI dashboard for AI safety incidents."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel

from aumai_opensafety.core import (
    IncidentClassifier,
    IncidentCollector,
    IncidentStore,
    TimelineAnalyzer,
)
from aumai_opensafety.models import (
    DashboardStats,
    IncidentCategory,
    IncidentSeverity,
    IncidentTimeline,
    SafetyIncident,
)

# ---------------------------------------------------------------------------
# Shared application state
# ---------------------------------------------------------------------------

_store = IncidentStore()
_analyzer = TimelineAnalyzer()
_classifier = IncidentClassifier()

app = FastAPI(
    title="AumAI OpenSafety Dashboard",
    description="AI Safety Incident Aggregator — REST API",
    version="0.1.0",
)


def get_store() -> IncidentStore:
    """FastAPI dependency that returns the global incident store."""
    return _store


# ---------------------------------------------------------------------------
# Request/Response schemas
# ---------------------------------------------------------------------------


class IncidentListResponse(BaseModel):
    """Paginated list of incidents."""

    items: list[SafetyIncident]
    total: int
    page: int
    page_size: int


class ReportIncidentRequest(BaseModel):
    """Request body for reporting a new incident."""

    incident: SafetyIncident
    auto_classify: bool = True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get(
    "/api/incidents",
    response_model=IncidentListResponse,
    summary="List incidents with pagination and filters",
)
def list_incidents(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    severity: Annotated[IncidentSeverity | None, Query()] = None,
    category: Annotated[IncidentCategory | None, Query()] = None,
    verified: Annotated[bool | None, Query()] = None,
    store: IncidentStore = Depends(get_store),  # noqa: B008
) -> IncidentListResponse:
    """Return a paginated, optionally filtered list of safety incidents."""
    items, total = store.paginate(
        page=page,
        page_size=page_size,
        severity=severity,
        category=category,
        verified=verified,
    )
    return IncidentListResponse(
        items=items, total=total, page=page, page_size=page_size
    )


@app.get(
    "/api/incidents/{incident_id}",
    response_model=SafetyIncident,
    summary="Get a single incident by ID",
)
def get_incident(
    incident_id: str,
    store: IncidentStore = Depends(get_store),  # noqa: B008
) -> SafetyIncident:
    """Retrieve a single incident by its ID."""
    incident = store.get(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=404, detail=f"Incident {incident_id!r} not found"
        )
    return incident


@app.post(
    "/api/incidents",
    response_model=SafetyIncident,
    status_code=201,
    summary="Report a new safety incident",
)
def create_incident(
    request: ReportIncidentRequest,
    store: IncidentStore = Depends(get_store),  # noqa: B008
) -> SafetyIncident:
    """Submit a new safety incident. Optionally auto-classifies severity/category."""
    incident = request.incident
    if request.auto_classify:
        incident = _classifier.reclassify(incident)
    store.add(incident)
    return incident


@app.get(
    "/api/stats",
    response_model=DashboardStats,
    summary="Dashboard aggregate statistics",
)
def get_stats(
    store: IncidentStore = Depends(get_store),  # noqa: B008
) -> DashboardStats:
    """Return aggregate statistics for the dashboard."""
    return _analyzer.build_dashboard_stats(store.all())


@app.get(
    "/api/timeline",
    response_model=IncidentTimeline,
    summary="Incident timeline ordered by date",
)
def get_timeline(
    store: IncidentStore = Depends(get_store),  # noqa: B008
) -> IncidentTimeline:
    """Return incidents sorted chronologically with summary statistics."""
    return _analyzer.build_timeline(store.all())


@app.get(
    "/api/search",
    response_model=list[SafetyIncident],
    summary="Full-text search across incidents",
)
def search_incidents(
    query: Annotated[str, Query(min_length=1)],
    store: IncidentStore = Depends(get_store),  # noqa: B008
) -> list[SafetyIncident]:
    """Search incidents by keyword across title, description, and tags."""
    return store.search(query)


def create_app(initial_incidents: list[SafetyIncident] | None = None) -> FastAPI:
    """Factory to create a dashboard app with optional seed data.

    Useful for testing and programmatic embedding.
    """
    global _store  # noqa: PLW0603
    _store = IncidentStore()
    if initial_incidents:
        collector = IncidentCollector()
        collector.bulk_import(initial_incidents)
        for incident in collector.all_incidents():
            _store.add(incident)
    return app


def load_into_store(incidents: list[dict[str, Any]]) -> int:
    """Helper: deserialize and load raw dicts into the global store."""
    collector = IncidentCollector()
    count = collector.bulk_import_json(incidents)
    for incident in collector.all_incidents():
        _store.add(incident)
    return count


__all__ = [
    "app",
    "create_app",
    "load_into_store",
]
