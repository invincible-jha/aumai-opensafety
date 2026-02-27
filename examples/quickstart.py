"""Quickstart examples for aumai-opensafety.

Demonstrates the core API: incident collection, auto-classification,
in-memory store queries, and temporal analysis.

Run this file directly to verify your installation:

    python examples/quickstart.py

No external network access or running server is required. All examples use
synthetic incident data defined inline.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

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
# Shared test data used across all demos
# ---------------------------------------------------------------------------

def _make_sample_incidents() -> list[SafetyIncident]:
    """Create a diverse set of synthetic safety incidents for demonstration."""
    now = datetime.now(tz=UTC)

    return [
        SafetyIncident(
            incident_id="INC-001",
            title="Medical AI hallucinated drug dosage",
            description=(
                "A medical advisory chatbot fabricated a dosage recommendation "
                "for a blood pressure medication that was twice the safe limit. "
                "Classified as a critical hallucination incident."
            ),
            severity=IncidentSeverity.critical,
            category=IncidentCategory.hallucination,
            source="https://example.com/safety-report-001",
            reported_date=now - timedelta(days=25),
            affected_systems=["medai-assistant-v3"],
            tags=["medical", "hallucination", "patient-safety"],
            verified=True,
        ),
        SafetyIncident(
            incident_id="INC-002",
            title="LLM jailbreak bypasses content safety filters",
            description=(
                "A prompt injection technique was used to circumvent the guardrails "
                "of a deployed model, allowing it to generate restricted content "
                "by overriding its safety filter configuration."
            ),
            severity=IncidentSeverity.high,
            category=IncidentCategory.safety_bypass,
            source="https://example.com/safety-report-002",
            reported_date=now - timedelta(days=20),
            affected_systems=["production-llm-v2", "api-gateway"],
            tags=["jailbreak", "prompt-injection", "guardrail", "content-filter"],
            verified=True,
        ),
        SafetyIncident(
            incident_id="INC-003",
            title="Training data memorization: PII exposed in responses",
            description=(
                "Users discovered that the model would reproduce verbatim text "
                "from training data including email addresses and phone numbers, "
                "constituting a privacy violation and data leak."
            ),
            severity=IncidentSeverity.high,
            category=IncidentCategory.data_leak,
            source="https://example.com/safety-report-003",
            reported_date=now - timedelta(days=15),
            affected_systems=["llm-service-eu"],
            tags=["pii", "privacy", "memorization", "training-data"],
            verified=False,
        ),
        SafetyIncident(
            incident_id="INC-004",
            title="Bias detected in job screening AI outputs",
            description=(
                "A study found significant demographic disparity in AI-assisted "
                "job screening tool outputs. The model produced discriminatory "
                "recommendations correlated with candidate gender and ethnicity."
            ),
            severity=IncidentSeverity.medium,
            category=IncidentCategory.bias,
            source="https://example.com/safety-report-004",
            reported_date=now - timedelta(days=10),
            affected_systems=["hr-screening-v1"],
            tags=["bias", "fairness", "demographic", "discrimination"],
            verified=True,
        ),
        SafetyIncident(
            incident_id="INC-005",
            title="Deepfake generation tool misused for fraud",
            description=(
                "An AI-powered video generation tool was weaponized to create "
                "deepfake videos used in financial scam campaigns targeting "
                "elderly users."
            ),
            severity=IncidentSeverity.critical,
            category=IncidentCategory.misuse,
            source="https://example.com/safety-report-005",
            reported_date=now - timedelta(days=5),
            affected_systems=["video-gen-api"],
            tags=["deepfake", "fraud", "scam", "misuse"],
            verified=True,
        ),
        SafetyIncident(
            incident_id="INC-006",
            title="Minor inference error in low-stakes classification",
            description=(
                "An edge case in the product classification model produces "
                "incorrect category assignments for a small subset of items "
                "with unusual naming conventions."
            ),
            severity=IncidentSeverity.low,
            category=IncidentCategory.model_failure,
            source="https://example.com/safety-report-006",
            reported_date=now - timedelta(days=3),
            affected_systems=["product-classifier-v4"],
            tags=["classification", "edge-case", "low-impact"],
            verified=False,
        ),
        SafetyIncident(
            incident_id="INC-007",
            title="Safety bypass via role-play framing",
            description=(
                "A bypass technique using fictional role-play framing was found "
                "to circumvent the model's restrictions on certain topics, "
                "overriding the safety filter through indirect instruction."
            ),
            severity=IncidentSeverity.high,
            category=IncidentCategory.safety_bypass,
            source="https://example.com/safety-report-007",
            reported_date=now - timedelta(days=2),
            affected_systems=["chat-assistant-v5"],
            tags=["jailbreak", "role-play", "bypass", "restriction-removed"],
            verified=True,
        ),
    ]


# ---------------------------------------------------------------------------
# Demo 1: Collecting and deduplicating incidents
# ---------------------------------------------------------------------------

def demo_incident_collection() -> IncidentCollector:
    """Show IncidentCollector's deduplication behaviour."""
    print("\n" + "=" * 60)
    print("Demo 1: Incident Collection and Deduplication")
    print("=" * 60)

    incidents = _make_sample_incidents()
    collector = IncidentCollector()

    # Add incidents one at a time
    for incident in incidents[:3]:
        is_new = collector.add(incident)
        print(f"  add({incident.incident_id}): new={is_new}")

    # Add the rest in bulk
    added_count = collector.bulk_import(incidents[3:])
    print(f"\nBulk import of {len(incidents) - 3} incidents: {added_count} newly added")

    # Demonstrate deduplication: re-importing all returns 0 new
    duplicate_count = collector.bulk_import(incidents)
    print(f"Re-importing all {len(incidents)} incidents: {duplicate_count} newly added (expected 0)")

    print(f"\nTotal unique incidents collected: {collector.count}")
    return collector


# ---------------------------------------------------------------------------
# Demo 2: Auto-classifying incidents from text
# ---------------------------------------------------------------------------

def demo_auto_classification() -> None:
    """Show IncidentClassifier inferring severity and category from text."""
    print("\n" + "=" * 60)
    print("Demo 2: Auto-Classification by Keyword Rules")
    print("=" * 60)

    classifier = IncidentClassifier()

    # Simulate incidents without pre-set severity/category
    raw_incident = SafetyIncident(
        incident_id="UNCLASSIFIED-001",
        title="Critical jailbreak vulnerability discovered",
        description=(
            "Researchers found a zero-day technique for bypassing the safety "
            "filter using prompt injection. Classified as critical because it "
            "enables remote code execution of arbitrary instructions."
        ),
        # These will be overwritten by the classifier
        severity=IncidentSeverity.low,
        category=IncidentCategory.other,
        source="https://example.com/research",
        reported_date=datetime.now(tz=UTC),
    )

    print(f"Before classification:")
    print(f"  severity : {raw_incident.severity.value}")
    print(f"  category : {raw_incident.category.value}")

    reclassified = classifier.reclassify(raw_incident)
    print(f"\nAfter classifier.reclassify():")
    print(f"  severity : {reclassified.severity.value}  (detected 'critical', 'rce')")
    print(f"  category : {reclassified.category.value}  (detected 'jailbreak', 'bypass')")
    print(f"\nOriginal incident is unchanged:")
    print(f"  severity : {raw_incident.severity.value}  (still 'low')")

    # Test individual classification methods
    test_cases = [
        ("Mass data exfiltration breach affecting millions", IncidentSeverity.critical),
        ("Model produced biased demographic outputs", IncidentSeverity.unknown if False else None),
        ("Minor edge case in cosmetic classifier", IncidentSeverity.low),
    ]

    print("\nSeverity classification examples:")
    for description_text, _ in test_cases:
        test_incident = SafetyIncident(
            incident_id="TEST",
            title=description_text,
            description=description_text,
            severity=IncidentSeverity.informational,
            category=IncidentCategory.other,
            source="test",
            reported_date=datetime.now(tz=UTC),
        )
        inferred = classifier.classify_severity(test_incident)
        print(f"  '{description_text[:50]}...' → {inferred.value}")


# ---------------------------------------------------------------------------
# Demo 3: Querying the incident store
# ---------------------------------------------------------------------------

def demo_incident_store(collector: IncidentCollector) -> IncidentStore:
    """Show the query and filter capabilities of IncidentStore."""
    print("\n" + "=" * 60)
    print("Demo 3: Incident Store Queries")
    print("=" * 60)

    store = IncidentStore()
    for incident in collector.all_incidents():
        store.add(incident)

    print(f"Store loaded with {store.count} incidents")

    # Filter by severity
    critical = store.filter_by_severity(IncidentSeverity.critical)
    print(f"\nCritical incidents: {len(critical)}")
    for inc in critical:
        print(f"  {inc.incident_id}: {inc.title[:50]}")

    # Filter by category
    bypasses = store.filter_by_category(IncidentCategory.safety_bypass)
    print(f"\nSafety bypass incidents: {len(bypasses)}")
    for inc in bypasses:
        print(f"  {inc.incident_id}: {inc.title[:50]}")

    # Filter verified only
    verified = store.filter_verified(verified=True)
    unverified = store.filter_verified(verified=False)
    print(f"\nVerified: {len(verified)}  |  Unverified: {len(unverified)}")

    # Full-text search
    results = store.search("jailbreak")
    print(f"\nSearch 'jailbreak': {len(results)} result(s)")
    for r in results:
        print(f"  {r.incident_id}: {r.title}")

    # Paginated query
    page_items, total = store.paginate(page=1, page_size=3)
    print(f"\nPage 1 (page_size=3): {len(page_items)} items of {total} total")
    for inc in page_items:
        print(f"  {inc.incident_id}: [{inc.severity.value}] {inc.title[:45]}...")

    return store


# ---------------------------------------------------------------------------
# Demo 4: Temporal analysis and dashboard statistics
# ---------------------------------------------------------------------------

def demo_temporal_analysis(store: IncidentStore) -> None:
    """Show TimelineAnalyzer building timelines and computing statistics."""
    print("\n" + "=" * 60)
    print("Demo 4: Temporal Analysis and Dashboard Statistics")
    print("=" * 60)

    analyzer = TimelineAnalyzer()
    incidents = store.all()

    # Build a timeline
    timeline = analyzer.build_timeline(incidents)
    print(f"Timeline built:")
    print(f"  period    : {timeline.period_description}")
    print(f"  earliest  : {timeline.earliest_date.date() if timeline.earliest_date else 'N/A'}")
    print(f"  latest    : {timeline.latest_date.date() if timeline.latest_date else 'N/A'}")
    print(f"  count     : {timeline.total_count}")

    print(f"\nIncidents in chronological order:")
    for inc in timeline.sorted_incidents():
        print(f"  {inc.reported_date.strftime('%Y-%m-%d')}  {inc.incident_id}  {inc.title[:45]}")

    # Daily incident counts
    daily = analyzer.incidents_per_day(incidents)
    print(f"\nIncidents per day (recent):")
    for date_str, count in list(daily.items())[-5:]:
        bar = "#" * count
        print(f"  {date_str}: {bar} ({count})")

    # Trending categories over last 30 days
    trending = analyzer.trending_categories(incidents, days=30)
    print(f"\nTrending categories (last 30 days):")
    for category_name, count in trending:
        print(f"  {category_name:<20} {count}")

    # Full dashboard statistics
    stats = analyzer.build_dashboard_stats(incidents)
    print(f"\nDashboard statistics:")
    print(f"  total_incidents  : {stats.total_incidents}")
    print(f"  verified_count   : {stats.verified_count}")
    print(f"  unverified_count : {stats.unverified_count}")
    print(f"\n  By severity:")
    for severity, count in sorted(stats.by_severity.items(), key=lambda x: -x[1]):
        print(f"    {severity:<15} {count}")
    print(f"\n  By category:")
    for category, count in sorted(stats.by_category.items(), key=lambda x: -x[1]):
        print(f"    {category:<20} {count}")
    print(f"\n  30-day trend data points: {len(stats.trend_30d)}")


# ---------------------------------------------------------------------------
# Demo 5: JSON round-trip serialization
# ---------------------------------------------------------------------------

def demo_serialization(store: IncidentStore) -> None:
    """Show Pydantic model serialization and deserialization."""
    print("\n" + "=" * 60)
    print("Demo 5: Serialization Round-Trip")
    print("=" * 60)

    # Take the first critical incident
    critical = store.filter_by_severity(IncidentSeverity.critical)
    incident = critical[0]

    # Serialize to dict (for JSON export)
    data = incident.model_dump(mode="json")
    print(f"Serialized incident '{incident.incident_id}':")
    print(f"  Keys: {list(data.keys())}")
    print(f"  severity field: '{data['severity']}'  (string, not enum)")
    print(f"  reported_date:  '{data['reported_date']}'  (ISO 8601 string)")

    # Deserialize back
    reloaded = SafetyIncident.model_validate(data)
    assert reloaded.incident_id == incident.incident_id
    assert reloaded.severity == incident.severity
    assert reloaded.reported_date == incident.reported_date
    print(f"\nRound-trip successful: {reloaded.incident_id} severity={reloaded.severity.value}")

    # Build and serialize DashboardStats
    analyzer = TimelineAnalyzer()
    stats = analyzer.build_dashboard_stats(store.all())
    stats_dict = stats.model_dump(mode="json")
    reloaded_stats = DashboardStats.model_validate(stats_dict)
    assert reloaded_stats.total_incidents == stats.total_incidents
    print(f"DashboardStats round-trip successful: {reloaded_stats.total_incidents} incidents")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run all quickstart demos."""
    print("aumai-opensafety Quickstart")
    print("=" * 60)
    print("Running 5 demos using synthetic safety incident data...\n")

    collector = demo_incident_collection()
    demo_auto_classification()
    store = demo_incident_store(collector)
    demo_temporal_analysis(store)
    demo_serialization(store)

    print("\n" + "=" * 60)
    print("All demos completed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    main()
