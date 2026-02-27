"""Tests for aumai_opensafety.core — classifier, collector, store, timeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

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
from tests.conftest import make_incident

# ===========================================================================
# IncidentClassifier
# ===========================================================================


class TestIncidentClassifierSeverity:
    """Tests for IncidentClassifier.classify_severity."""

    def test_critical_keyword_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Critical breach in production",
            description="A mass harm event occurred.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.critical

    def test_critical_keyword_in_description(self, classifier: IncidentClassifier) -> None:  # noqa: E501
        incident = make_incident(
            title="Incident report",
            description="Remote code execution was achieved via zero-day exploit.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.critical

    def test_high_keyword_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="High severity data leak",
            description="Unauthorized access to user records.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.high

    def test_medium_keyword_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Medium degradation observed",
            description="Incorrect output was returned for some queries.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.medium

    def test_low_keyword_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Minor edge case identified",
            description="Cosmetic rendering issue in the UI.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.low

    def test_informational_keyword_detected(self, classifier: IncidentClassifier) -> None:  # noqa: E501
        incident = make_incident(
            title="FYI: awareness note",
            description="An observation was made during routine testing.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.informational

    def test_no_keyword_defaults_to_informational(
        self, classifier: IncidentClassifier
    ) -> None:
        incident = make_incident(
            title="Completely unrelated heading",
            description="Nothing special happening here whatsoever.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.informational

    def test_case_insensitive_matching(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="CRITICAL BREACH DETECTED",
            description="EXFILTRATION of data occurred.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.critical

    def test_priority_order_critical_over_high(
        self, classifier: IncidentClassifier
    ) -> None:
        # Both "critical" and "high" present — critical must win.
        incident = make_incident(
            title="Critical and high severity event",
            description="Both breach and exposure noted.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.critical

    def test_multi_word_keyword_in_title(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Mass harm reported",
            description="Event unrelated otherwise.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.critical

    def test_rce_keyword_triggers_critical(self, classifier: IncidentClassifier) -> None:  # noqa: E501
        incident = make_incident(
            title="RCE found",
            description="Attacker used rce to gain shell access.",
        )
        assert classifier.classify_severity(incident) == IncidentSeverity.critical


class TestIncidentClassifierCategory:
    """Tests for IncidentClassifier.classify_category."""

    def test_model_failure_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Model failure in inference",
            description="The model crash caused service outage.",
        )
        assert classifier.classify_category(incident) == IncidentCategory.model_failure

    def test_data_leak_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="PII exposed to external parties",
            description="Training data leaked via memorization.",
        )
        assert classifier.classify_category(incident) == IncidentCategory.data_leak

    def test_bias_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Discriminatory output identified",
            description="Demographic disparity found in model recommendations.",
        )
        assert classifier.classify_category(incident) == IncidentCategory.bias

    def test_misuse_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Model weaponized for disinformation",
            description="Deepfake content generated using adversarial prompts.",
        )
        assert classifier.classify_category(incident) == IncidentCategory.misuse

    def test_safety_bypass_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Jailbreak successfully bypassed safety filter",
            description="Guardrail override using prompt injection.",
        )
        assert classifier.classify_category(incident) == IncidentCategory.safety_bypass

    def test_hallucination_detected(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Fabricated citation in legal summary",
            description="The model produced a fictional case reference.",
        )
        assert classifier.classify_category(incident) == IncidentCategory.hallucination

    def test_unknown_text_returns_other(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="Completely unrelated heading",
            description="Nothing that matches any rule.",
        )
        assert classifier.classify_category(incident) == IncidentCategory.other

    def test_case_insensitive_category(self, classifier: IncidentClassifier) -> None:
        incident = make_incident(
            title="JAILBREAK ATTEMPT",
            description="BYPASS of SAFETY FILTER confirmed.",
        )
        assert classifier.classify_category(incident) == IncidentCategory.safety_bypass


class TestIncidentClassifierReclassify:
    """Tests for IncidentClassifier.reclassify."""

    def test_reclassify_returns_new_instance(
        self, classifier: IncidentClassifier
    ) -> None:
        incident = make_incident(
            title="Critical breach",
            description="Data exfiltration occurred.",
            severity=IncidentSeverity.low,
            category=IncidentCategory.other,
        )
        reclassified = classifier.reclassify(incident)
        assert reclassified is not incident

    def test_reclassify_updates_severity(
        self, classifier: IncidentClassifier
    ) -> None:
        incident = make_incident(
            title="Critical zero-day exploit",
            description="Widespread breach confirmed.",
            severity=IncidentSeverity.low,
            category=IncidentCategory.other,
        )
        reclassified = classifier.reclassify(incident)
        assert reclassified.severity == IncidentSeverity.critical

    def test_reclassify_updates_category(
        self, classifier: IncidentClassifier
    ) -> None:
        incident = make_incident(
            title="Jailbreak attack",
            description="Prompt injection bypassed guardrail.",
            severity=IncidentSeverity.low,
            category=IncidentCategory.other,
        )
        reclassified = classifier.reclassify(incident)
        assert reclassified.category == IncidentCategory.safety_bypass

    def test_reclassify_preserves_other_fields(
        self, classifier: IncidentClassifier
    ) -> None:
        incident = make_incident(
            incident_id="INC-PRESERVE",
            title="Minor edge case",
            description="Low risk cosmetic issue.",
            tags=["ui", "edge-case"],
            verified=True,
        )
        reclassified = classifier.reclassify(incident)
        assert reclassified.incident_id == "INC-PRESERVE"
        assert reclassified.tags == ["ui", "edge-case"]
        assert reclassified.verified is True

    def test_reclassify_does_not_mutate_original(
        self, classifier: IncidentClassifier
    ) -> None:
        incident = make_incident(
            title="Minor issue",
            description="Low risk item.",
            severity=IncidentSeverity.critical,
        )
        original_severity = incident.severity
        classifier.reclassify(incident)
        assert incident.severity == original_severity


# ===========================================================================
# IncidentCollector
# ===========================================================================


class TestIncidentCollectorAdd:
    """Tests for IncidentCollector.add."""

    def test_add_new_incident_returns_true(
        self, collector: IncidentCollector
    ) -> None:
        incident = make_incident(incident_id="INC-001")
        assert collector.add(incident) is True

    def test_add_duplicate_returns_false(
        self, collector: IncidentCollector
    ) -> None:
        incident = make_incident(incident_id="INC-DUP")
        collector.add(incident)
        assert collector.add(incident) is False

    def test_add_duplicate_does_not_increase_count(
        self, collector: IncidentCollector
    ) -> None:
        incident = make_incident(incident_id="INC-CNT")
        collector.add(incident)
        collector.add(incident)
        assert collector.count == 1

    def test_add_different_incidents_increases_count(
        self, collector: IncidentCollector
    ) -> None:
        for i in range(5):
            collector.add(make_incident(incident_id=f"INC-{i:03d}"))
        assert collector.count == 5


class TestIncidentCollectorBulkImport:
    """Tests for IncidentCollector.bulk_import."""

    def test_bulk_import_returns_new_count(
        self, collector: IncidentCollector, sample_incidents: list[SafetyIncident]
    ) -> None:
        added = collector.bulk_import(sample_incidents)
        assert added == len(sample_incidents)

    def test_bulk_import_deduplicates(
        self, collector: IncidentCollector, sample_incidents: list[SafetyIncident]
    ) -> None:
        collector.bulk_import(sample_incidents)
        added_second_time = collector.bulk_import(sample_incidents)
        assert added_second_time == 0

    def test_bulk_import_partial_duplicates(
        self, collector: IncidentCollector
    ) -> None:
        existing = make_incident(incident_id="INC-EXIST")
        new_one = make_incident(incident_id="INC-NEW")
        collector.add(existing)
        added = collector.bulk_import([existing, new_one])
        assert added == 1

    def test_bulk_import_empty_list(
        self, collector: IncidentCollector
    ) -> None:
        assert collector.bulk_import([]) == 0

    def test_all_incidents_returns_all_added(
        self, collector: IncidentCollector, sample_incidents: list[SafetyIncident]
    ) -> None:
        collector.bulk_import(sample_incidents)
        all_ids = {i.incident_id for i in collector.all_incidents()}
        expected_ids = {i.incident_id for i in sample_incidents}
        assert all_ids == expected_ids


class TestIncidentCollectorBulkImportJson:
    """Tests for IncidentCollector.bulk_import_json."""

    def test_bulk_import_json_from_dicts(
        self,
        collector: IncidentCollector,
        sample_incidents_json: list[dict],
    ) -> None:
        added = collector.bulk_import_json(sample_incidents_json)
        assert added == len(sample_incidents_json)

    def test_bulk_import_json_deduplicates(
        self,
        collector: IncidentCollector,
        sample_incidents_json: list[dict],
    ) -> None:
        collector.bulk_import_json(sample_incidents_json)
        added_again = collector.bulk_import_json(sample_incidents_json)
        assert added_again == 0

    def test_bulk_import_json_invalid_schema_raises(
        self, collector: IncidentCollector
    ) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            collector.bulk_import_json([{"not_a_valid_field": True}])

    def test_bulk_import_json_empty_list(
        self, collector: IncidentCollector
    ) -> None:
        assert collector.bulk_import_json([]) == 0


class TestIncidentCollectorCount:
    """Tests for IncidentCollector.count property."""

    def test_count_starts_at_zero(self, collector: IncidentCollector) -> None:
        assert collector.count == 0

    def test_count_matches_unique_incidents(
        self, collector: IncidentCollector
    ) -> None:
        for i in range(3):
            collector.add(make_incident(incident_id=f"INC-{i}"))
        assert collector.count == 3


# ===========================================================================
# IncidentStore
# ===========================================================================


class TestIncidentStoreAdd:
    """Tests for IncidentStore.add and get."""

    def test_add_and_retrieve(self, store: IncidentStore) -> None:
        incident = make_incident(incident_id="INC-STORE-001")
        store.add(incident)
        retrieved = store.get("INC-STORE-001")
        assert retrieved is not None
        assert retrieved.incident_id == "INC-STORE-001"

    def test_get_missing_returns_none(self, store: IncidentStore) -> None:
        assert store.get("NONEXISTENT") is None

    def test_add_overwrites_existing(self, store: IncidentStore) -> None:
        original = make_incident(incident_id="INC-OW", title="Original")
        updated = make_incident(incident_id="INC-OW", title="Updated")
        store.add(original)
        store.add(updated)
        assert store.get("INC-OW").title == "Updated"  # type: ignore[union-attr]
        assert store.count == 1

    def test_count_increments(self, store: IncidentStore) -> None:
        for i in range(4):
            store.add(make_incident(incident_id=f"INC-{i}"))
        assert store.count == 4

    def test_all_returns_all_incidents(
        self, store: IncidentStore, sample_incidents: list[SafetyIncident]
    ) -> None:
        for inc in sample_incidents:
            store.add(inc)
        assert len(store.all()) == len(sample_incidents)

    def test_all_on_empty_store(self, store: IncidentStore) -> None:
        assert store.all() == []


class TestIncidentStoreFilterBySeverity:
    """Tests for IncidentStore.filter_by_severity."""

    def test_filter_returns_only_matching_severity(
        self, populated_store: IncidentStore
    ) -> None:
        results = populated_store.filter_by_severity(IncidentSeverity.critical)
        assert all(i.severity == IncidentSeverity.critical for i in results)

    def test_filter_returns_empty_when_no_match(
        self, store: IncidentStore
    ) -> None:
        store.add(make_incident(severity=IncidentSeverity.low))
        results = store.filter_by_severity(IncidentSeverity.critical)
        assert results == []

    def test_filter_all_severities_covered(
        self, populated_store: IncidentStore
    ) -> None:
        # Every severity in the populated store should be findable
        for severity in (
            IncidentSeverity.critical,
            IncidentSeverity.high,
            IncidentSeverity.medium,
            IncidentSeverity.low,
            IncidentSeverity.informational,
        ):
            results = populated_store.filter_by_severity(severity)
            assert len(results) >= 1, f"Expected at least one {severity} incident"


class TestIncidentStoreFilterByCategory:
    """Tests for IncidentStore.filter_by_category."""

    def test_filter_returns_only_matching_category(
        self, store: IncidentStore
    ) -> None:
        store.add(make_incident(incident_id="A", category=IncidentCategory.bias))
        store.add(make_incident(incident_id="B", category=IncidentCategory.misuse))
        results = store.filter_by_category(IncidentCategory.bias)
        assert len(results) == 1
        assert results[0].incident_id == "A"

    def test_filter_returns_empty_when_no_match(
        self, store: IncidentStore
    ) -> None:
        store.add(make_incident(category=IncidentCategory.other))
        assert store.filter_by_category(IncidentCategory.data_leak) == []


class TestIncidentStoreFilterVerified:
    """Tests for IncidentStore.filter_verified."""

    def test_filter_verified_true(
        self,
        store: IncidentStore,
        verified_incident: SafetyIncident,
        unverified_incident: SafetyIncident,
    ) -> None:
        store.add(verified_incident)
        store.add(unverified_incident)
        verified = store.filter_verified(verified=True)
        assert all(i.verified is True for i in verified)
        assert len(verified) == 1

    def test_filter_verified_false(
        self,
        store: IncidentStore,
        verified_incident: SafetyIncident,
        unverified_incident: SafetyIncident,
    ) -> None:
        store.add(verified_incident)
        store.add(unverified_incident)
        unverified = store.filter_verified(verified=False)
        assert all(i.verified is False for i in unverified)
        assert len(unverified) == 1

    def test_filter_verified_default_is_true(
        self,
        store: IncidentStore,
        verified_incident: SafetyIncident,
    ) -> None:
        store.add(verified_incident)
        # Default arg is True
        assert len(store.filter_verified()) == 1


class TestIncidentStoreSearch:
    """Tests for IncidentStore.search."""

    def test_search_matches_title(self, store: IncidentStore) -> None:
        store.add(make_incident(incident_id="A", title="Jailbreak discovered"))
        store.add(make_incident(incident_id="B", title="Model failure"))
        results = store.search("jailbreak")
        assert len(results) == 1
        assert results[0].incident_id == "A"

    def test_search_matches_description(self, store: IncidentStore) -> None:
        store.add(
            make_incident(
                incident_id="A",
                description="A prompt injection attack was detected.",
            )
        )
        store.add(make_incident(incident_id="B", description="Nothing relevant here."))
        results = store.search("prompt injection")
        assert len(results) == 1

    def test_search_matches_tags(self, store: IncidentStore) -> None:
        store.add(
            make_incident(incident_id="A", tags=["pii", "breach"])
        )
        results = store.search("pii")
        assert len(results) == 1

    def test_search_is_case_insensitive(self, store: IncidentStore) -> None:
        store.add(make_incident(incident_id="A", title="CRITICAL BREACH"))
        results = store.search("critical breach")
        assert len(results) == 1

    def test_search_no_match_returns_empty(self, store: IncidentStore) -> None:
        store.add(make_incident(incident_id="A", title="Unrelated incident"))
        assert store.search("nonexistent_term_xyz") == []

    def test_search_special_regex_chars_are_escaped(
        self, store: IncidentStore
    ) -> None:
        store.add(make_incident(incident_id="A", title="Error in model (v2.3)"))
        # The parentheses and dot must not be treated as regex metacharacters
        results = store.search("(v2.3)")
        assert len(results) == 1

    def test_search_returns_multiple_matches(self, store: IncidentStore) -> None:
        store.add(make_incident(incident_id="A", title="Bias in model A"))
        store.add(make_incident(incident_id="B", title="Bias in model B"))
        store.add(make_incident(incident_id="C", title="Unrelated"))
        results = store.search("bias")
        assert len(results) == 2


class TestIncidentStorePaginate:
    """Tests for IncidentStore.paginate."""

    def test_paginate_returns_correct_page_size(
        self, populated_store: IncidentStore
    ) -> None:
        items, total = populated_store.paginate(page=1, page_size=2)
        assert len(items) == 2
        assert total == populated_store.count

    def test_paginate_second_page(self, populated_store: IncidentStore) -> None:
        _, total = populated_store.paginate(page=1, page_size=2)
        items_p2, _ = populated_store.paginate(page=2, page_size=2)
        assert len(items_p2) <= 2

    def test_paginate_sorted_by_date_descending(
        self, store: IncidentStore
    ) -> None:
        now = datetime.now(tz=UTC)
        for days_ago in [10, 1, 5]:
            store.add(
                make_incident(
                    incident_id=f"INC-{days_ago}",
                    reported_date=now - timedelta(days=days_ago),
                )
            )
        items, _ = store.paginate()
        dates = [i.reported_date for i in items]
        assert dates == sorted(dates, reverse=True)

    def test_paginate_with_severity_filter(
        self, populated_store: IncidentStore
    ) -> None:
        items, total = populated_store.paginate(
            severity=IncidentSeverity.critical
        )
        assert all(i.severity == IncidentSeverity.critical for i in items)
        assert total == len(
            populated_store.filter_by_severity(IncidentSeverity.critical)
        )

    def test_paginate_with_category_filter(
        self, populated_store: IncidentStore
    ) -> None:
        items, total = populated_store.paginate(
            category=IncidentCategory.data_leak
        )
        assert all(i.category == IncidentCategory.data_leak for i in items)

    def test_paginate_with_verified_filter(
        self,
        store: IncidentStore,
        verified_incident: SafetyIncident,
        unverified_incident: SafetyIncident,
    ) -> None:
        store.add(verified_incident)
        store.add(unverified_incident)
        items, total = store.paginate(verified=True)
        assert total == 1
        assert items[0].verified is True

    def test_paginate_beyond_total_returns_empty(
        self, populated_store: IncidentStore
    ) -> None:
        items, _ = populated_store.paginate(page=999, page_size=100)
        assert items == []

    def test_paginate_all_filters_combined(
        self,
        store: IncidentStore,
        critical_incident: SafetyIncident,
        high_incident: SafetyIncident,
    ) -> None:
        store.add(critical_incident)
        store.add(high_incident)
        items, total = store.paginate(
            severity=IncidentSeverity.critical,
            category=IncidentCategory.data_leak,
            verified=True,
        )
        assert all(i.severity == IncidentSeverity.critical for i in items)
        assert all(i.category == IncidentCategory.data_leak for i in items)
        assert all(i.verified is True for i in items)

    def test_paginate_empty_store(self, store: IncidentStore) -> None:
        items, total = store.paginate()
        assert items == []
        assert total == 0


# ===========================================================================
# TimelineAnalyzer
# ===========================================================================


class TestTimelineAnalyzerBuildTimeline:
    """Tests for TimelineAnalyzer.build_timeline."""

    def test_empty_list_returns_empty_timeline(
        self, analyzer: TimelineAnalyzer
    ) -> None:
        timeline = analyzer.build_timeline([])
        assert timeline.total_count == 0
        assert timeline.incidents == []
        assert timeline.period_description == "No incidents"

    def test_single_incident_timeline(
        self, analyzer: TimelineAnalyzer, critical_incident: SafetyIncident
    ) -> None:
        timeline = analyzer.build_timeline([critical_incident])
        assert timeline.total_count == 1
        assert timeline.earliest_date == critical_incident.reported_date
        assert timeline.latest_date == critical_incident.reported_date
        assert "1 incidents over 0 days" in timeline.period_description

    def test_multiple_incidents_sorted(
        self,
        analyzer: TimelineAnalyzer,
        sample_incidents: list[SafetyIncident],
    ) -> None:
        timeline = analyzer.build_timeline(sample_incidents)
        dates = [i.reported_date for i in timeline.incidents]
        assert dates == sorted(dates)

    def test_total_count_matches_input(
        self,
        analyzer: TimelineAnalyzer,
        sample_incidents: list[SafetyIncident],
    ) -> None:
        timeline = analyzer.build_timeline(sample_incidents)
        assert timeline.total_count == len(sample_incidents)

    def test_earliest_and_latest_dates_correct(
        self,
        analyzer: TimelineAnalyzer,
        sample_incidents: list[SafetyIncident],
    ) -> None:
        timeline = analyzer.build_timeline(sample_incidents)
        all_dates = [i.reported_date for i in sample_incidents]
        assert timeline.earliest_date == min(all_dates)
        assert timeline.latest_date == max(all_dates)

    def test_period_description_contains_count_and_days(
        self,
        analyzer: TimelineAnalyzer,
        sample_incidents: list[SafetyIncident],
    ) -> None:
        timeline = analyzer.build_timeline(sample_incidents)
        assert str(len(sample_incidents)) in timeline.period_description
        assert "days" in timeline.period_description

    def test_unsorted_input_produces_sorted_timeline(
        self, analyzer: TimelineAnalyzer
    ) -> None:
        now = datetime.now(tz=UTC)
        incidents = [
            make_incident(
                incident_id=f"INC-{i}",
                reported_date=now - timedelta(days=i),
            )
            for i in [3, 1, 5, 0, 2]
        ]
        timeline = analyzer.build_timeline(incidents)
        dates = [i.reported_date for i in timeline.incidents]
        assert dates == sorted(dates)


class TestTimelineAnalyzerIncidentsPerDay:
    """Tests for TimelineAnalyzer.incidents_per_day."""

    def test_empty_list_returns_empty_dict(
        self, analyzer: TimelineAnalyzer
    ) -> None:
        assert analyzer.incidents_per_day([]) == {}

    def test_single_incident(
        self, analyzer: TimelineAnalyzer, critical_incident: SafetyIncident
    ) -> None:
        result = analyzer.incidents_per_day([critical_incident])
        day_key = critical_incident.reported_date.strftime("%Y-%m-%d")
        assert result[day_key] == 1

    def test_multiple_incidents_same_day(self, analyzer: TimelineAnalyzer) -> None:
        date = datetime(2025, 6, 15, tzinfo=UTC)
        incidents = [
            make_incident(incident_id=f"INC-{i}", reported_date=date)
            for i in range(3)
        ]
        result = analyzer.incidents_per_day(incidents)
        assert result["2025-06-15"] == 3

    def test_incidents_spread_across_days(
        self, analyzer: TimelineAnalyzer
    ) -> None:
        base = datetime(2025, 6, 1, tzinfo=UTC)
        incidents = [
            make_incident(
                incident_id=f"INC-{i}",
                reported_date=base + timedelta(days=i),
            )
            for i in range(5)
        ]
        result = analyzer.incidents_per_day(incidents)
        assert len(result) == 5
        assert all(v == 1 for v in result.values())

    def test_result_keys_are_sorted(self, analyzer: TimelineAnalyzer) -> None:
        base = datetime(2025, 1, 1, tzinfo=UTC)
        incidents = [
            make_incident(
                incident_id=f"INC-{i}",
                reported_date=base + timedelta(days=i * 10),
            )
            for i in [4, 1, 3, 2, 0]
        ]
        result = analyzer.incidents_per_day(incidents)
        keys = list(result.keys())
        assert keys == sorted(keys)

    def test_result_key_format_is_iso_date(self, analyzer: TimelineAnalyzer) -> None:
        import re

        date = datetime(2025, 12, 31, tzinfo=UTC)
        result = analyzer.incidents_per_day([make_incident(reported_date=date)])
        key = list(result.keys())[0]
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", key)


class TestTimelineAnalyzerTrendingCategories:
    """Tests for TimelineAnalyzer.trending_categories."""

    def test_empty_list_returns_empty(self, analyzer: TimelineAnalyzer) -> None:
        assert analyzer.trending_categories([]) == []

    def test_old_incidents_excluded(
        self,
        analyzer: TimelineAnalyzer,
        old_incident: SafetyIncident,
    ) -> None:
        # old_incident is 60 days old; default window is 30 days
        result = analyzer.trending_categories([old_incident])
        assert result == []

    def test_recent_incidents_included(
        self,
        analyzer: TimelineAnalyzer,
        critical_incident: SafetyIncident,
    ) -> None:
        result = analyzer.trending_categories([critical_incident])
        assert len(result) > 0
        categories = [cat for cat, _ in result]
        assert critical_incident.category.value in categories

    def test_sorted_descending_by_count(
        self, analyzer: TimelineAnalyzer
    ) -> None:
        now = datetime.now(tz=UTC)
        incidents = (
            [
                make_incident(
                    incident_id=f"BIAS-{i}",
                    category=IncidentCategory.bias,
                    reported_date=now,
                )
                for i in range(3)
            ]
            + [
                make_incident(
                    incident_id=f"MISUSE-{i}",
                    category=IncidentCategory.misuse,
                    reported_date=now,
                )
                for i in range(1)
            ]
        )
        result = analyzer.trending_categories(incidents)
        counts = [cnt for _, cnt in result]
        assert counts == sorted(counts, reverse=True)

    def test_custom_days_window(
        self,
        analyzer: TimelineAnalyzer,
        old_incident: SafetyIncident,
    ) -> None:
        # old_incident is 60 days old; with days=90 it should be included
        result = analyzer.trending_categories([old_incident], days=90)
        assert len(result) > 0


class TestTimelineAnalyzerBuildDashboardStats:
    """Tests for TimelineAnalyzer.build_dashboard_stats."""

    def test_empty_incidents_returns_zero_stats(
        self, analyzer: TimelineAnalyzer
    ) -> None:
        stats = analyzer.build_dashboard_stats([])
        assert stats.total_incidents == 0
        assert stats.verified_count == 0
        assert stats.unverified_count == 0
        assert stats.by_severity == {}
        assert stats.by_category == {}
        assert stats.trend_30d == []

    def test_total_incidents_count(
        self,
        analyzer: TimelineAnalyzer,
        sample_incidents: list[SafetyIncident],
    ) -> None:
        stats = analyzer.build_dashboard_stats(sample_incidents)
        assert stats.total_incidents == len(sample_incidents)

    def test_verified_unverified_counts(
        self,
        analyzer: TimelineAnalyzer,
        verified_incident: SafetyIncident,
        unverified_incident: SafetyIncident,
    ) -> None:
        stats = analyzer.build_dashboard_stats([verified_incident, unverified_incident])
        assert stats.verified_count == 1
        assert stats.unverified_count == 1

    def test_verified_plus_unverified_equals_total(
        self,
        analyzer: TimelineAnalyzer,
        sample_incidents: list[SafetyIncident],
    ) -> None:
        stats = analyzer.build_dashboard_stats(sample_incidents)
        assert stats.verified_count + stats.unverified_count == stats.total_incidents

    def test_by_severity_sums_to_total(
        self,
        analyzer: TimelineAnalyzer,
        sample_incidents: list[SafetyIncident],
    ) -> None:
        stats = analyzer.build_dashboard_stats(sample_incidents)
        assert sum(stats.by_severity.values()) == stats.total_incidents

    def test_by_category_sums_to_total(
        self,
        analyzer: TimelineAnalyzer,
        sample_incidents: list[SafetyIncident],
    ) -> None:
        stats = analyzer.build_dashboard_stats(sample_incidents)
        assert sum(stats.by_category.values()) == stats.total_incidents

    def test_trend_30d_excludes_old_incidents(
        self,
        analyzer: TimelineAnalyzer,
        old_incident: SafetyIncident,
    ) -> None:
        # old_incident is 60 days ago — must not appear in trend_30d
        stats = analyzer.build_dashboard_stats([old_incident])
        assert stats.trend_30d == []

    def test_trend_30d_includes_recent_incidents(
        self,
        analyzer: TimelineAnalyzer,
        critical_incident: SafetyIncident,
    ) -> None:
        stats = analyzer.build_dashboard_stats([critical_incident])
        assert len(stats.trend_30d) > 0
        day_key = critical_incident.reported_date.strftime("%Y-%m-%d")
        dates_in_trend = [entry["date"] for entry in stats.trend_30d]
        assert day_key in dates_in_trend

    def test_trend_30d_sorted_by_date(
        self, analyzer: TimelineAnalyzer
    ) -> None:
        now = datetime.now(tz=UTC)
        incidents = [
            make_incident(
                incident_id=f"INC-{i}",
                reported_date=now - timedelta(days=i),
            )
            for i in range(5)
        ]
        stats = analyzer.build_dashboard_stats(incidents)
        dates = [entry["date"] for entry in stats.trend_30d]
        assert dates == sorted(dates)
