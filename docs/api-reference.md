# API Reference — aumai-opensafety

Complete reference for all public classes, functions, and models in `aumai-opensafety`.

---

## Module: `aumai_opensafety.models`

Pydantic data models for AI safety incident tracking. All models are validated at
instantiation time.

---

### `IncidentSeverity`

```python
class IncidentSeverity(str, Enum):
```

Severity classification for AI safety incidents.

**Values:**

| Value | String | Description |
|---|---|---|
| `IncidentSeverity.critical` | `"critical"` | Severe harm potential; immediate action required |
| `IncidentSeverity.high` | `"high"` | Significant risk; prioritized response needed |
| `IncidentSeverity.medium` | `"medium"` | Moderate impact; addressed in normal workflow |
| `IncidentSeverity.low` | `"low"` | Minor impact; tracked for trend purposes |
| `IncidentSeverity.informational` | `"informational"` | Observation only; no action required |

Being a `str` Enum, values serialize to their string representation in JSON and are
accepted as input strings in Pydantic validation.

---

### `IncidentCategory`

```python
class IncidentCategory(str, Enum):
```

Category classification for AI safety incidents.

**Values:**

| Value | String | Description |
|---|---|---|
| `IncidentCategory.model_failure` | `"model_failure"` | Model crash, inference error, or performance degradation |
| `IncidentCategory.data_leak` | `"data_leak"` | PII exposure, training data memorization, privacy violation |
| `IncidentCategory.bias` | `"bias"` | Discriminatory, unfair, or stereotyping outputs |
| `IncidentCategory.misuse` | `"misuse"` | Adversarial use, disinformation, fraud, deepfakes |
| `IncidentCategory.safety_bypass` | `"safety_bypass"` | Jailbreaks, prompt injection, guardrail circumvention |
| `IncidentCategory.hallucination` | `"hallucination"` | Fabricated facts, incorrect citations, invented information |
| `IncidentCategory.other` | `"other"` | Does not fit the above categories |

---

### `SafetyIncident`

```python
class SafetyIncident(BaseModel):
```

Represents a single AI safety incident or near-miss report.

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `incident_id` | `str` | Yes | Unique identifier for the incident. Used for deduplication. |
| `title` | `str` | Yes | Short descriptive title (typically 5–15 words). |
| `description` | `str` | Yes | Full incident description. Used by `IncidentClassifier`. |
| `severity` | `IncidentSeverity` | Yes | Severity level. |
| `category` | `IncidentCategory` | Yes | Incident category. |
| `source` | `str` | Yes | URL or name of the reporting source. |
| `reported_date` | `datetime` | Yes | Date/time the incident was reported. Used for timeline and trend analysis. |
| `affected_systems` | `list[str]` | No | Names of AI systems involved. Defaults to `[]`. |
| `tags` | `list[str]` | No | Free-form tags for search and filtering. Defaults to `[]`. |
| `verified` | `bool` | No | Whether the incident has been verified. Defaults to `False`. |

**Example:**

```python
from datetime import datetime, UTC
from aumai_opensafety.models import SafetyIncident, IncidentSeverity, IncidentCategory

incident = SafetyIncident(
    incident_id="INC-2025-001",
    title="Medical AI fabricated drug dosage recommendation",
    description=(
        "A medical advisory system produced a fabricated dosage recommendation "
        "for a common antibiotic that contradicted clinical guidelines, "
        "potentially endangering patients."
    ),
    severity=IncidentSeverity.critical,
    category=IncidentCategory.hallucination,
    source="https://example.com/ai-safety-report-001",
    reported_date=datetime(2025, 1, 15, tzinfo=UTC),
    affected_systems=["medai-assistant-v3"],
    tags=["medical", "hallucination", "patient-safety", "antibiotic"],
    verified=True,
)
```

---

### `IncidentTimeline`

```python
class IncidentTimeline(BaseModel):
```

A chronologically sorted collection of safety incidents with summary statistics.
Produced by `TimelineAnalyzer.build_timeline()`.

**Fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `incidents` | `list[SafetyIncident]` | `[]` | The incidents in this timeline. |
| `total_count` | `int` | `0` | Total number of incidents. |
| `earliest_date` | `datetime \| None` | `None` | Date of the earliest incident. |
| `latest_date` | `datetime \| None` | `None` | Date of the most recent incident. |
| `period_description` | `str` | `""` | Human-readable summary, e.g. `"47 incidents over 183 days"`. |

**Methods:**

#### `sorted_incidents() -> list[SafetyIncident]`

Return the incidents sorted by `reported_date` ascending.

**Returns:** `list[SafetyIncident]`

**Example:**

```python
timeline = analyzer.build_timeline(incidents)
print(timeline.period_description)
for inc in timeline.sorted_incidents():
    print(f"  {inc.reported_date.date()} — {inc.title}")
```

---

### `DashboardStats`

```python
class DashboardStats(BaseModel):
```

Aggregate statistics for the safety incident dashboard. Produced by
`TimelineAnalyzer.build_dashboard_stats()`.

**Fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `total_incidents` | `int` | `0` | Total number of incidents in the dataset. |
| `by_severity` | `dict[str, int]` | `{}` | Count of incidents by severity string key, e.g. `{"critical": 5, "high": 12}`. |
| `by_category` | `dict[str, int]` | `{}` | Count of incidents by category string key. |
| `trend_30d` | `list[dict[str, Any]]` | `[]` | Daily incident counts for the last 30 days. Each entry: `{"date": "YYYY-MM-DD", "count": N}`. |
| `verified_count` | `int` | `0` | Number of verified incidents. |
| `unverified_count` | `int` | `0` | Number of unverified incidents. |

**Example:**

```python
stats = analyzer.build_dashboard_stats(store.all())
print(f"Total: {stats.total_incidents}")
print(f"Critical: {stats.by_severity.get('critical', 0)}")

# Render 30-day trend as ASCII chart
for entry in stats.trend_30d[-7:]:  # last 7 days
    bar = "#" * entry["count"]
    print(f"  {entry['date']}: {bar} ({entry['count']})")
```

---

## Module: `aumai_opensafety.core`

The four main operational classes for incident collection, storage, classification, and
analysis.

---

### `IncidentClassifier`

```python
class IncidentClassifier:
```

Classifies safety incidents by severity and category using keyword-matching rules.
The keyword tables are defined at module level in `core.py` and cover the most common
AI safety incident vocabulary in English.

**Constructor:**

```python
IncidentClassifier()
```

No arguments. Stateless.

**Severity keyword table** (priority order):

| Severity | Keywords (partial list) |
|---|---|
| `critical` | `"critical"`, `"catastrophic"`, `"mass harm"`, `"breach"`, `"exfiltration"`, `"rce"`, `"zero-day"` |
| `high` | `"high"`, `"severe"`, `"dangerous"`, `"exploit"`, `"unauthorized access"`, `"data leak"` |
| `medium` | `"medium"`, `"moderate"`, `"incorrect output"`, `"misleading"`, `"bias detected"` |
| `low` | `"low"`, `"minor"`, `"minimal"`, `"edge case"` |
| `informational` | `"informational"`, `"observation"`, `"fyi"`, `"awareness"` |

**Category keyword table** (partial list):

| Category | Keywords |
|---|---|
| `model_failure` | `"model failure"`, `"inference error"`, `"performance degradation"` |
| `data_leak` | `"data leak"`, `"pii exposed"`, `"memorization"`, `"privacy"` |
| `bias` | `"bias"`, `"discriminatory"`, `"stereotype"`, `"demographic"` |
| `misuse` | `"misuse"`, `"adversarial"`, `"disinformation"`, `"deepfake"`, `"fraud"` |
| `safety_bypass` | `"jailbreak"`, `"bypass"`, `"prompt injection"`, `"guardrail"`, `"circumvent"` |
| `hallucination` | `"hallucination"`, `"fabricated"`, `"invented"`, `"false fact"` |

---

#### `classify_severity(incident: SafetyIncident) -> IncidentSeverity`

Infer severity from the incident's `title` and `description` via keyword matching.

**Parameters:**
- `incident` (`SafetyIncident`)

**Returns:** `IncidentSeverity` — The first matching severity level in priority order
(`critical` > `high` > `medium` > `low` > `informational`). Returns `informational` if
no keyword matches.

**Example:**

```python
classifier = IncidentClassifier()
severity = classifier.classify_severity(incident)
# Incident with "catastrophic" in description → IncidentSeverity.critical
```

---

#### `classify_category(incident: SafetyIncident) -> IncidentCategory`

Infer category from the incident's `title` and `description` via keyword matching.

**Parameters:**
- `incident` (`SafetyIncident`)

**Returns:** `IncidentCategory` — The first matching category. Returns
`IncidentCategory.other` if no keyword matches.

---

#### `reclassify(incident: SafetyIncident) -> SafetyIncident`

Return a new `SafetyIncident` with `severity` and `category` replaced by the
classifier's inferences. The original incident is not mutated.

**Parameters:**
- `incident` (`SafetyIncident`)

**Returns:** `SafetyIncident` — A new instance (Pydantic `model_copy(update={...})`)
with updated `severity` and `category`.

**Example:**

```python
# Both fields will be overwritten regardless of their original values
reclassified = classifier.reclassify(raw_incident)
print(reclassified.severity)   # inferred
print(reclassified.category)   # inferred
print(raw_incident.severity)   # unchanged
```

---

### `IncidentCollector`

```python
class IncidentCollector:
```

Collects and deduplicates `SafetyIncident` objects. Use this as the ingestion entry
point when importing from external sources.

**Constructor:**

```python
IncidentCollector()
```

Starts with an empty collection.

---

#### `add(incident: SafetyIncident) -> bool`

Add a single incident. Silently ignores duplicates.

**Parameters:**
- `incident` (`SafetyIncident`)

**Returns:** `bool` — `True` if the incident was newly added; `False` if an incident
with the same `incident_id` was already present.

---

#### `bulk_import(incidents: list[SafetyIncident]) -> int`

Add a list of incidents. Duplicates are silently ignored.

**Parameters:**
- `incidents` (`list[SafetyIncident]`)

**Returns:** `int` — Count of newly added incidents.

---

#### `bulk_import_json(data: list[dict[str, Any]]) -> int`

Deserialize a JSON array of incident dicts and import them.

**Parameters:**
- `data` (`list[dict[str, Any]]`) — List of raw incident dicts matching the
  `SafetyIncident` schema.

**Returns:** `int` — Count of newly added incidents.

**Raises:** `pydantic.ValidationError` if any dict does not conform to `SafetyIncident`.

---

#### `all_incidents() -> list[SafetyIncident]`

Return all collected incidents as a list.

**Returns:** `list[SafetyIncident]`

---

#### `count` (property)

```python
@property
def count(self) -> int:
```

Total number of collected incidents.

---

### `IncidentStore`

```python
class IncidentStore:
```

In-memory store with rich query, filter, search, and pagination capabilities. Use this
for in-process queries after collecting incidents.

**Constructor:**

```python
IncidentStore()
```

Starts empty.

---

#### `add(incident: SafetyIncident) -> None`

Insert or overwrite an incident. If an incident with the same `incident_id` exists, it
is replaced.

---

#### `get(incident_id: str) -> SafetyIncident | None`

Retrieve a single incident by `incident_id`. Returns `None` if not found.

---

#### `all() -> list[SafetyIncident]`

Return all stored incidents as a list.

**Returns:** `list[SafetyIncident]`

---

#### `filter_by_severity(severity: IncidentSeverity) -> list[SafetyIncident]`

Return all incidents with the given severity level. Exact match.

**Parameters:**
- `severity` (`IncidentSeverity`)

**Returns:** `list[SafetyIncident]`

---

#### `filter_by_category(category: IncidentCategory) -> list[SafetyIncident]`

Return all incidents with the given category. Exact match.

**Parameters:**
- `category` (`IncidentCategory`)

**Returns:** `list[SafetyIncident]`

---

#### `filter_verified(verified: bool = True) -> list[SafetyIncident]`

Return incidents filtered by verification status.

**Parameters:**
- `verified` (`bool`) — `True` for verified; `False` for unverified. Defaults to `True`.

**Returns:** `list[SafetyIncident]`

---

#### `search(query: str) -> list[SafetyIncident]`

Full-text search across `title`, `description`, and `tags` fields.

**Parameters:**
- `query` (`str`) — Search string. Case-insensitive. Matched as a literal string (regex
  special characters are escaped via `re.escape`).

**Returns:** `list[SafetyIncident]` — All incidents where any of the three text fields
contain the query string.

**Example:**

```python
results = store.search("prompt injection")
results = store.search("GPT-4")
results = store.search("patient")
```

---

#### `paginate(page: int = 1, page_size: int = 20, severity: IncidentSeverity | None = None, category: IncidentCategory | None = None, verified: bool | None = None) -> tuple[list[SafetyIncident], int]`

Return a page of incidents sorted by `reported_date` descending (newest first), with
optional pre-filtering.

**Parameters:**
- `page` (`int`) — 1-based page number. Defaults to `1`.
- `page_size` (`int`) — Number of items per page. Defaults to `20`.
- `severity` (`IncidentSeverity | None`) — Filter by severity. `None` means no filter.
- `category` (`IncidentCategory | None`) — Filter by category. `None` means no filter.
- `verified` (`bool | None`) — Filter by verification status. `None` means no filter.

**Returns:** `tuple[list[SafetyIncident], int]` — A 2-tuple of `(items_on_this_page,
total_matching_count)`. The total count reflects all matching incidents before
pagination.

**Example:**

```python
page_items, total = store.paginate(
    page=1,
    page_size=10,
    severity=IncidentSeverity.critical,
    verified=True,
)
total_pages = (total + 9) // 10
print(f"Page 1/{total_pages}: {len(page_items)} items, {total} total")
```

---

#### `count` (property)

```python
@property
def count(self) -> int:
```

Total number of stored incidents.

---

### `TimelineAnalyzer`

```python
class TimelineAnalyzer:
```

Temporal analysis of incident collections. Stateless — operates on lists of incidents
passed as arguments.

**Constructor:**

```python
TimelineAnalyzer()
```

No arguments.

---

#### `build_timeline(incidents: list[SafetyIncident]) -> IncidentTimeline`

Build a sorted `IncidentTimeline` from a list of incidents.

**Parameters:**
- `incidents` (`list[SafetyIncident]`) — May be in any order; will be sorted internally.

**Returns:** `IncidentTimeline` — Sorted by `reported_date` ascending. If `incidents` is
empty, returns an `IncidentTimeline` with `period_description="No incidents"`.

---

#### `incidents_per_day(incidents: list[SafetyIncident]) -> dict[str, int]`

Count incidents per calendar day.

**Parameters:**
- `incidents` (`list[SafetyIncident]`)

**Returns:** `dict[str, int]` — Keys are ISO date strings (`"YYYY-MM-DD"`), values are
incident counts. Sorted by date ascending.

**Example:**

```python
daily = analyzer.incidents_per_day(store.all())
# {"2025-01-01": 2, "2025-01-02": 0, ...}  (only days with incidents appear)
```

---

#### `trending_categories(incidents: list[SafetyIncident], days: int = 30) -> list[tuple[str, int]]`

Return incident category counts for the most recent N days, sorted by count descending.

**Parameters:**
- `incidents` (`list[SafetyIncident]`)
- `days` (`int`) — Rolling window size in days. Defaults to `30`. Uses
  `datetime.now(UTC) - timedelta(days=days)` as the cutoff.

**Returns:** `list[tuple[str, int]]` — List of `(category_value_string, count)` tuples,
most frequent first. Returns only categories that appeared in the window.

**Example:**

```python
trending = analyzer.trending_categories(incidents, days=7)
# [("safety_bypass", 8), ("hallucination", 5), ("bias", 2)]
```

---

#### `build_dashboard_stats(incidents: list[SafetyIncident]) -> DashboardStats`

Aggregate all statistics for the dashboard view.

**Parameters:**
- `incidents` (`list[SafetyIncident]`) — Full incident list to analyze.

**Returns:** `DashboardStats` — Populated with:
- `total_incidents`: len(incidents)
- `by_severity`: Counter of severity values across all incidents
- `by_category`: Counter of category values across all incidents
- `trend_30d`: Daily counts for incidents with `reported_date` within the last 30 days,
  as a list of `{"date": "YYYY-MM-DD", "count": N}` dicts sorted by date
- `verified_count`: Count of incidents where `verified=True`
- `unverified_count`: `total_incidents - verified_count`

---

## Module: `aumai_opensafety` (top-level)

The package `__init__.py` re-exports the five core models.

```python
from aumai_opensafety import (
    DashboardStats,
    IncidentCategory,
    IncidentSeverity,
    IncidentTimeline,
    SafetyIncident,
)
```

**`__version__`** (`str`) — Package version string, e.g. `"0.1.0"`.

---

## Module: `aumai_opensafety.dashboard`

FastAPI application for the incident dashboard. Used by the `serve` CLI command.

**`create_app() -> FastAPI`**

Create and return the FastAPI application instance. Initializes the global
`IncidentStore`.

**`load_into_store(data: list[dict[str, Any]]) -> int`**

Load a list of incident dicts into the application's global store. Returns count of
newly added incidents.

The dashboard exposes REST endpoints including:
- `GET /incidents` — Paginated incident listing with optional filters
- `GET /incidents/{incident_id}` — Single incident lookup
- `POST /incidents` — Add a new incident
- `GET /stats` — `DashboardStats` JSON
- `GET /search?q=...` — Full-text search

See `http://localhost:8000/docs` when the server is running for the full OpenAPI spec.
