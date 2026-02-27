# Getting Started with aumai-opensafety

This guide takes you from installation to a working incident aggregator with a live
dashboard API in under ten minutes, then covers common patterns for production use.

---

## Prerequisites

- Python 3.11 or newer
- `pip` package manager
- A JSON file of safety incidents (or you can create one using the examples below)

For the dashboard server: `uvicorn` is also required (installed separately or via the
`[server]` extra).

---

## Installation

### From PyPI (core only)

```bash
pip install aumai-opensafety
```

### From PyPI with server support

```bash
pip install "aumai-opensafety[server]"
```

This also installs `uvicorn` and `fastapi`, which are required for the `serve` command.

### From source

```bash
git clone https://github.com/aumai/aumai-opensafety.git
cd aumai-opensafety
pip install .
```

### Developer mode

```bash
git clone https://github.com/aumai/aumai-opensafety.git
cd aumai-opensafety
pip install -e ".[dev]"
make test
```

Verify the installation:

```bash
opensafety --version
# aumai-opensafety, version 0.1.0
```

---

## Your First Safety Incident Aggregation

### Step 1: Create a sample incidents file

Create `/tmp/incidents.json` with sample data:

```json
[
  {
    "incident_id": "INC-001",
    "title": "LLM jailbreak bypasses safety filter in production",
    "description": "A prompt injection technique was used to circumvent guardrails, allowing the model to produce restricted content.",
    "severity": "high",
    "category": "safety_bypass",
    "source": "https://example.com/report-001",
    "reported_date": "2025-01-10T09:00:00Z",
    "affected_systems": ["gpt4-production-v2"],
    "tags": ["jailbreak", "prompt-injection", "guardrail"],
    "verified": true
  },
  {
    "incident_id": "INC-002",
    "title": "Medical AI hallucination: fabricated drug dosage",
    "description": "A medical advisory system fabricated a drug dosage recommendation that contradicted clinical guidelines, classified as critical hallucination.",
    "severity": "critical",
    "category": "hallucination",
    "source": "https://example.com/report-002",
    "reported_date": "2025-01-12T14:30:00Z",
    "affected_systems": ["medai-assistant-v3"],
    "tags": ["medical", "hallucination", "patient-safety"],
    "verified": true
  },
  {
    "incident_id": "INC-003",
    "title": "Training data memorization: PII exposed in outputs",
    "description": "Users discovered the model would reproduce verbatim text from its training data including email addresses and phone numbers.",
    "severity": "high",
    "category": "data_leak",
    "source": "https://example.com/report-003",
    "reported_date": "2025-01-14T11:00:00Z",
    "affected_systems": ["llm-service-eu"],
    "tags": ["pii", "privacy", "memorization"],
    "verified": false
  }
]
```

### Step 2: Ingest and inspect

```bash
opensafety ingest --file /tmp/incidents.json
```

Output:

```
Ingested 3 new incidents from incidents.json
  critical       : 1
  high           : 2
```

### Step 3: View dashboard statistics

```bash
opensafety stats --file /tmp/incidents.json
```

Output:

```
Total incidents : 3
Verified        : 2
Unverified      : 1

By severity:
  critical       : 1
  high           : 2

By category:
  data_leak           : 1
  hallucination       : 1
  safety_bypass       : 1
```

### Step 4: Auto-classify incidents

If your incident data does not have severity and category pre-set, use `--auto-classify`
to infer them from the text:

```bash
opensafety ingest --file /tmp/incidents.json --auto-classify
```

The classifier reads the `title` and `description` fields and matches against keyword
tables to infer severity and category. See the [API Reference](api-reference.md) for the
full keyword lists.

### Step 5: Start the dashboard server

```bash
pip install uvicorn  # if not already installed
opensafety serve --seed /tmp/incidents.json --port 8000
```

Then open `http://localhost:8000/docs` in your browser to explore the API via the
auto-generated FastAPI documentation.

---

## Common Patterns

### Pattern 1: Continuous ingestion from multiple sources

In production, you typically ingest from multiple sources on a schedule. Here is a
Python script that merges several source files and deduplicates:

```python
import json
from pathlib import Path
from aumai_opensafety.core import IncidentCollector, IncidentClassifier
from aumai_opensafety.models import SafetyIncident

collector = IncidentCollector()
classifier = IncidentClassifier()

source_files = [
    Path("/data/incidents/aiid-export.json"),
    Path("/data/incidents/internal-reports.json"),
    Path("/data/incidents/third-party-feed.json"),
]

for source_file in source_files:
    raw = json.loads(source_file.read_text())
    # Auto-classify if this source doesn't have structured severity
    incidents = [SafetyIncident.model_validate(item) for item in raw]
    incidents = [classifier.reclassify(i) for i in incidents]
    added = collector.bulk_import(incidents)
    print(f"{source_file.name}: {added} new incidents")

print(f"Total unique incidents: {collector.count}")
```

---

### Pattern 2: Querying and filtering the store

```python
from aumai_opensafety.core import IncidentStore
from aumai_opensafety.models import IncidentSeverity, IncidentCategory

store = IncidentStore()
for incident in collector.all_incidents():
    store.add(incident)

# Get all critical incidents
critical = store.filter_by_severity(IncidentSeverity.critical)
print(f"Critical incidents: {len(critical)}")

# Get all safety bypass incidents
bypasses = store.filter_by_category(IncidentCategory.safety_bypass)

# Full-text search
results = store.search("prompt injection")
for r in results:
    print(f"  {r.incident_id}: {r.title}")

# Paginated API-style query — page 2, high severity, verified only
page_items, total = store.paginate(
    page=2,
    page_size=10,
    severity=IncidentSeverity.high,
    verified=True,
)
print(f"Showing {len(page_items)} of {total} matching incidents")
```

---

### Pattern 3: Trend monitoring and alerting

Use `TimelineAnalyzer` to build a monitoring loop that alerts when a specific category
is trending up.

```python
from aumai_opensafety.core import TimelineAnalyzer
from aumai_opensafety.models import IncidentCategory

analyzer = TimelineAnalyzer()
incidents = store.all()

# Get daily incident counts for charting
daily = analyzer.incidents_per_day(incidents)
for date, count in list(daily.items())[-7:]:  # last 7 days
    print(f"  {date}: {'#' * count} ({count})")

# Trending categories in the last 7 days
trending_7d = analyzer.trending_categories(incidents, days=7)
print("Trending categories (7 days):")
for category_name, count in trending_7d[:3]:
    print(f"  {category_name}: {count} incidents")

# Alert if safety_bypass is in top 2 trending categories
top_categories = [cat for cat, _ in trending_7d[:2]]
if IncidentCategory.safety_bypass.value in top_categories:
    print("ALERT: safety_bypass is trending — review recent incidents")
```

---

### Pattern 4: Exporting dashboard stats for a monitoring system

```python
import json
from aumai_opensafety.core import TimelineAnalyzer

analyzer = TimelineAnalyzer()
stats = analyzer.build_dashboard_stats(store.all())

# Export to JSON for a monitoring dashboard
stats_json = stats.model_dump(mode="json")
with open("dashboard-stats.json", "w") as f:
    json.dump(stats_json, f, indent=2, default=str)

# The stats object contains:
# - total_incidents: int
# - by_severity: {"critical": N, "high": N, ...}
# - by_category: {"hallucination": N, ...}
# - trend_30d: [{"date": "2025-01-01", "count": 3}, ...]
# - verified_count: int
# - unverified_count: int
print(f"Dashboard stats saved with {stats.total_incidents} incidents")
print(f"30-day trend has {len(stats.trend_30d)} data points")
```

---

### Pattern 5: Running the API server programmatically

```python
import uvicorn
from aumai_opensafety.dashboard import create_app, load_into_store
import json

# Load incidents into the app's store
app = create_app()
raw = json.loads(open("incidents.json").read())
count = load_into_store(raw)
print(f"Loaded {count} incidents into dashboard store")

# Run the server
uvicorn.run(app, host="127.0.0.1", port=8000)
```

---

## Troubleshooting FAQ

**Q: `opensafety ingest` reports `Input file must be a JSON array`.**

The input file must be a JSON array (starts with `[`). If your file is a JSON object
(starts with `{`), wrap it in an array first:
```bash
python -c "
import json
data = json.load(open('incident.json'))
json.dump([data], open('incidents.json', 'w'))
"
```

---

**Q: `opensafety serve` fails with `uvicorn is required to run the server`.**

Install uvicorn:
```bash
pip install uvicorn
# or
pip install "aumai-opensafety[server]"
```

---

**Q: All incidents are getting classified as `informational` / `other` with `--auto-classify`.**

The classifier matches keywords in the `title` and `description` fields. Check that
these fields are populated with meaningful English text. Overly terse titles like
"Incident 42" will not match any keywords.

To debug, inspect what the classifier sees:
```python
from aumai_opensafety.core import IncidentClassifier
classifier = IncidentClassifier()
text = incident.title + " " + incident.description
print(text.lower())  # This is exactly what the classifier searches
```

---

**Q: Duplicate incidents are being added after a re-ingest.**

`IncidentCollector` deduplicates by `incident_id`. If the same logical incident appears
with different IDs in different source files, it will be added as a new record. Assign
stable, deterministic IDs to incidents (e.g., a hash of the source URL) to prevent this.

---

**Q: The `stats --file` command fails with a validation error.**

One or more records in your JSON file do not match the `SafetyIncident` model. Common
issues:
- `severity` must be one of: `critical`, `high`, `medium`, `low`, `informational`
- `category` must be one of: `model_failure`, `data_leak`, `bias`, `misuse`,
  `safety_bypass`, `hallucination`, `other`
- `reported_date` must be an ISO 8601 datetime string (e.g., `"2025-01-10T09:00:00Z"`)

Use Pydantic validation to find the bad record:
```python
import json
from aumai_opensafety.models import SafetyIncident
raw = json.load(open("incidents.json"))
for i, item in enumerate(raw):
    try:
        SafetyIncident.model_validate(item)
    except Exception as e:
        print(f"Record {i} invalid: {e}")
```

---

**Q: How do I add custom incident categories?**

`IncidentCategory` is a `str` `Enum`. To add custom categories, subclass it:
```python
from aumai_opensafety.models import IncidentCategory
from enum import Enum

class ExtendedCategory(str, Enum):
    model_failure = "model_failure"
    data_leak = "data_leak"
    # ... all original values ...
    agentic_loop = "agentic_loop"   # your custom category
    tool_abuse = "tool_abuse"
```

Then use `ExtendedCategory` anywhere `IncidentCategory` is expected in your own code.
Note that the built-in classifier keyword tables only cover the original categories.
