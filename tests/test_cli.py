"""Tests for aumai_opensafety.cli — Click command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from aumai_opensafety.cli import main
from tests.conftest import incident_to_dict, make_incident

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_incidents_json(path: Path, incidents: list[dict]) -> None:
    path.write_text(json.dumps(incidents), encoding="utf-8")


# ===========================================================================
# --version
# ===========================================================================


class TestVersion:
    """Tests for the --version flag."""

    def test_version_flag_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0

    def test_version_flag_reports_0_1_0(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert "0.1.0" in result.output


# ===========================================================================
# ingest command
# ===========================================================================


class TestIngest:
    """Tests for the `ingest` sub-command."""

    def test_ingest_valid_file_exits_zero(
        self, incidents_json_file: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["ingest", "--file", str(incidents_json_file)])
        assert result.exit_code == 0

    def test_ingest_reports_correct_count(
        self,
        incidents_json_file: Path,
        sample_incidents: list,
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["ingest", "--file", str(incidents_json_file)])
        assert f"Ingested {len(sample_incidents)} new incidents" in result.output

    def test_ingest_prints_severity_breakdown(
        self, incidents_json_file: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["ingest", "--file", str(incidents_json_file)])
        # At least one severity label should appear in output
        severity_labels = ["critical", "high", "medium", "low", "informational"]
        assert any(label in result.output for label in severity_labels)

    def test_ingest_auto_classify_flag(
        self, incidents_json_file: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["ingest", "--file", str(incidents_json_file), "--auto-classify"],
        )
        assert result.exit_code == 0

    def test_ingest_non_array_json_exits_nonzero(
        self, invalid_json_file: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["ingest", "--file", str(invalid_json_file)])
        assert result.exit_code != 0

    def test_ingest_non_array_json_prints_error(
        self, invalid_json_file: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["ingest", "--file", str(invalid_json_file)])
        assert "JSON array" in result.output

    def test_ingest_nonexistent_file_exits_nonzero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["ingest", "--file", "/nonexistent/path/file.json"]
        )
        assert result.exit_code != 0

    def test_ingest_single_incident(self, tmp_path: Path) -> None:
        incident = make_incident(incident_id="INC-SINGLE-CLI")
        file = tmp_path / "single.json"
        _write_incidents_json(file, [incident_to_dict(incident)])
        runner = CliRunner()
        result = runner.invoke(main, ["ingest", "--file", str(file)])
        assert "Ingested 1 new incidents" in result.output

    def test_ingest_empty_array_ingests_zero(self, tmp_path: Path) -> None:
        file = tmp_path / "empty.json"
        _write_incidents_json(file, [])
        runner = CliRunner()
        result = runner.invoke(main, ["ingest", "--file", str(file)])
        assert "Ingested 0 new incidents" in result.output

    def test_ingest_with_auto_classify_reclassifies_incidents(
        self, tmp_path: Path
    ) -> None:
        incident = make_incident(
            incident_id="INC-AUTOCLASSIFY-CLI",
            title="Critical breach in production",
            description="Mass exfiltration of user data.",
        )
        file = tmp_path / "auto.json"
        _write_incidents_json(file, [incident_to_dict(incident)])
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["ingest", "--file", str(file), "--auto-classify"],
        )
        assert result.exit_code == 0
        # After reclassification, "critical" should appear in the severity table
        assert "critical" in result.output


# ===========================================================================
# stats command
# ===========================================================================


class TestStats:
    """Tests for the `stats` sub-command."""

    def test_stats_valid_file_exits_zero(
        self, incidents_json_file: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["stats", "--file", str(incidents_json_file)])
        assert result.exit_code == 0

    def test_stats_outputs_total_incidents(
        self,
        incidents_json_file: Path,
        sample_incidents: list,
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["stats", "--file", str(incidents_json_file)])
        assert f"Total incidents : {len(sample_incidents)}" in result.output

    def test_stats_outputs_verified_and_unverified(
        self, incidents_json_file: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["stats", "--file", str(incidents_json_file)])
        assert "Verified" in result.output
        assert "Unverified" in result.output

    def test_stats_outputs_by_severity_section(
        self, incidents_json_file: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["stats", "--file", str(incidents_json_file)])
        assert "By severity:" in result.output

    def test_stats_outputs_by_category_section(
        self, incidents_json_file: Path
    ) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["stats", "--file", str(incidents_json_file)])
        assert "By category:" in result.output

    def test_stats_without_file_exits_nonzero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["stats"])
        assert result.exit_code != 0

    def test_stats_without_file_prints_error_message(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["stats"])
        # Error message goes to stderr; CliRunner captures it in output by default
        assert "Provide --file" in result.output

    def test_stats_nonexistent_file_exits_nonzero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["stats", "--file", "/nonexistent/path/stats.json"]
        )
        assert result.exit_code != 0


# ===========================================================================
# serve command
# ===========================================================================


class TestServe:
    """Tests for the `serve` sub-command."""

    def test_serve_without_uvicorn_exits_nonzero(self) -> None:
        """When uvicorn is not installed the command must fail gracefully."""
        runner = CliRunner()
        # Patch the import inside cli.py to simulate uvicorn being missing.
        with patch.dict(sys.modules, {"uvicorn": None}):
            result = runner.invoke(main, ["serve"])
        assert result.exit_code != 0

    def test_serve_without_uvicorn_prints_install_hint(self) -> None:
        runner = CliRunner()
        with patch.dict(sys.modules, {"uvicorn": None}):
            result = runner.invoke(main, ["serve"])
        assert "uvicorn" in result.output

    def test_serve_with_uvicorn_calls_run(self) -> None:
        """When uvicorn is available, uvicorn.run must be invoked."""
        mock_uvicorn = MagicMock()
        runner = CliRunner()
        with patch.dict(sys.modules, {"uvicorn": mock_uvicorn}):
            runner.invoke(main, ["serve"])
        mock_uvicorn.run.assert_called_once()

    def test_serve_passes_host_and_port_to_uvicorn(self) -> None:
        mock_uvicorn = MagicMock()
        runner = CliRunner()
        with patch.dict(sys.modules, {"uvicorn": mock_uvicorn}):
            runner.invoke(main, ["serve", "--host", "127.0.0.1", "--port", "9000"])
        _, kwargs = mock_uvicorn.run.call_args
        assert kwargs.get("host") == "127.0.0.1"
        assert kwargs.get("port") == 9000

    def test_serve_with_valid_seed_file_loads_incidents(
        self, incidents_json_file: Path, sample_incidents: list
    ) -> None:
        mock_uvicorn = MagicMock()
        runner = CliRunner()
        with patch.dict(sys.modules, {"uvicorn": mock_uvicorn}):
            result = runner.invoke(
                main,
                ["serve", "--seed", str(incidents_json_file)],
            )
        assert f"Loaded {len(sample_incidents)} incidents" in result.output

    def test_serve_with_invalid_seed_format_prints_error(
        self, invalid_json_file: Path
    ) -> None:
        """Seed file that is an object (not array) should print an error."""
        mock_uvicorn = MagicMock()
        runner = CliRunner()
        with patch.dict(sys.modules, {"uvicorn": mock_uvicorn}):
            result = runner.invoke(
                main,
                ["serve", "--seed", str(invalid_json_file)],
            )
        assert "JSON array" in result.output
