"""Tests for triage.scanners.snyk."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from factories import SNYK_RESULT_DICT, SNYK_RULE_DICT, SNYK_SARIF_DOC
from triage.config import SnykConfig
from triage.scanners.snyk import (
    _build_rule_index,
    _extract_cwe,
    _normalize_snyk_flow,
    _parse_snyk_result,
    scan,
)


class TestExtractCwe:
    def test_list_with_cwe(self):
        assert _extract_cwe(["CWE-89"]) == "89"

    def test_list_with_label_string(self):
        assert _extract_cwe(["CWE-79: Cross-site Scripting"]) == "79"

    def test_single_string(self):
        assert _extract_cwe("CWE-78: OS Command Injection") == "78"

    def test_none_returns_empty(self):
        assert _extract_cwe(None) == ""

    def test_empty_list_returns_empty(self):
        assert _extract_cwe([]) == ""

    def test_takes_first_cwe_from_list(self):
        assert _extract_cwe(["CWE-89", "CWE-22"]) == "89"

    def test_case_insensitive(self):
        assert _extract_cwe("cwe-22: Path Traversal") == "22"

    def test_no_cwe_in_string_returns_empty(self):
        assert _extract_cwe("OWASP A03") == ""


class TestBuildRuleIndex:
    def test_indexes_by_id(self):
        idx = _build_rule_index([SNYK_RULE_DICT])
        assert "python/SQLInjection" in idx
        assert idx["python/SQLInjection"] is SNYK_RULE_DICT

    def test_empty_list_returns_empty_dict(self):
        assert _build_rule_index([]) == {}

    def test_missing_id_uses_empty_string_key(self):
        idx = _build_rule_index([{"shortDescription": {"text": "No ID"}}])
        assert "" in idx


class TestParseSnykResult:
    def _rule_index(self) -> dict:
        return _build_rule_index([SNYK_RULE_DICT])

    def test_basic_mapping(self):
        f = _parse_snyk_result(SNYK_RESULT_DICT, self._rule_index())
        assert f.cwe_id == "89"
        assert f.severity == 5  # "error" → 5
        assert f.file == "app/db.py"  # %SRCROOT%/ prefix stripped
        assert f.line == 42
        assert f.scan_engine == "snyk"
        assert f.scan_file == "snyk"

    def test_issue_id_format(self):
        f = _parse_snyk_result(SNYK_RESULT_DICT, self._rule_index())
        assert f.issue_id == "python/SQLInjection:app/db.py:42"

    def test_issue_type_from_rule_short_description(self):
        f = _parse_snyk_result(SNYK_RESULT_DICT, self._rule_index())
        assert f.issue_type == "SQL Injection"

    def test_display_text_from_message(self):
        f = _parse_snyk_result(SNYK_RESULT_DICT, self._rule_index())
        assert "SQL Injection" in f.display_text

    def test_severity_warning(self):
        r = {**SNYK_RESULT_DICT, "level": "warning"}
        f = _parse_snyk_result(r, self._rule_index())
        assert f.severity == 3

    def test_severity_note(self):
        r = {**SNYK_RESULT_DICT, "level": "note"}
        f = _parse_snyk_result(r, self._rule_index())
        assert f.severity == 1

    def test_severity_none(self):
        r = {**SNYK_RESULT_DICT, "level": "none"}
        f = _parse_snyk_result(r, self._rule_index())
        assert f.severity == 1

    def test_unknown_rule_id_returns_empty_cwe(self):
        r = {**SNYK_RESULT_DICT, "ruleId": "unknown/Rule"}
        f = _parse_snyk_result(r, self._rule_index())
        assert f.cwe_id == ""

    def test_srcroot_prefix_stripped(self):
        r = {
            **SNYK_RESULT_DICT,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "%SRCROOT%/src/app.py"},
                        "region": {"startLine": 5},
                    }
                }
            ],
        }
        f = _parse_snyk_result(r, self._rule_index())
        assert f.file == "src/app.py"

    def test_uri_without_srcroot_unchanged(self):
        r = {
            **SNYK_RESULT_DICT,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app/views.py"},
                        "region": {"startLine": 10},
                    }
                }
            ],
        }
        f = _parse_snyk_result(r, self._rule_index())
        assert f.file == "app/views.py"

    def test_code_flows_stored_in_stack_dumps(self):
        f = _parse_snyk_result(SNYK_RESULT_DICT, self._rule_index())
        assert f.stack_dumps is not None
        path = f.stack_dumps[0]
        assert path["source"]["line"] == 10
        assert path["source"]["file"] == "app/db.py"
        assert path["sink"]["line"] == 42
        assert path["sink"]["file"] == "app/db.py"
        assert path["steps"] == []

    def test_no_code_flows_leaves_stack_dumps_none(self):
        r = {**SNYK_RESULT_DICT, "codeFlows": []}
        f = _parse_snyk_result(r, self._rule_index())
        assert f.stack_dumps is None


class TestNormalizeSnykFlow:
    def _make_flow(self, *, n_steps: int = 0) -> list[dict]:
        # Real Snyk locations have only {id, physicalLocation} — no message field.
        def _loc(uri: str, line: int, idx: int = 0) -> dict:
            return {
                "location": {
                    "id": idx,
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": line, "endLine": line},
                    },
                }
            }

        step_locs = [_loc("app/db.py", 20 + i, idx=i + 1) for i in range(n_steps)]
        source = _loc("app/routes.py", 5, idx=0)
        sink = _loc("app/db.py", 42, idx=n_steps + 1)
        return [{"threadFlows": [{"locations": [source] + step_locs + [sink]}]}]

    def test_source_mapped(self):
        paths = _normalize_snyk_flow(self._make_flow())
        assert paths[0]["source"] == {"file": "app/routes.py", "line": 5, "snippet": ""}

    def test_sink_mapped(self):
        paths = _normalize_snyk_flow(self._make_flow())
        assert paths[0]["sink"] == {"file": "app/db.py", "line": 42, "snippet": ""}

    def test_no_steps_returns_empty_list(self):
        paths = _normalize_snyk_flow(self._make_flow(n_steps=0))
        assert paths[0]["steps"] == []

    def test_intermediate_steps_mapped(self):
        paths = _normalize_snyk_flow(self._make_flow(n_steps=2))
        assert len(paths[0]["steps"]) == 2
        assert paths[0]["steps"][0]["line"] == 20
        assert paths[0]["steps"][0]["snippet"] == ""  # Snyk provides no message text

    def test_all_steps_returned(self):
        n = 15
        paths = _normalize_snyk_flow(self._make_flow(n_steps=n))
        assert len(paths[0]["steps"]) == n

    def test_none_returns_none(self):
        assert _normalize_snyk_flow(None) is None

    def test_empty_list_returns_none(self):
        assert _normalize_snyk_flow([]) is None

    def test_thread_flow_with_fewer_than_two_locations_skipped(self):
        flows = [{"threadFlows": [{"locations": []}]}]
        assert _normalize_snyk_flow(flows) is None

    def test_multiple_thread_flows_produce_multiple_paths(self):
        flow = self._make_flow()
        # Duplicate the threadFlow to simulate two paths
        flow[0]["threadFlows"].append(flow[0]["threadFlows"][0])
        paths = _normalize_snyk_flow(flow)
        assert len(paths) == 2


class TestSnykScan:
    def _cfg(self) -> SnykConfig:
        return SnykConfig(severity_threshold="low")

    @pytest.fixture(autouse=True)
    def _snyk_installed(self):
        """Mock shutil.which so tests don't depend on snyk being on PATH."""
        with patch("triage.scanners.snyk.shutil.which", return_value="/usr/bin/snyk"):
            yield

    def test_successful_scan_returns_findings(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()

        with patch(
            "triage.scanners.snyk.capture_cmd",
            return_value=(False, json.dumps(SNYK_SARIF_DOC), ""),
        ):
            result = scan(repo, self._cfg())

        assert result.scan_engine == "snyk"
        assert len(result.findings) == 1
        assert result.total_raw == 1

    def test_exit_code_1_with_findings_not_an_error(self, tmp_path: Path):
        """Snyk exits 1 when findings exist — should not raise."""
        repo = tmp_path / "my-repo"
        repo.mkdir()

        with patch(
            "triage.scanners.snyk.capture_cmd",
            return_value=(False, json.dumps(SNYK_SARIF_DOC), ""),
        ):
            result = scan(repo, self._cfg())

        assert len(result.findings) == 1

    def test_empty_runs_returns_zero_findings(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        empty_sarif = json.dumps({"runs": []})

        with patch(
            "triage.scanners.snyk.capture_cmd",
            return_value=(True, empty_sarif, ""),
        ):
            result = scan(repo, self._cfg())

        assert result.findings == []
        assert result.total_raw == 0

    def test_empty_stdout_returns_zero_findings(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()

        with patch(
            "triage.scanners.snyk.capture_cmd",
            return_value=(True, "", ""),
        ):
            result = scan(repo, self._cfg())

        assert result.findings == []

    def test_missing_binary_raises_with_install_hint(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()

        with patch("triage.scanners.snyk.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="snyk is not installed"):
                scan(repo, self._cfg())

    def test_auth_error_raises_runtime_error(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()

        with patch(
            "triage.scanners.snyk.capture_cmd",
            return_value=(False, "", "Not authenticated. Please run `snyk auth`"),
        ):
            with pytest.raises(RuntimeError):
                scan(repo, self._cfg())

    def test_invalid_json_raises_runtime_error(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()

        with patch(
            "triage.scanners.snyk.capture_cmd",
            return_value=(False, "not-json{{", ""),
        ):
            with pytest.raises(RuntimeError, match="not valid JSON"):
                scan(repo, self._cfg())

    def test_severity_threshold_passed_in_cmd(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        cfg = SnykConfig(severity_threshold="high")

        with patch(
            "triage.scanners.snyk.capture_cmd",
            return_value=(True, json.dumps(SNYK_SARIF_DOC), ""),
        ) as mock_capture:
            scan(repo, cfg)

        cmd = mock_capture.call_args[0][0]
        assert "--severity-threshold" in cmd
        assert "high" in cmd

    def test_raw_output_saved_when_sast_dir_provided(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        sast_dir = tmp_path / ".sast-results"

        with patch(
            "triage.scanners.snyk.capture_cmd",
            return_value=(True, json.dumps(SNYK_SARIF_DOC), ""),
        ):
            scan(repo, self._cfg(), sast_dir)

        saved = sast_dir / ".snyk" / "raw_snyk_output.json"
        assert saved.exists()
        assert json.loads(saved.read_text()) == SNYK_SARIF_DOC

    def test_result_repo_name_matches_directory(self, tmp_path: Path):
        repo = tmp_path / "cool-project"
        repo.mkdir()

        with patch(
            "triage.scanners.snyk.capture_cmd",
            return_value=(True, json.dumps({"runs": []}), ""),
        ):
            result = scan(repo, self._cfg())

        assert result.repo_name == "cool-project"
