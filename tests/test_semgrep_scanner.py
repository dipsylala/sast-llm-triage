"""Tests for triage.scanners.semgrep."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import json

import pytest

from factories import SEMGREP_RESULT_DICT
from triage.scanners.semgrep import _extract_cwe, _normalize_semgrep_trace, _parse_semgrep_result, scan
from triage.config import SemgrepConfig


class TestExtractCwe:
    def test_list_with_cwe(self):
        assert _extract_cwe(["CWE-89: SQL Injection"]) == "89"

    def test_single_string(self):
        assert _extract_cwe("CWE-79: XSS") == "79"

    def test_none_returns_empty(self):
        assert _extract_cwe(None) == ""

    def test_empty_list_returns_empty(self):
        assert _extract_cwe([]) == ""

    def test_takes_first_cwe_from_list(self):
        assert _extract_cwe(["CWE-89: SQL Injection", "CWE-22: Path Traversal"]) == "89"

    def test_case_insensitive(self):
        assert _extract_cwe("cwe-78: OS Command Injection") == "78"

    def test_no_cwe_in_string(self):
        assert _extract_cwe("OWASP A01") == ""


class TestParseSemgrepResult:
    def test_basic_mapping(self):
        f = _parse_semgrep_result(SEMGREP_RESULT_DICT)
        assert f.cwe_id == "89"
        assert f.severity == 4  # ERROR → 4
        assert f.file == "app/db.py"
        assert f.line == 42
        assert f.scan_engine == "semgrep"
        assert f.scan_file == "semgrep"

    def test_issue_id_format(self):
        f = _parse_semgrep_result(SEMGREP_RESULT_DICT)
        check_id = SEMGREP_RESULT_DICT["check_id"]
        assert f.issue_id == f"{check_id}:app/db.py:42"

    def test_severity_critical(self):
        r = {**SEMGREP_RESULT_DICT, "extra": {**SEMGREP_RESULT_DICT["extra"], "severity": "CRITICAL"}}
        f = _parse_semgrep_result(r)
        assert f.severity == 5

    def test_severity_warning(self):
        r = {**SEMGREP_RESULT_DICT, "extra": {**SEMGREP_RESULT_DICT["extra"], "severity": "WARNING"}}
        f = _parse_semgrep_result(r)
        assert f.severity == 3

    def test_severity_info(self):
        r = {**SEMGREP_RESULT_DICT, "extra": {**SEMGREP_RESULT_DICT["extra"], "severity": "INFO"}}
        f = _parse_semgrep_result(r)
        assert f.severity == 1

    def test_unknown_severity_defaults_to_2(self):
        r = {**SEMGREP_RESULT_DICT, "extra": {**SEMGREP_RESULT_DICT["extra"], "severity": "MEDIUM"}}
        f = _parse_semgrep_result(r)
        assert f.severity == 2

    def test_no_cwe_metadata_returns_empty_cwe(self):
        r = {
            **SEMGREP_RESULT_DICT,
            "extra": {
                "message": "something",
                "severity": "WARNING",
                "metadata": {},
            },
        }
        f = _parse_semgrep_result(r)
        assert f.cwe_id == ""

    def test_dataflow_trace_stored_in_stack_dumps(self):
        trace = {
            "taint_source": {
                "location": {"path": "app/db.py", "start": {"line": 10, "col": 1}},
                "content": "request.args.get('id')",
            },
            "intermediate_vars": [
                {
                    "location": {"path": "app/db.py", "start": {"line": 20, "col": 5}},
                    "content": "user_id",
                }
            ],
            "taint_sink": {
                "location": {"path": "app/db.py", "start": {"line": 42, "col": 5}},
                "content": "cursor.execute(query)",
            },
        }
        r = {
            **SEMGREP_RESULT_DICT,
            "extra": {**SEMGREP_RESULT_DICT["extra"], "dataflow_trace": trace},
        }
        f = _parse_semgrep_result(r)
        # normalized schema — list with one path
        assert f.stack_dumps[0]["source"]["snippet"] == "request.args.get('id')"
        assert f.stack_dumps[0]["source"]["file"] == "app/db.py"
        assert f.stack_dumps[0]["source"]["line"] == 10
        assert len(f.stack_dumps[0]["steps"]) == 1
        assert f.stack_dumps[0]["steps"][0]["snippet"] == "user_id"
        assert f.stack_dumps[0]["sink"]["snippet"] == "cursor.execute(query)"
        assert f.stack_dumps[0]["sink"]["line"] == 42

    def test_no_dataflow_trace_leaves_stack_dumps_none(self):
        f = _parse_semgrep_result(SEMGREP_RESULT_DICT)
        assert f.stack_dumps is None


class TestNormalizesSemgrepTrace:
    def _make_trace(self, *, n_steps: int = 1) -> dict:
        steps = [
            {
                "location": {"path": "app/db.py", "start": {"line": 20 + i, "col": 1}},
                "content": f"var_{i}",
            }
            for i in range(n_steps)
        ]
        return {
            "taint_source": {
                "location": {"path": "app/routes.py", "start": {"line": 5, "col": 1}},
                "content": "request.form['q']",
            },
            "intermediate_vars": steps,
            "taint_sink": {
                "location": {"path": "app/db.py", "start": {"line": 42, "col": 3}},
                "content": "cursor.execute(sql)",
            },
        }

    def test_source_mapped(self):
        r = _normalize_semgrep_trace(self._make_trace())
        assert r[0]["source"] == {"file": "app/routes.py", "line": 5, "snippet": "request.form['q']"}

    def test_sink_mapped(self):
        r = _normalize_semgrep_trace(self._make_trace())
        assert r[0]["sink"] == {"file": "app/db.py", "line": 42, "snippet": "cursor.execute(sql)"}

    def test_steps_mapped(self):
        r = _normalize_semgrep_trace(self._make_trace(n_steps=2))
        assert len(r[0]["steps"]) == 2
        assert r[0]["steps"][0] == {"file": "app/db.py", "line": 20, "snippet": "var_0"}

    def test_no_steps_returns_empty_list(self):
        trace = self._make_trace(n_steps=0)
        r = _normalize_semgrep_trace(trace)
        assert r[0]["steps"] == []

    def test_always_returns_single_element_list(self):
        r = _normalize_semgrep_trace(self._make_trace())
        assert isinstance(r, list)
        assert len(r) == 1

    def test_missing_source_returns_none(self):
        trace = self._make_trace()
        del trace["taint_source"]
        assert _normalize_semgrep_trace(trace) is None

    def test_missing_sink_returns_none(self):
        trace = self._make_trace()
        del trace["taint_sink"]
        assert _normalize_semgrep_trace(trace) is None

    def test_none_input_returns_none(self):
        assert _normalize_semgrep_trace(None) is None


class TestSemgrepScan:
    def _make_cfg(self, pro: bool = False) -> SemgrepConfig:
        return SemgrepConfig(config="auto", pro=pro)

    def test_successful_scan_returns_findings(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        cfg = self._make_cfg()

        semgrep_output = json.dumps(
            {"results": [SEMGREP_RESULT_DICT], "errors": []}
        )

        with patch(
            "triage.scanners.semgrep.capture_cmd",
            return_value=(True, semgrep_output, ""),
        ):
            result = scan(repo, cfg)

        assert result.scan_engine == "semgrep"
        assert len(result.findings) == 1
        assert result.total_raw == 1

    def test_exit_code_1_with_findings_is_not_error(self, tmp_path: Path):
        """Semgrep exits 1 when findings exist — should not raise."""
        repo = tmp_path / "my-repo"
        repo.mkdir()
        cfg = self._make_cfg()

        semgrep_output = json.dumps(
            {"results": [SEMGREP_RESULT_DICT], "errors": []}
        )

        with patch(
            "triage.scanners.semgrep.capture_cmd",
            return_value=(False, semgrep_output, ""),  # ok=False simulates exit 1
        ):
            result = scan(repo, cfg)

        assert len(result.findings) == 1

    def test_missing_binary_raises_with_install_hint(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        cfg = self._make_cfg()

        with patch("triage.scanners.semgrep.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="semgrep is not installed"):
                scan(repo, cfg)

    def test_scan_failure_with_no_json_raises(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        cfg = self._make_cfg()

        with patch(
            "triage.scanners.semgrep.capture_cmd",
            return_value=(False, "", "semgrep: command not found"),
        ):
            with pytest.raises(RuntimeError, match="semgrep"):
                scan(repo, cfg)

    def test_pro_flag_passed_when_configured(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        cfg = self._make_cfg(pro=True)

        semgrep_output = json.dumps({"results": [], "errors": []})

        with patch(
            "triage.scanners.semgrep.capture_cmd",
            return_value=(True, semgrep_output, ""),
        ) as mock_capture:
            scan(repo, cfg)

        called_cmd = mock_capture.call_args[0][0]
        assert "--pro" in called_cmd

    def test_pro_missing_binary_falls_back_to_oss(self, tmp_path: Path):
        """When --pro binary is absent semgrep reports to stderr; scanner retries without --pro."""
        repo = tmp_path / "my-repo"
        repo.mkdir()
        cfg = self._make_cfg(pro=True)

        semgrep_output = json.dumps({"results": [SEMGREP_RESULT_DICT], "errors": []})
        pro_stderr = "Failed to find semgrep-core-proprietary.exe in PATH or in the semgrep package."

        call_args_list: list = []

        def fake_capture(cmd, **kwargs):
            call_args_list.append(list(cmd))
            if "--pro" in cmd:
                # Simulate the Pro binary missing: non-zero exit, no JSON, error in stderr
                return (False, "", pro_stderr)
            # OSS fallback succeeds
            return (True, semgrep_output, "")

        with patch("triage.scanners.semgrep.capture_cmd", side_effect=fake_capture):
            result = scan(repo, cfg)

        assert len(call_args_list) == 2, "Expected two calls: --pro attempt then OSS fallback"
        assert "--pro" in call_args_list[0]
        assert "--pro" not in call_args_list[1]
        assert len(result.findings) == 1

    def test_raw_output_saved_when_sast_dir_provided(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        sast_dir = tmp_path / ".sast-results"
        cfg = self._make_cfg()
        semgrep_output = json.dumps({"results": [SEMGREP_RESULT_DICT], "errors": []})

        with patch(
            "triage.scanners.semgrep.capture_cmd",
            return_value=(True, semgrep_output, ""),
        ):
            scan(repo, cfg, sast_dir)

        saved = sast_dir / ".semgrep" / "raw_semgrep_output.json"
        assert saved.exists()
        assert json.loads(saved.read_text())["results"][0]["check_id"] == SEMGREP_RESULT_DICT["check_id"]

    def test_pro_flag_absent_when_not_configured(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        cfg = self._make_cfg(pro=False)

        semgrep_output = json.dumps({"results": [], "errors": []})

        with patch(
            "triage.scanners.semgrep.capture_cmd",
            return_value=(True, semgrep_output, ""),
        ) as mock_capture:
            scan(repo, cfg)

        called_cmd = mock_capture.call_args[0][0]
        assert "--pro" not in called_cmd
