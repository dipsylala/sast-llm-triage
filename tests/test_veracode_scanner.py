"""Tests for triage.scanners.veracode."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from factories import VERACODE_FINDING_DICT
from triage.scanners.veracode import _normalize_veracode_trace, _parse_veracode_finding, scan
from triage.config import VeracodeConfig


class TestParseVeracodeFinding:
    def test_basic_field_mapping(self):
        finding = _parse_veracode_finding(VERACODE_FINDING_DICT, "filtered_test.json")
        assert finding.issue_id == "1042"
        assert finding.cwe_id == "89"
        assert finding.issue_type == "SQL Injection"
        assert finding.severity == 4
        assert finding.file == "src/main/java/App.java"
        assert finding.line == 88
        assert finding.scan_engine == "veracode"
        assert finding.scan_file == "filtered_test.json"
        assert "SQL injection" in finding.display_text

    def test_missing_files_section(self):
        raw = {**VERACODE_FINDING_DICT, "files": {}}
        finding = _parse_veracode_finding(raw, "filtered_test.json")
        assert finding.file == ""
        assert finding.line == 0

    def test_missing_issue_id_defaults_to_empty_string(self):
        raw = {k: v for k, v in VERACODE_FINDING_DICT.items() if k != "issue_id"}
        finding = _parse_veracode_finding(raw, "filtered_test.json")
        assert finding.issue_id == ""

    def test_severity_coerced_to_int(self):
        raw = {**VERACODE_FINDING_DICT, "severity": "3"}
        finding = _parse_veracode_finding(raw, "filtered_test.json")
        assert finding.severity == 3


class TestNormalizeVeracodeTrace:
    def _make_raw(self, *, n_frames: int = 3) -> dict:
        """Veracode stores frames sink-first; source is the last frame."""
        frames = [
            {
                "SourceFile": f"src/Step{n_frames - i}.java",
                "SourceLine": 100 - i * 10,
                "VarNames": [f"var{n_frames - i}"],
                "FunctionName": f"method{n_frames - i}",
            }
            for i in range(n_frames)
        ]
        return {"stack_dump": [{"Frame": frames}]}

    def test_source_is_last_frame(self):
        raw = self._make_raw(n_frames=3)
        r = _normalize_veracode_trace(raw)
        # frame[-1] is the source
        assert r[0]["source"]["file"] == "src/Step1.java"
        assert r[0]["source"]["snippet"] == "var1"

    def test_sink_is_first_frame(self):
        raw = self._make_raw(n_frames=3)
        r = _normalize_veracode_trace(raw)
        # frame[0] is the sink
        assert r[0]["sink"]["file"] == "src/Step3.java"
        assert r[0]["sink"]["snippet"] == "var3"

    def test_middle_frames_become_steps(self):
        raw = self._make_raw(n_frames=4)
        r = _normalize_veracode_trace(raw)
        assert len(r[0]["steps"]) == 2

    def test_two_frames_no_steps(self):
        raw = self._make_raw(n_frames=2)
        r = _normalize_veracode_trace(raw)
        assert r[0]["steps"] == []

    def test_one_frame_source_and_sink_same(self):
        raw = self._make_raw(n_frames=1)
        r = _normalize_veracode_trace(raw)
        assert r[0]["source"] == r[0]["sink"]

    def test_none_input_returns_none(self):
        assert _normalize_veracode_trace(None) is None

    def test_empty_stack_dump_returns_none(self):
        assert _normalize_veracode_trace({"stack_dump": []}) is None

    def test_empty_frames_returns_none(self):
        assert _normalize_veracode_trace({"stack_dump": [{"Frame": []}]}) is None

    def test_fallback_to_function_name_when_no_var_names(self):
        raw = {"stack_dump": [{"Frame": [
            {"SourceFile": "A.java", "SourceLine": 10, "VarNames": [], "FunctionName": "doQuery"},
            {"SourceFile": "B.java", "SourceLine": 5, "VarNames": [], "FunctionName": "getInput"},
        ]}]}
        r = _normalize_veracode_trace(raw)
        # frame[-1] = source = B.java (getInput)
        assert r[0]["source"]["snippet"] == "getInput"
        assert r[0]["sink"]["snippet"] == "doQuery"

    def test_multiple_stack_dumps_return_multiple_paths(self):
        raw = {
            "stack_dump": [
                {"Frame": [
                    {"SourceFile": "A.java", "SourceLine": 20, "VarNames": ["sinkVar"], "FunctionName": "sinkMethod"},
                    {"SourceFile": "B.java", "SourceLine": 5,  "VarNames": ["srcVar"],  "FunctionName": "srcMethod"},
                ]},
                {"Frame": [
                    {"SourceFile": "C.java", "SourceLine": 30, "VarNames": ["altSink"], "FunctionName": "altSinkMethod"},
                    {"SourceFile": "D.java", "SourceLine": 2,  "VarNames": ["altSrc"],  "FunctionName": "altSrcMethod"},
                ]},
            ]
        }
        r = _normalize_veracode_trace(raw)
        assert len(r) == 2
        # each path is reversed: frame[-1] = source, frame[0] = sink
        assert r[0]["source"]["file"] == "B.java"
        assert r[0]["sink"]["file"] == "A.java"
        assert r[1]["source"]["file"] == "D.java"
        assert r[1]["sink"]["file"] == "C.java"

    def test_skips_dump_with_empty_frames_keeps_valid_ones(self):
        raw = {
            "stack_dump": [
                {"Frame": []},  # invalid — should be skipped
                {"Frame": [
                    {"SourceFile": "X.java", "SourceLine": 10, "VarNames": ["v"], "FunctionName": "f"},
                ]},
            ]
        }
        r = _normalize_veracode_trace(raw)
        assert len(r) == 1
        assert r[0]["source"]["file"] == "X.java"


class TestScanFilteredJson:
    """Test the scan() function using a stubbed package + filtered JSON."""

    def _make_cfg(self) -> VeracodeConfig:
        return VeracodeConfig(package_dir_name=".veracode", scan_workers=1)

    def test_scan_parses_filtered_json(self, tmp_path: Path):
        repo = tmp_path / "my-repo"
        repo.mkdir()
        sast_dir = tmp_path / ".sast-results"
        cfg = self._make_cfg()
        pkg_dir = sast_dir / cfg.package_dir_name
        pkg_dir.mkdir(parents=True)

        # Create a fake package file
        fake_pkg = pkg_dir / "my-repo-pack.zip"
        fake_pkg.write_bytes(b"PK")

        # Create filtered JSON that scan() will parse
        filtered_data = {
            "findings": [VERACODE_FINDING_DICT],
        }
        filtered_path = pkg_dir / f"filtered_{fake_pkg.stem}.json"
        filtered_path.write_text(json.dumps(filtered_data), encoding="utf-8")

        with (
            patch("triage.scanners.veracode.run_cmd", return_value=(True, "")) as mock_run,
        ):
            # _package should not be called (pkg_dir already has files)
            # We patch run_cmd to avoid calling the real veracode CLI
            # and pre-create the filtered output before scan_package is called.
            result = scan(repo, sast_dir, cfg)

        assert result.scan_engine == "veracode"
        assert result.repo_name == "my-repo"
        assert len(result.findings) == 1
        assert result.findings[0].cwe_id == "89"

    def test_missing_binary_raises_with_install_hint(self, tmp_path: Path):
        repo = tmp_path / "empty-repo"
        repo.mkdir()
        sast_dir = tmp_path / ".sast-results"
        cfg = self._make_cfg()

        with patch("triage.scanners.veracode.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="veracode is not installed"):
                scan(repo, sast_dir, cfg)

    def test_scan_raises_when_no_packages(self, tmp_path: Path):
        repo = tmp_path / "empty-repo"
        repo.mkdir()
        sast_dir = tmp_path / ".sast-results"
        cfg = self._make_cfg()

        with patch(
            "triage.scanners.veracode.run_cmd", return_value=(False, "packaging failed")
        ):
            with pytest.raises(RuntimeError, match="package produced no output"):
                scan(repo, sast_dir, cfg)
