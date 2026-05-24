"""Tests for triage.stages.normalizer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from factories import make_finding, make_scan_result
from triage.stages.normalizer import normalize


def _make_result(findings=None, repo_name="my-repo"):
    return make_scan_result(findings=findings, repo_name=repo_name)


QUALIFYING = frozenset(["89", "78", "22", "79"])


class TestNormalizeFiltering:
    def test_non_qualifying_cwe_excluded(self, tmp_path: Path):
        findings = [
            make_finding(cwe_id="89", severity=4, issue_id="1"),   # qualifying
            make_finding(cwe_id="999", severity=5, issue_id="2"),  # NOT qualifying
        ]
        result = _make_result(findings)
        combined_path = normalize(result, QUALIFYING, sast_dir=tmp_path)
        data = json.loads(combined_path.read_text())
        assert data["total_qualifying"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["cwe_id"] == "89"

    def test_qualifying_findings_all_included(self, tmp_path: Path):
        findings = [make_finding(cwe_id="89", issue_id=str(i)) for i in range(5)]
        result = _make_result(findings)
        combined_path = normalize(result, QUALIFYING, sast_dir=tmp_path)
        data = json.loads(combined_path.read_text())
        assert len(data["findings"]) == 5


class TestNormalizeSortOrder:
    def test_sorted_by_severity_descending(self, tmp_path: Path):
        findings = [
            make_finding(cwe_id="89", severity=2, issue_id="low"),
            make_finding(cwe_id="89", severity=5, issue_id="high"),
            make_finding(cwe_id="89", severity=3, issue_id="med"),
        ]
        result = _make_result(findings)
        combined_path = normalize(result, QUALIFYING, sast_dir=tmp_path)
        data = json.loads(combined_path.read_text())
        severities = [f["severity"] for f in data["findings"]]
        assert severities == sorted(severities, reverse=True)

    def test_secondary_sort_by_cwe_ascending(self, tmp_path: Path):
        findings = [
            make_finding(cwe_id="89", severity=4, issue_id="sql"),
            make_finding(cwe_id="22", severity=4, issue_id="path"),
            make_finding(cwe_id="79", severity=4, issue_id="xss"),
        ]
        result = _make_result(findings)
        combined_path = normalize(result, QUALIFYING, sast_dir=tmp_path)
        data = json.loads(combined_path.read_text())
        cwes = [int(f["cwe_id"]) for f in data["findings"]]
        assert cwes == sorted(cwes)


class TestNormalizeOutput:
    def test_triage_findings_written(self, tmp_path: Path):
        result = _make_result([make_finding(cwe_id="89")])
        combined_path = normalize(result, QUALIFYING, sast_dir=tmp_path)
        assert combined_path.exists()
        assert combined_path.name == "triage_findings.json"

    def test_raw_findings_written(self, tmp_path: Path):
        result = _make_result([make_finding(cwe_id="89")])
        normalize(result, QUALIFYING, sast_dir=tmp_path)
        raw_path = tmp_path / "raw_findings.json"
        assert raw_path.exists()
        data = json.loads(raw_path.read_text())
        assert "findings" in data

    def test_triage_findings_structure(self, tmp_path: Path):
        findings = [make_finding(cwe_id="89", issue_id="1")]
        result = _make_result(findings, repo_name="test-repo")
        result.repo_url = "https://github.com/owner/test-repo"
        combined_path = normalize(
            result, QUALIFYING, sast_dir=tmp_path, repo_url=result.repo_url
        )
        data = json.loads(combined_path.read_text())
        assert data["repo"] == "test-repo"
        assert data["repo_url"] == "https://github.com/owner/test-repo"
        assert data["scan_engine"] == "semgrep"
        assert "total_qualifying" in data
        assert isinstance(data["findings"], list)

    def test_empty_findings_writes_empty_list(self, tmp_path: Path):
        result = _make_result([])
        combined_path = normalize(result, QUALIFYING, sast_dir=tmp_path)
        data = json.loads(combined_path.read_text())
        assert data["findings"] == []
        assert data["total_qualifying"] == 0

    def test_sast_dir_created_if_not_exists(self, tmp_path: Path):
        sast_dir = tmp_path / "new" / ".sast-results"
        result = _make_result([])
        normalize(result, QUALIFYING, sast_dir=sast_dir)
        assert sast_dir.is_dir()


class TestFindingsSummary:
    def test_summary_written(self, tmp_path: Path):
        result = _make_result([make_finding(cwe_id="89")])
        normalize(result, QUALIFYING, sast_dir=tmp_path)
        assert (tmp_path / "findings_summary.md").exists()

    def test_summary_contains_table_header(self, tmp_path: Path):
        result = _make_result([make_finding(cwe_id="89")])
        normalize(result, QUALIFYING, sast_dir=tmp_path)
        text = (tmp_path / "findings_summary.md").read_text(encoding="utf-8")
        assert "| issue_id |" in text
        assert "| -------- |" in text

    def test_summary_contains_finding_row(self, tmp_path: Path):
        f = make_finding(cwe_id="89", issue_id="42", severity=4)
        result = _make_result([f])
        normalize(result, QUALIFYING, sast_dir=tmp_path)
        text = (tmp_path / "findings_summary.md").read_text(encoding="utf-8")
        assert "42" in text
        assert "89" in text

    def test_summary_stack_dumps_flag(self, tmp_path: Path):
        with_dumps = make_finding(
            cwe_id="89", issue_id="1",
            stack_dumps=[{"source": {}, "steps": [], "sink": {}}],
        )
        without_dumps = make_finding(cwe_id="78", issue_id="2", stack_dumps=None)
        result = _make_result([with_dumps, without_dumps])
        normalize(result, QUALIFYING, sast_dir=tmp_path)
        text = (tmp_path / "findings_summary.md").read_text(encoding="utf-8")
        assert "yes" in text
        assert "no" in text

    def test_summary_severity_and_cwe_counts(self, tmp_path: Path):
        findings = [
            make_finding(cwe_id="89", severity=4, issue_id="1"),
            make_finding(cwe_id="89", severity=4, issue_id="2"),
            make_finding(cwe_id="78", severity=3, issue_id="3"),
        ]
        result = _make_result(findings)
        normalize(result, QUALIFYING, sast_dir=tmp_path)
        text = (tmp_path / "findings_summary.md").read_text(encoding="utf-8")
        assert "## Counts by severity" in text
        assert "## Counts by CWE" in text
        assert "4: 2" in text
        assert "3: 1" in text
        assert "CWE-78: 1" in text
        assert "CWE-89: 2" in text

    def test_summary_written_for_empty_findings(self, tmp_path: Path):
        result = _make_result([])
        normalize(result, QUALIFYING, sast_dir=tmp_path)
        assert (tmp_path / "findings_summary.md").exists()
