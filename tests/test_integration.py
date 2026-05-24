"""Integration tests — full pipeline from scan through triage_findings.json.

Each test exercises all stages (scan → enrich → normalize)
against a real temporary repository directory.  Only the external CLI call
is mocked; the enricher actually reads source files from disk so
source_excerpt is populated from real content.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from triage.config import SemgrepConfig, SnykConfig, VeracodeConfig
from triage.scanners import semgrep as semgrep_scanner
from triage.scanners import snyk as snyk_scanner
from triage.scanners import veracode as veracode_scanner
from factories import make_finding
from triage.stages.result_enricher import enrich
from triage.stages.normalizer import normalize

_QUALIFYING_CWES: frozenset[str] = frozenset({"89", "78"})


# ---------------------------------------------------------------------------
# Semgrep integration test
# ---------------------------------------------------------------------------


# Realistic semgrep JSON with a CWE-89 taint finding + dataflow_trace.
# Paths are repo-relative, matching real semgrep output when given a directory.
_SEMGREP_OUTPUT = json.dumps({
    "results": [{
        "check_id": "python.lang.security.injection.tainted-sql-string",
        "path": "app/db.py",
        "start": {"line": 9, "col": 5},
        "end":   {"line": 9, "col": 30},
        "extra": {
            "severity": "ERROR",
            "message": "User-controlled data flows into cursor.execute().",
            "metadata": {"cwe": ["CWE-89: SQL Injection"]},
            "dataflow_trace": {
                "taint_source": {
                    "location": {
                        "path": "routes/api.py",
                        "start": {"line": 4, "col": 11},
                        "end":   {"line": 4, "col": 35},
                    },
                    "content": "request.args.get('id')",
                },
                "intermediate_vars": [{
                    "location": {
                        "path": "app/db.py",
                        "start": {"line": 7, "col": 13},
                        "end":   {"line": 7, "col": 18},
                    },
                    "content": "query",
                }],
                "taint_sink": {
                    "location": {
                        "path": "app/db.py",
                        "start": {"line": 9, "col": 5},
                        "end":   {"line": 9, "col": 30},
                    },
                    "content": "cursor.execute(query)",
                },
            },
        },
    }],
    "errors": [],
})


class TestSemgrepPipeline:
    """Full pipeline: semgrep scan → enrich → normalize."""

    def test_triage_findings_written(self, mini_repo: Path, tmp_path: Path):
        cfg = SemgrepConfig(config="auto", pro=False)
        sast_dir = tmp_path / "out" / ".sast-results"

        with patch(
            "triage.scanners.semgrep.capture_cmd",
            return_value=(True, _SEMGREP_OUTPUT, ""),
        ):
            result = semgrep_scanner.scan(mini_repo, cfg)

        enrich(result.findings, mini_repo, 8)
        out_path = normalize(result, _QUALIFYING_CWES, sast_dir)

        assert out_path.exists()
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        assert payload["scan_engine"] == "semgrep"
        assert payload["total_qualifying"] == 1
        assert len(payload["findings"]) == 1

    def test_source_excerpt_populated(self, mini_repo: Path, tmp_path: Path):
        cfg = SemgrepConfig(config="auto", pro=False)

        with patch(
            "triage.scanners.semgrep.capture_cmd",
            return_value=(True, _SEMGREP_OUTPUT, ""),
        ):
            result = semgrep_scanner.scan(mini_repo, cfg)

        enrich(result.findings, mini_repo, 8)
        finding = result.findings[0]

        assert ">>>" in finding.source_excerpt
        assert "cursor.execute" in finding.source_excerpt

    def test_dataflow_trace_normalized(self, mini_repo: Path, tmp_path: Path):
        cfg = SemgrepConfig(config="auto", pro=False)

        with patch(
            "triage.scanners.semgrep.capture_cmd",
            return_value=(True, _SEMGREP_OUTPUT, ""),
        ):
            result = semgrep_scanner.scan(mini_repo, cfg)

        finding = result.findings[0]

        assert finding.stack_dumps is not None
        assert len(finding.stack_dumps) == 1  # semgrep always one path
        p = finding.stack_dumps[0]
        assert p["source"]["snippet"] == "request.args.get('id')"
        assert p["source"]["line"] == 4
        assert len(p["steps"]) == 1
        assert p["steps"][0]["snippet"] == "query"
        assert p["sink"]["snippet"] == "cursor.execute(query)"
        assert p["sink"]["line"] == 9

    def test_dataflow_trace_populated(self, mini_repo: Path, tmp_path: Path):
        """enrich() fills empty stack_dumps snippets from source files."""
        finding = make_finding(
            file="app/db.py",
            line=9,
            stack_dumps=[
                {
                    "source": {"file": "routes/api.py", "line": 4, "snippet": ""},
                    "steps": [{"file": "app/db.py", "line": 7, "snippet": ""}],
                    "sink": {"file": "app/db.py", "line": 9, "snippet": ""},
                }
            ],
        )

        enrich([finding], mini_repo, context_lines=2)

        p = finding.stack_dumps[0]
        assert p["source"]["snippet"] == "uid = request.args.get('id')"
        assert p["steps"][0]["snippet"] == "query = 'SELECT * FROM users WHERE id=' + user_id"
        assert p["sink"]["snippet"] == "cursor.execute(query)"


def _veracode_filtered_json() -> dict:
    return {
        "findings": [{
            "issue_id": "2001",
            "cwe_id": "89",
            "issue_type": "SQL Injection",
            "severity": 4,
            "display_text": "User input flows into cursor.execute() without sanitization.",
            "files": {
                "source_file": {
                    "file": "app/db.py",
                    "line": 9,
                }
            },
            # Veracode stores frames sink-first; two separate call chains.
            "stack_dumps": {
                "stack_dump": [
                    {
                        "Frame": [
                            {"SourceFile": "app/db.py",     "SourceLine": 9, "VarNames": ["query"],  "FunctionName": "get_user"},
                            {"SourceFile": "routes/api.py", "SourceLine": 4, "VarNames": ["uid"],    "FunctionName": "search"},
                        ]
                    },
                    {
                        "Frame": [
                            {"SourceFile": "app/db.py",     "SourceLine": 9, "VarNames": ["query"],  "FunctionName": "get_user"},
                            {"SourceFile": "routes/api.py", "SourceLine": 5, "VarNames": ["result"], "FunctionName": "search"},
                        ]
                    },
                ]
            },
        }]
    }


class TestVeracodePipeline:
    """Full pipeline: veracode scan (mocked CLI) → enrich → normalize."""

    def _run_pipeline(self, mini_repo: Path, tmp_path: Path) -> tuple[dict, list]:
        """Run all pipeline stages and return (payload, findings list)."""
        cfg = VeracodeConfig(package_dir_name=".veracode", scan_workers=1)
        sast_dir = tmp_path / ".sast-results"
        pkg_dir = sast_dir / cfg.package_dir_name
        pkg_dir.mkdir(parents=True)

        # Pre-create the package file and filtered JSON to simulate CLI output.
        fake_pkg = pkg_dir / "mini-repo-pack.zip"
        fake_pkg.write_bytes(b"PK\x03\x04")
        (pkg_dir / f"filtered_{fake_pkg.stem}.json").write_text(
            json.dumps(_veracode_filtered_json()), encoding="utf-8"
        )

        with patch("triage.scanners.veracode.run_cmd", return_value=(True, "")):
            result = veracode_scanner.scan(mini_repo, sast_dir, cfg)

        enrich(result.findings, mini_repo, 8)
        out_path = normalize(result, _QUALIFYING_CWES, sast_dir)

        payload = json.loads(out_path.read_text(encoding="utf-8"))
        return payload, payload["findings"]

    def test_triage_findings_written(self, mini_repo: Path, tmp_path: Path):
        payload, findings = self._run_pipeline(mini_repo, tmp_path)

        assert payload["scan_engine"] == "veracode"
        assert payload["total_qualifying"] == 1
        assert len(findings) == 1

    def test_source_excerpt_populated(self, mini_repo: Path, tmp_path: Path):
        _, findings = self._run_pipeline(mini_repo, tmp_path)
        excerpt = findings[0]["source_excerpt"]

        assert ">>>" in excerpt
        assert "cursor.execute" in excerpt

    def test_multi_path_stack_dumps(self, mini_repo: Path, tmp_path: Path):
        """Two stack_dump entries produce two normalized paths."""
        _, findings = self._run_pipeline(mini_repo, tmp_path)
        stack_dumps = findings[0]["stack_dumps"]

        assert isinstance(stack_dumps, list)
        assert len(stack_dumps) == 2

        # Each path: frames reversed, so frame[-1]=source, frame[0]=sink.
        for path in stack_dumps:
            assert path["source"]["file"] == "routes/api.py"
            assert path["sink"]["file"] == "app/db.py"
            assert path["sink"]["line"] == 9

        # The two paths differ in source line (entry point).
        source_lines = {p["source"]["line"] for p in stack_dumps}
        assert source_lines == {4, 5}


# ---------------------------------------------------------------------------
# Snyk Code integration test
# ---------------------------------------------------------------------------

_SNYK_PIPELINE_SARIF: dict = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "SnykCode",
                    "rules": [
                        {
                            "id": "python/SqlInjection",
                            "shortDescription": {"text": "SQL Injection"},
                            "help": {"markdown": "Unsanitized input in SQL query.", "text": ""},
                            "properties": {
                                "tags": ["security"],
                                "cwe": ["CWE-89: Improper Neutralization of Special Elements"],
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python/SqlInjection",
                    "ruleIndex": 0,
                    "level": "error",
                    "message": {"text": "SQL Injection: user input flows to cursor.execute."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/db.py", "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": 9, "endLine": 9, "startColumn": 5, "endColumn": 28},
                            }
                        }
                    ],
                    "properties": {"priorityScore": 850, "isAutofixable": False},
                    "codeFlows": [
                        {
                            "threadFlows": [
                                {
                                    "locations": [
                                        {
                                            "location": {
                                                "id": 0,
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "routes/api.py", "uriBaseId": "%SRCROOT%"},
                                                    "region": {"startLine": 4},
                                                },
                                            }
                                        },
                                        {
                                            "location": {
                                                "id": 1,
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "app/db.py", "uriBaseId": "%SRCROOT%"},
                                                    "region": {"startLine": 9},
                                                },
                                            }
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                }
            ],
        }
    ],
}


class TestSnykPipeline:
    """Full scan → enrich → normalize pipeline for Snyk Code."""

    def _cfg(self) -> SnykConfig:
        return SnykConfig()

    def _run_pipeline(
        self, mini_repo: Path, tmp_path: Path
    ) -> tuple[Path, list[dict]]:
        sarif_json = json.dumps(_SNYK_PIPELINE_SARIF)
        with (
            patch("shutil.which", return_value="/usr/bin/snyk"),
            patch(
                "triage.scanners.snyk.capture_cmd",
                return_value=(True, sarif_json, ""),
            ),
        ):
            scan_result = snyk_scanner.scan(mini_repo, self._cfg())

        enrich(scan_result.findings, mini_repo)
        out_dir = tmp_path / "output"
        out_path = normalize(scan_result, _QUALIFYING_CWES, out_dir)
        findings = json.loads(out_path.read_text())["findings"]
        return out_path, findings

    def test_finding_count(self, mini_repo: Path, tmp_path: Path):
        """One SQL injection finding expected."""
        _, findings = self._run_pipeline(mini_repo, tmp_path)
        assert len(findings) == 1

    def test_finding_cwe(self, mini_repo: Path, tmp_path: Path):
        """CWE-89 parsed from SARIF rule properties."""
        _, findings = self._run_pipeline(mini_repo, tmp_path)
        assert findings[0]["cwe_id"] == "89"

    def test_finding_source_excerpt(self, mini_repo: Path, tmp_path: Path):
        """Enricher should populate source_excerpt from app/db.py line 9."""
        _, findings = self._run_pipeline(mini_repo, tmp_path)
        assert "cursor.execute" in findings[0]["source_excerpt"]
