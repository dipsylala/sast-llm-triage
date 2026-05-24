"""Test factories and shared sample data.

This module is the single source of truth for:
  - builder functions (make_finding, make_scan_result)
  - representative raw scanner payloads (SEMGREP_RESULT_DICT, VERACODE_FINDING_DICT)

Keeping non-fixture helpers here — rather than in conftest.py — ensures
conftest.py remains fixture-only and these helpers stay importable from
any test file without relying on pytest's path magic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from triage.models import Finding, ScanResult


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def make_finding(**overrides) -> Finding:
    """Return a Finding pre-populated with safe defaults.

    Pass keyword args to override any field, e.g.:
        make_finding(cwe_id="78", severity=5)
    """
    defaults: dict[str, Any] = dict(
        issue_id="1",
        scan_file="semgrep",
        cwe_id="89",
        issue_type="sql-injection",
        severity=4,
        file="app/db.py",
        line=42,
        scan_engine="semgrep",
        display_text="SQL injection sink",
        source_excerpt="",
        stack_dumps=None,
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# ScanResult builder
# ---------------------------------------------------------------------------


def make_scan_result(
    findings: list[Finding] | None = None,
    repo_name: str = "my-repo",
) -> ScanResult:
    """Return a ScanResult pre-populated with safe defaults."""
    findings = findings or []
    return ScanResult(
        repo_name=repo_name,
        repo_path=Path("/tmp") / repo_name,
        scan_engine="semgrep",
        findings=findings,
        total_raw=len(findings),
        repo_url=None,
    )


# ---------------------------------------------------------------------------
# Representative raw Semgrep result dict
# ---------------------------------------------------------------------------


SEMGREP_RESULT_DICT: dict = {
    "check_id": "python.lang.security.injection.tainted-sql-string",
    "path": "app/db.py",
    "start": {"line": 42, "col": 5},
    "end": {"line": 42, "col": 60},
    "extra": {
        "message": "SQL injection via tainted input",
        "severity": "ERROR",
        "metadata": {
            "cwe": ["CWE-89: SQL Injection"],
        },
    },
}


# ---------------------------------------------------------------------------
# Representative raw Veracode filtered-JSON finding dict
# ---------------------------------------------------------------------------


VERACODE_FINDING_DICT: dict = {
    "issue_id": "1042",
    "cwe_id": "89",
    "issue_type": "SQL Injection",
    "severity": 4,
    "display_text": "This call contains a SQL injection flaw.",
    "files": {
        "source_file": {
            "file": "src/main/java/App.java",
            "line": 88,
        }
    },
    "stack_dumps": None,
}


# ---------------------------------------------------------------------------
# Representative raw Snyk SARIF result + matching rule dict
# ---------------------------------------------------------------------------

SNYK_RULE_DICT: dict = {
    "id": "python/SQLInjection",
    "shortDescription": {"text": "SQL Injection"},
    "fullDescription": {"text": "Unsanitized input is passed to a SQL query."},
    "properties": {
        "tags": ["security"],
        "categories": ["Security"],
        "cwe": ["CWE-89"],
        "precision": "very-high",
    },
}

SNYK_RESULT_DICT: dict = {
    "ruleId": "python/SQLInjection",
    "ruleIndex": 0,
    "level": "error",
    "message": {"text": "SQL Injection: unsanitized input flows into cursor.execute."},
    "locations": [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "app/db.py", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 42, "endLine": 42, "startColumn": 5, "endColumn": 30},
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
                                    "artifactLocation": {"uri": "app/db.py", "uriBaseId": "%SRCROOT%"},
                                    "region": {"startLine": 10, "endLine": 10, "startColumn": 1, "endColumn": 30},
                                },
                            }
                        },
                        {
                            "location": {
                                "id": 1,
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/db.py", "uriBaseId": "%SRCROOT%"},
                                    "region": {"startLine": 42, "endLine": 42, "startColumn": 5, "endColumn": 30},
                                },
                            }
                        },
                    ]
                }
            ]
        }
    ],
}

# A minimal SARIF document (runs[0]) built from the above primitives.
SNYK_SARIF_DOC: dict = {
    "runs": [
        {
            "tool": {"driver": {"name": "SnykCode", "rules": [SNYK_RULE_DICT]}},
            "results": [SNYK_RESULT_DICT],
        }
    ]
}
