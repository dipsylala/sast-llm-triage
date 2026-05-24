"""Stage 4 — Normalizer.

Filters findings to the qualifying CWE set, sorts, and writes three output files:

- ``<sast_dir>/raw_findings.json``       — all pre-filter findings
- ``<sast_dir>/triage_findings.json``   — filtered, sorted, ready for
  the LLM triage agent
- ``<sast_dir>/findings_summary.md``    — Markdown index for agent orientation
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path

from triage.models import Finding, ScanResult

logger = logging.getLogger(__name__)


def _sort_key(f: Finding) -> tuple[int, int, str]:
    """Sort findings: severity desc, CWE asc (numeric), issue_id asc."""
    try:
        cwe_int = int(f.cwe_id) if f.cwe_id else 9999
    except ValueError:
        cwe_int = 9999
    return (-f.severity, cwe_int, f.issue_id)


def normalize(
    result: ScanResult,
    qualifying_cwes: frozenset[str],
    sast_dir: Path,
    repo_url: str | None = None,
) -> Path:
    """Filter, sort, and write ``triage_findings.json``.

    Args:
        result: The enriched :class:`ScanResult`.
        qualifying_cwes: Set of CWE ID strings to include.
        sast_dir: Directory where output files are written
            (``<output_dir>/<repo_name>/.sast-results``).
        repo_url: Original remote URL, if known.

    Returns:
        Absolute path to the written ``triage_findings.json``.
    """
    sast_dir.mkdir(parents=True, exist_ok=True)

    # --- Write raw findings ---
    raw_out = sast_dir / "raw_findings.json"
    raw_out.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.debug("raw_findings written to %s", raw_out)

    # --- Filter ---
    qualifying = [f for f in result.findings if f.cwe_id in qualifying_cwes]
    total_pre_dedup = len(qualifying)

    # --- Deduplicate by (file, line, cwe_id) ---
    # Multiple rules often flag the same sink.  Keep one representative per
    # unique location; the others are recorded in `also_flagged_by`.
    groups: dict[tuple[str, int, str], list[Finding]] = defaultdict(list)
    for f in qualifying:
        groups[(f.file, f.line, f.cwe_id)].append(f)

    also_flagged_by: dict[str, list[str]] = {}
    representatives: list[Finding] = []
    for group in groups.values():
        # Prefer highest severity; break ties by preferring findings with stack_dumps.
        rep = max(group, key=lambda f: (f.severity, 1 if f.stack_dumps else 0))
        representatives.append(rep)
        others = [f.issue_id for f in group if f.issue_id != rep.issue_id]
        if others:
            also_flagged_by[rep.issue_id] = others

    total_qualifying = len(representatives)

    # --- Sort ---
    representatives.sort(key=_sort_key)

    # --- Build combined findings dicts ---
    combined: list[dict] = []  # type: ignore[type-arg]
    for finding in representatives:
        d = finding.to_dict()
        if finding.issue_id in also_flagged_by:
            d["also_flagged_by"] = also_flagged_by[finding.issue_id]
        combined.append(d)

    # --- Write triage_findings.json ---
    payload = {
        "repo": result.repo_name,
        "repo_url": repo_url,
        "scan_engine": result.scan_engine,
        "total_pre_dedup": total_pre_dedup,
        "total_qualifying": total_qualifying,
        "findings": combined,
    }

    combined_out = sast_dir / "triage_findings.json"
    combined_out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.info(
        "triage_findings written: %d qualifying finding(s), %d after dedup → %s",
        total_pre_dedup,
        total_qualifying,
        combined_out,
    )

    _write_findings_summary(representatives, sast_dir)

    return combined_out


def _write_findings_summary(findings: list[Finding], sast_dir: Path) -> None:
    """Write ``findings_summary.md`` — a Markdown index of qualifying findings."""
    rows = [
        "# Findings Summary",
        "",
        "| issue_id | sev | CWE | issue_type | file:line | stack_dumps? |",
        "| -------- | --- | --- | ---------- | --------- | ------------ |",
    ]
    severity_counts: dict[int, int] = {}
    cwe_counts: dict[str, int] = {}

    for f in findings:
        has_dumps = "yes" if f.stack_dumps else "no"
        rows.append(
            f"| {f.issue_id} | {f.severity} | {f.cwe_id} | {f.issue_type} "
            f"| {f.file}:{f.line} | {has_dumps} |"
        )
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        cwe_counts[f.cwe_id] = cwe_counts.get(f.cwe_id, 0) + 1

    rows += ["", "## Counts by severity", ""]
    for sev in sorted(severity_counts, reverse=True):
        rows.append(f"- {sev}: {severity_counts[sev]}")

    rows += ["", "## Counts by CWE", ""]
    for cwe in sorted(cwe_counts, key=lambda c: (int(c) if c.isdigit() else 9999)):
        rows.append(f"- CWE-{cwe}: {cwe_counts[cwe]}")

    summary_out = sast_dir / "findings_summary.md"
    summary_out.write_text("\n".join(rows) + "\n", encoding="utf-8")
    logger.debug("findings_summary written to %s", summary_out)
