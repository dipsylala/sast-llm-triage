"""Stage 4 — Normalizer.

Filters findings to the qualifying CWE set, sorts, and writes two output files:

- ``<sast_dir>/raw_findings.json``     — all pre-filter findings
- ``<sast_dir>/triage_findings.json`` — filtered, sorted, ready for
  the LLM triage agent
"""

from __future__ import annotations

import json
import logging
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
    total_qualifying = len(qualifying)

    # --- Sort ---
    qualifying.sort(key=_sort_key)

    # --- Build combined findings dicts ---
    combined: list[dict] = []  # type: ignore[type-arg]
    for finding in qualifying:
        d = finding.to_dict()
        combined.append(d)

    # --- Write triage_findings.json ---
    payload = {
        "repo": result.repo_name,
        "repo_url": repo_url,
        "scan_engine": result.scan_engine,
        "total_qualifying": total_qualifying,
        "findings": combined,
    }

    combined_out = sast_dir / "triage_findings.json"
    combined_out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.info(
        "triage_findings written: %d qualifying finding(s) → %s",
        total_qualifying,
        combined_out,
    )

    return combined_out
