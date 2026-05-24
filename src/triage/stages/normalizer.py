"""Stage 4 — Normalizer.

Filters findings to the qualifying CWE set, sorts, and writes two output files:

- ``<sast_dir>/raw_findings.json``     — all pre-filter findings
- ``<sast_dir>/combined_results.json`` — filtered, sorted, ready for
  the LLM triage agent (optionally capped via ``max_findings`` config)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from triage.models import Finding, ScanResult

logger = logging.getLogger(__name__)

_CAP_NOTE_TEMPLATE = (
    "NOTE: Capped at {max} of {total} total findings due to volume."
)


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
    max_findings: int,
    sast_dir: Path,
    repo_url: str | None = None,
) -> Path:
    """Filter, sort, cap, enrich, and write ``combined_results.json``.

    Args:
        result: The enriched and scored :class:`ScanResult`.
        qualifying_cwes: Set of CWE ID strings to include.
        max_findings: Maximum number of findings in ``combined_results.json``.
        sast_dir: Directory where output files are written
            (``<output_dir>/<repo_name>/.sast-results``).
        repo_url: Original remote URL, if known.

    Returns:
        Absolute path to the written ``combined_results.json``.
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

    # --- Cap (max_findings == 0 means no cap) ---
    capped = bool(max_findings) and total_qualifying > max_findings
    to_write = qualifying[:max_findings] if max_findings else qualifying

    # --- Build combined findings dicts ---
    combined: list[dict] = []  # type: ignore[type-arg]
    for i, finding in enumerate(to_write):
        d = finding.to_dict()
        if capped and i == 0:
            d["reasoning_note"] = _CAP_NOTE_TEMPLATE.format(
                max=max_findings, total=total_qualifying
            )
        combined.append(d)

    # --- Write combined_results.json ---
    payload = {
        "repo": result.repo_name,
        "repo_url": repo_url,
        "scan_engine": result.scan_engine,
        "total_qualifying": total_qualifying,
        "assessed_count": len(combined),
        "capped": capped,
        "findings": combined,
    }

    combined_out = sast_dir / "combined_results.json"
    combined_out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.info(
        "combined_results written: %d/%d qualifying finding(s)%s → %s",
        len(combined),
        total_qualifying,
        " (capped)" if capped else "",
        combined_out,
    )

    return combined_out
