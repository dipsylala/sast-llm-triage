"""Finding — single SAST finding from any scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """A single vulnerability finding produced by Veracode or Semgrep.

    Fields are intentionally compatible with the ``triage_findings.json``
    schema consumed by ``agents/scan-repo.md``.
    """

    # --- identity ---
    issue_id: str
    """Unique ID within this scan.  Veracode: numeric string.
    Semgrep: ``<check_id>:<path>:<line>``.
    Snyk: ``<rule_id>:<uri>:<line>``."""

    scan_file: str
    """Source filename that produced this finding.
    Veracode: the filtered JSON filename.  Semgrep/Snyk: the scanner name string."""

    cwe_id: str
    """CWE number as a plain string, e.g. ``"89"``.  Empty string when
    the scanner did not map the finding to a CWE."""

    issue_type: str
    """Human-readable flaw category (e.g. ``"SQL Injection"``)."""

    # --- location ---
    file: str
    """Repo-relative source file path."""

    line: int
    """1-based line number of the sink."""

    # --- metadata ---
    scan_engine: str
    """``"veracode"``, ``"semgrep"``, or ``"snyk"``."""

    severity: int = 0
    """0–5 severity scale (Veracode convention: 4 = High, 5 = Very High).
    Semgrep severities are mapped: CRITICAL→5, ERROR→4, WARNING→3, INFO→1."""

    display_text: str = ""
    """Tool description of the flaw class."""

    # --- enriched by result_enricher ---
    source_excerpt: str = ""
    """Sink line marked ``>>>`` plus ±context lines.  Populated by
    :mod:`triage.stages.result_enricher`."""

    # --- scored by result_scorer ---
    score: int = 0
    """Priority score.  Populated by :mod:`triage.stages.result_scorer`."""

    # --- optional extra data ---
    stack_dumps: list[dict[str, Any]] | None = field(default=None, repr=False)
    """Normalized data-flow paths produced by the scanner, or ``None``.

    A list of paths; each path has the same schema (source → sink)::

        [
            {
                "source": {"file": str, "line": int, "snippet": str},
                "steps":  [{"file": str, "line": int, "snippet": str}, ...],
                "sink":   {"file": str, "line": int, "snippet": str},
            },
            ...  # Veracode may yield multiple paths per finding
        ]

    Only present when the scanner resolved at least one complete source → sink
    path.  Semgrep always produces exactly one path; Veracode may produce
    several (one per distinct call chain reaching the same sink); Snyk produces
    one path per ``codeFlow`` entry.
    """

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict."""
        d: dict[str, Any] = {
            "issue_id": self.issue_id,
            "scan_file": self.scan_file,
            "cwe_id": self.cwe_id,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "scan_engine": self.scan_engine,
            "display_text": self.display_text,
            "source_excerpt": self.source_excerpt,
            "score": self.score,
        }
        if self.stack_dumps is not None:
            d["stack_dumps"] = self.stack_dumps
        return d
