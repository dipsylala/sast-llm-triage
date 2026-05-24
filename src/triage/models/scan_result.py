"""ScanResult — container returned by every scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .finding import Finding


@dataclass
class ScanResult:
    """All findings produced by a single scanner invocation."""

    repo_name: str
    """Repository name derived from the URL or local path."""

    repo_path: Path
    """Absolute path to the cloned or provided source directory."""

    scan_engine: str
    """``"veracode"`` or ``"semgrep"``."""

    findings: list[Finding] = field(default_factory=list)
    """Raw findings before any CWE filtering or capping."""

    total_raw: int = 0
    """Count of raw findings before any processing.  Set by the scanner."""

    repo_url: str | None = None
    """Original URL when the repo was cloned from a remote.  ``None`` for
    local paths."""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict of all raw findings."""
        return {
            "repo": self.repo_name,
            "repo_url": self.repo_url,
            "scan_engine": self.scan_engine,
            "total_raw": self.total_raw,
            "findings": [f.to_dict() for f in self.findings],
        }
