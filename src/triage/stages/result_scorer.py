"""Stage 3 — Result scorer.

Assigns a priority score to each finding based on its CWE ID and file path.

Score formula
-------------
    score = cwe_base_score + path_boost

CWE base scores
---------------
    77, 78  (command injection)          10
    120, 121, 787  (buffer overflow)     10
    415, 416  (double free / UAF)         9
    502  (unsafe deserialization)         9
    134  (format string)                  8
    22, 73, 98  (path traversal / LFI)   8
    190, 191  (integer overflow)          7
    89  (SQL injection)                   7
    918  (SSRF)                           6
    79, 80  (XSS)                         3
    (any other qualifying CWE)            2

Path boosts (+3 each)
---------------------
    file path contains "controllers/"
    file path contains "routes/"
"""

from __future__ import annotations

from triage.models import Finding

# Single source of truth for scoring rules.
_CWE_BASE_SCORES: dict[str, int] = {
    "77":  10,
    "78":  10,
    "120": 10,
    "121": 10,
    "787": 10,
    "415":  9,
    "416":  9,
    "502":  9,
    "134":  8,
    "22":   8,
    "73":   8,
    "98":   8,
    "190":  7,
    "191":  7,
    "89":   7,
    "918":  6,
    "79":   3,
    "80":   3,
}

_DEFAULT_CWE_SCORE = 2

_PATH_BOOSTS: dict[str, int] = {
    "controllers/": 3,
    "routes/":      3,
}


def _cwe_base(cwe_id: str) -> int:
    return _CWE_BASE_SCORES.get(cwe_id, _DEFAULT_CWE_SCORE)


def _path_boost(file_path: str) -> int:
    normalised = file_path.replace("\\", "/")
    return sum(
        boost
        for fragment, boost in _PATH_BOOSTS.items()
        if fragment in normalised
    )


def score(findings: list[Finding]) -> list[Finding]:
    """Set ``Finding.score`` for every finding in *findings*.

    Mutates the findings in place and also returns the list for convenience.

    Args:
        findings: List of findings to score.

    Returns:
        The same list of findings with ``score`` populated.
    """
    for finding in findings:
        finding.score = _cwe_base(finding.cwe_id) + _path_boost(finding.file)
    return findings
