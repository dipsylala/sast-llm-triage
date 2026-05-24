"""Stage 2 — Result enricher.

Reads ±N source lines around each finding's reported line and populates
``Finding.source_excerpt``.  The sink line is marked with ``>>>``.

Also fills empty ``snippet`` fields on ``stack_dumps`` nodes so the LLM
agent does not need a separate ``read_file`` call per data-flow step.
"""

from __future__ import annotations

import logging
from pathlib import Path

from triage.models import Finding

logger = logging.getLogger(__name__)


def _safe_resolve(local_path: Path, file_rel: str) -> Path | None:
    """Resolve *file_rel* relative to *local_path*, preventing path traversal.

    Returns ``None`` if the resolved path escapes *local_path* or does not
    exist.
    """
    if not file_rel:
        return None

    # Normalise separators and strip leading slashes that would make
    # Path() treat the value as absolute.
    normalised = file_rel.replace("\\", "/").lstrip("/")

    try:
        resolved = (local_path / normalised).resolve()
    except (OSError, ValueError):
        return None

    # Prevent path traversal outside the repository root.
    try:
        resolved.relative_to(local_path.resolve())
    except ValueError:
        logger.warning(
            "path traversal attempt blocked: %s resolves outside %s",
            file_rel,
            local_path,
        )
        return None

    if not resolved.is_file():
        # Veracode sometimes prefixes paths with an extra top-level segment
        # (the package name).  Try stripping the first component.
        parts = Path(normalised).parts
        if len(parts) > 1:
            alt = (local_path / Path(*parts[1:])).resolve()
            try:
                alt.relative_to(local_path.resolve())
            except ValueError:
                return None
            if alt.is_file():
                return alt
        return None

    return resolved


def _build_excerpt(lines: list[str], sink_line: int, context: int) -> str:
    """Build a formatted excerpt around *sink_line* (1-based)."""
    total = len(lines)
    start = max(0, sink_line - context - 1)
    end = min(total, sink_line + context)
    out: list[str] = []
    for i in range(start, end):
        lineno = i + 1
        marker = ">>>" if lineno == sink_line else "   "
        out.append(f"{lineno:5d} {marker} {lines[i].rstrip()}")
    return "\n".join(out)


def enrich(
    findings: list[Finding],
    local_path: Path,
    context_lines: int = 4,
) -> list[Finding]:
    """Populate ``Finding.source_excerpt`` for every finding in *findings*.

    Mutates the findings in place and also returns the list for convenience.

    Args:
        findings: List of findings to enrich.
        local_path: Absolute path to the repository root.
        context_lines: Number of source lines to include either side of the
            sink line.

    Returns:
        The same list of findings, with ``source_excerpt`` populated.
    """
    local_path = local_path.resolve()

    for finding in findings:
        resolved = _safe_resolve(local_path, finding.file)
        if resolved is None:
            finding.source_excerpt = f"[source file not found: {finding.file}]"
            continue

        try:
            source_lines = resolved.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError as exc:
            finding.source_excerpt = f"[could not read {finding.file}: {exc}]"
            continue

        if finding.line < 1 or finding.line > len(source_lines):
            finding.source_excerpt = (
                f"[line {finding.line} out of range in {finding.file}]"
            )
            continue

        finding.source_excerpt = _build_excerpt(
            source_lines, finding.line, context_lines
        )

    for finding in findings:
        _enrich_stack_dumps(finding, local_path)

    return findings


def _enrich_stack_dumps(finding: Finding, local_path: Path) -> None:
    """Populate missing ``snippet`` values in every stack-dump node.

    Uses the full repo-relative path in each node's ``file`` field to resolve
    files unambiguously.  Nodes whose ``file`` does not resolve (bare filename,
    path traversal, missing file) are left unchanged rather than guessing.
    File contents are cached per path to avoid redundant reads across nodes
    that share a file.
    """
    if not finding.stack_dumps:
        return

    file_cache: dict[str, list[str]] = {}

    for path in finding.stack_dumps:
        nodes = []
        if "source" in path:
            nodes.append(path["source"])
        nodes.extend(path.get("steps", []))
        if "sink" in path:
            nodes.append(path["sink"])

        for node in nodes:
            if node.get("snippet"):
                continue  # already populated

            file_rel: str = node.get("file") or ""
            line_num: int = node.get("line") or 0
            if not file_rel or line_num < 1:
                continue

            if file_rel not in file_cache:
                resolved = _safe_resolve(local_path, file_rel)
                if resolved is None:
                    file_cache[file_rel] = []  # unresolvable — skip all nodes from this file
                    continue
                try:
                    file_cache[file_rel] = resolved.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                except OSError:
                    file_cache[file_rel] = []
                    continue

            source_lines = file_cache[file_rel]
            if not source_lines or line_num > len(source_lines):
                continue

            node["snippet"] = source_lines[line_num - 1].strip()
