"""Semgrep scanner — runs ``semgrep --config auto --json`` locally.

Semgrep runs entirely on the local machine.  Source code is never uploaded.
Rule definitions are fetched from the Semgrep registry (``--config auto``);
semgrep handles caching automatically.

Set ``semgrep.pro: true`` in config.yaml and export ``SEMGREP_APP_TOKEN``
to enable the Semgrep Pro Engine (interfile analysis).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from triage.config import SemgrepConfig
from triage.models import Finding, ScanResult

from .base import _tool_available, capture_cmd

logger = logging.getLogger(__name__)

# Semgrep severity → Veracode 0-5 scale
_SEVERITY_MAP: dict[str, int] = {
    "CRITICAL": 5,
    "ERROR": 4,
    "WARNING": 3,
    "INFO": 1,
}

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _extract_cwe(cwe_field: Any) -> str:
    """Return the first CWE number found in a semgrep metadata CWE value.

    The field may be a list of strings (``["CWE-89: SQL Injection"]``), a
    single string, or absent / ``None``.
    """
    if not cwe_field:
        return ""

    candidates: list[str]
    if isinstance(cwe_field, list):
        candidates = [str(c) for c in cwe_field]
    else:
        candidates = [str(cwe_field)]

    for candidate in candidates:
        m = _CWE_RE.search(candidate)
        if m:
            return m.group(1)

    return ""


def _normalize_semgrep_trace(trace: dict | None, local_path: Path) -> list[dict] | None:
    """Convert Semgrep's ``extra.dataflow_trace`` to the common dataflow trace schema.

    Semgrep always produces a single path per finding; it is returned as a
    one-element list so the schema matches Veracode's multi-path format.

    Raw Semgrep ``dataflow_trace`` shape:

    .. code-block:: json

        {
          "taint_source": ["CliLoc", [{"path": "/abs/src/Foo.ts",
                                        "start": {"line": 5}}, "req.body"]],
          "intermediate_vars": [
            {"location": {"path": "…", "start": {"line": 8}},
             "content": "userId"}
          ],
          "taint_sink":   ["CliLoc", [{"path": "…", "start": {"line": 12}},
                                       "query(userId)"]]
        }

    Nodes come in two forms:

    - **Tagged tuple** ``["CliLoc", [loc_obj, content_str]]`` — used for
      ``taint_source`` and ``taint_sink``.
    - **Plain dict** ``{"location": loc_obj, "content": str}`` — used for
      ``intermediate_vars``.
    - ``["CliCall", [..., ["CliLoc", ...]]]`` — nested call; the inner
      ``CliLoc`` is extracted recursively.

    Field mapping:

    ===============================  =======================
    Raw key                          step field
    ===============================  =======================
    ``loc.path`` (made repo-relative) ``file``
    ``loc.start.line``               ``line``
    tag payload content str          ``snippet``
    ===============================  =======================

    Absolute paths are made repo-relative via
    ``Path.relative_to(local_path.resolve())``.
    """
    if not trace:
        return None

    def _extract_loc_content(node: dict | list) -> tuple[dict, str]:
        """Recursively unwrap semgrep's tagged-tuple or plain-dict node.

        Semgrep emits nodes in two forms:
        - Plain dict:   {"location": {...}, "content": "..."}  (intermediate_vars)
        - Tagged tuple: ["CliLoc",  [loc_obj, content_str]]
                        ["CliCall", [callee, steps, ["CliLoc", [...]]]]
        """
        if isinstance(node, dict):
            return node.get("location", {}), str(node.get("content", ""))
        if isinstance(node, list) and len(node) == 2:
            tag, payload = node[0], node[1]
            if tag == "CliLoc" and isinstance(payload, list) and len(payload) >= 2:
                loc = payload[0] if isinstance(payload[0], dict) else {}
                return loc, str(payload[1])
            if tag == "CliCall" and isinstance(payload, list):
                # Last element is the concrete sink/source CliLoc
                for item in reversed(payload):
                    if isinstance(item, list) and item and item[0] == "CliLoc":
                        return _extract_loc_content(item)
        return {}, ""

    def _node_step(node: dict | list) -> dict:
        loc, content = _extract_loc_content(node)
        file_str = str(loc.get("path", ""))
        _fp = Path(file_str)
        if _fp.is_absolute():
            try:
                file_str = _fp.relative_to(local_path.resolve()).as_posix()
            except ValueError:
                pass  # outside repo root — leave as-is
        file_str = file_str.replace("\\", "/")
        return {
            "file": file_str,
            "line": int(loc.get("start", {}).get("line", 0)),
            "snippet": content,
        }

    taint_source = trace.get("taint_source")
    taint_sink = trace.get("taint_sink")
    if not taint_source or not taint_sink:
        return None

    return [{
        "source": _node_step(taint_source),
        "steps": [_node_step(v) for v in (trace.get("intermediate_vars") or [])],
        "sink": _node_step(taint_sink),
    }]


def _parse_semgrep_result(
    result: dict[str, Any],
    local_path: Path,
) -> Finding:
    """Map one entry from Semgrep's ``--json`` output to a :class:`Finding`.

    Raw Semgrep result shape (one element of ``results[]"):

    .. code-block:: json

        {
          "check_id": "javascript.lang.security.audit.sqli.knex-sqli",
          "path": "/abs/path/src/db.ts",
          "start": {"line": 42, "col": 5},
          "extra": {
            "severity": "ERROR",
            "message": "Potential SQL injection …",
            "metadata": {
              "cwe": ["CWE-89: SQL Injection"]
            },
            "dataflow_trace": { ... }
          }
        }

    Field mapping:

    ============================  ================================
    Raw key                       Finding field
    ============================  ================================
    ``check_id``                  ``issue_type``
    ``check_id:path:line``        ``issue_id`` (synthetic key)
    ``path`` (repo-relative)      ``file``
    ``start.line``                ``line``
    ``extra.severity``            ``severity`` (mapped via
                                  :data:`_SEVERITY_MAP` to 0-5)
    ``extra.message``             ``display_text``
    ``extra.metadata.cwe[0]``     ``cwe_id`` (first CWE number
                                  extracted by :func:`_extract_cwe`)
    ``extra.dataflow_trace``      ``stack_dumps`` (normalised by
                                  :func:`_normalize_semgrep_trace`)
    ============================  ================================

    Absolute ``path`` values are made repo-relative via
    ``Path.relative_to(local_path.resolve())``.
    """
    check_id: str = str(result.get("check_id", ""))
    path: str = str(result.get("path", ""))
    start: dict[str, Any] = result.get("start", {})
    line: int = int(start.get("line", 0))

    _p = Path(path)
    if _p.is_absolute():
        try:
            path = _p.relative_to(local_path.resolve()).as_posix()
        except ValueError:
            pass  # outside repo root — leave as-is
    path = path.replace("\\", "/")

    extra: dict[str, Any] = result.get("extra", {})
    metadata: dict[str, Any] = extra.get("metadata", {})

    cwe_raw = metadata.get("cwe") or metadata.get("CWE")
    cwe_id = _extract_cwe(cwe_raw)

    severity_str: str = str(extra.get("severity", "")).upper()
    severity: int = _SEVERITY_MAP.get(severity_str, 2)

    issue_id = f"{check_id}:{path}:{line}"
    display_text: str = str(extra.get("message", ""))

    dataflow_trace: list[dict] | None = _normalize_semgrep_trace(extra.get("dataflow_trace"), local_path)

    return Finding(
        issue_id=issue_id,
        scan_file="semgrep",
        cwe_id=cwe_id,
        issue_type=check_id,
        severity=severity,
        file=path,
        line=line,
        scan_engine="semgrep",
        display_text=display_text,
        stack_dumps=dataflow_trace,
    )


def scan(local_path: Path, cfg: SemgrepConfig, sast_dir: Path | None = None) -> ScanResult:
    """Run semgrep against *local_path* and return a :class:`ScanResult`.

    Args:
        local_path: Absolute path to the source directory to scan.
        cfg: Semgrep-specific configuration.
        sast_dir: If provided, the raw semgrep JSON output is written to
            ``<sast_dir>/.semgrep/raw_semgrep_output.json`` before parsing.

    Returns:
        A :class:`ScanResult` containing all raw findings.

    Raises:
        RuntimeError: If semgrep exits with a non-zero code or its output
            cannot be parsed as JSON.
    """
    _SEMGREP = ["uv", "run", "semgrep"]

    if not _tool_available(["uv", "run", "semgrep", "show", "version"]):
        raise RuntimeError(
            "semgrep is not available.\n"
            "Install it with: uv sync --extra semgrep"
        )

    repo_name = local_path.name

    cmd = _SEMGREP + ["--config", cfg.config, "--json", "--dataflow-traces", "--quiet"]
    if cfg.pro:
        cmd.append("--pro")
    if sast_dir is not None:
        try:
            exclude_rel = sast_dir.resolve().relative_to(local_path.resolve())
            cmd.extend(["--exclude", str(exclude_rel)])
        except ValueError:
            pass  # sast_dir outside local_path — nothing to exclude
    cmd.append(str(local_path))

    print(f"\n[semgrep] Scanning {local_path} ...")
    print(f"  $ {' '.join(cmd)}")

    ok, stdout, stderr = capture_cmd(cmd, cwd=local_path)

    # Detect missing semgrep-core-proprietary binary and fall back to OSS mode.
    if cfg.pro and "semgrep-core-proprietary" in (stderr or ""):
        print(
            "\n[semgrep] WARNING: --pro requested but semgrep-core-proprietary is not "
            "installed.\n"
            "  Run `semgrep install-semgrep-pro` to enable Pro Engine.\n"
            "  Falling back to OSS semgrep for this scan.\n"
        )
        cmd = [c for c in cmd if c != "--pro"]
        ok, stdout, stderr = capture_cmd(cmd, cwd=local_path)

    if sast_dir is not None and stdout.strip():
        semgrep_dir = sast_dir / ".semgrep"
        semgrep_dir.mkdir(parents=True, exist_ok=True)
        raw_out = semgrep_dir / "raw_semgrep_output.json"
        raw_out.write_text(stdout, encoding="utf-8")
        print(f"[semgrep] Raw output saved to {raw_out}")

    if stderr:
        # semgrep writes progress / warning information to stderr; log it at
        # DEBUG level so it doesn't pollute the console output by default.
        for line in stderr.splitlines():
            logger.debug("[semgrep stderr] %s", line)

    if not ok and not stdout.strip():
        raise RuntimeError(
            f"semgrep exited with an error and produced no output.\n"
            f"stderr: {stderr[:500] if stderr else '(empty)'}"
        )

    try:
        data: dict[str, Any] = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"semgrep output is not valid JSON: {exc}\n"
            f"stdout (first 500 chars): {stdout[:500]}"
        ) from exc

    raw_results: list[dict[str, Any]] = data.get("results", [])
    findings = [_parse_semgrep_result(r, local_path) for r in raw_results]

    # Semgrep may return exit code 1 when findings are present (not an error).
    # Log any reported errors from the JSON payload but don't abort.
    errors: list[Any] = data.get("errors", [])
    if errors:
        logger.warning("[semgrep] %d error(s) reported in JSON output", len(errors))
        for err in errors[:5]:
            logger.warning("  %s", err)

    print(f"[semgrep] {len(findings)} raw finding(s)")

    return ScanResult(
        repo_name=repo_name,
        repo_path=local_path,
        scan_engine="semgrep",
        findings=findings,
        total_raw=len(findings),
    )
