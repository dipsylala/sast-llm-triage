"""Snyk Code scanner — runs ``snyk code test --json`` locally.

Snyk Code analyses source files on the local machine.  The source tree is
sent to Snyk's cloud analysis service and findings are returned as a SARIF
2.1.0 document.

Prerequisites
-------------
1. Install the Snyk CLI (see https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli).
2. Authenticate once with ``snyk auth``.

The scan command used is::

    snyk code test --json <local_path>

Exit codes
----------
Snyk exits with 0 (no findings), 1 (findings present), or ≥2 (error).
Exit code 1 is therefore *not* treated as a hard failure.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path
from typing import Any

from triage.config import SnykConfig
from triage.models import Finding, ScanResult

from .base import capture_cmd

logger = logging.getLogger(__name__)

# SARIF level → Veracode 0-5 scale
_SEVERITY_MAP: dict[str, int] = {
    "error": 5,
    "warning": 3,
    "note": 1,
    "none": 1,
}

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)



def _extract_cwe(cwe_list: Any) -> str:
    """Return the first CWE number found in a Snyk rule's ``cwe`` property.

    The field is typically a list of strings such as ``["CWE-89"]`` but may
    also be a bare string or absent.
    """
    if not cwe_list:
        return ""
    candidates: list[str]
    if isinstance(cwe_list, list):
        candidates = [str(c) for c in cwe_list]
    else:
        candidates = [str(cwe_list)]
    for candidate in candidates:
        m = _CWE_RE.search(candidate)
        if m:
            return m.group(1)
    return ""


def _normalize_snyk_flow(code_flows: list[dict] | None) -> list[dict] | None:
    """Convert Snyk's SARIF ``codeFlows`` to the common dataflow trace schema.

    Snyk emits one ``codeFlow`` per finding, containing a single ``threadFlow``
    whose ``locations`` list represents the full taint path in source-to-sink
    order (index 0 = source, last index = sink).

    Snyk does NOT include a ``message.text`` field on individual trace locations
    in practice — ``snippet`` will always be an empty string.  The file/line
    values are reliable and are the primary useful content.

    All intermediate steps are included.
    """
    if not code_flows:
        return None

    def _loc_step(loc: dict) -> dict:
        phys = loc.get("location", {}).get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "")
        region = phys.get("region", {})
        line = int(region.get("startLine", 0))
        # message.text is absent in real Snyk output; default to empty string.
        snippet = loc.get("location", {}).get("message", {}).get("text", "")
        return {"file": uri, "line": line, "snippet": snippet}

    paths: list[dict] = []
    for flow in code_flows:
        for thread_flow in flow.get("threadFlows", []):
            locations = thread_flow.get("locations", [])
            if len(locations) < 2:
                continue
            middle = locations[1:-1]
            paths.append({
                "source": _loc_step(locations[0]),
                "steps": [_loc_step(loc) for loc in middle],
                "sink": _loc_step(locations[-1]),
            })

    return paths if paths else None


def _build_rule_index(rules: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return a mapping of rule ID → rule dict for fast lookup."""
    return {str(r.get("id", "")): r for r in rules}


def _parse_snyk_result(
    result: dict[str, Any],
    rule_index: dict[str, dict[str, Any]],
) -> Finding:
    """Map one SARIF result dict to a :class:`Finding`."""
    rule_id: str = str(result.get("ruleId", ""))
    level: str = str(result.get("level", "warning")).lower()
    severity: int = _SEVERITY_MAP.get(level, 2)

    # Location
    locations = result.get("locations", [])
    phys = locations[0].get("physicalLocation", {}) if locations else {}
    uri: str = phys.get("artifactLocation", {}).get("uri", "")
    # Strip the %SRCROOT%/ prefix that Snyk sometimes prepends
    if uri.startswith("%SRCROOT%/"):
        uri = uri[len("%SRCROOT%/"):]
    region = phys.get("region", {})
    line: int = int(region.get("startLine", 0))

    # Rule metadata
    rule = rule_index.get(rule_id, {})
    rule_props: dict[str, Any] = rule.get("properties", {})
    cwe_id = _extract_cwe(rule_props.get("cwe"))
    issue_type: str = rule.get("shortDescription", {}).get("text", rule_id)
    display_text: str = result.get("message", {}).get("text", "")

    issue_id = f"{rule_id}:{uri}:{line}"

    dataflow: list[dict] | None = _normalize_snyk_flow(result.get("codeFlows"))

    return Finding(
        issue_id=issue_id,
        scan_file="snyk",
        cwe_id=cwe_id,
        issue_type=issue_type,
        severity=severity,
        file=uri,
        line=line,
        scan_engine="snyk",
        display_text=display_text,
        stack_dumps=dataflow,
    )


def scan(local_path: Path, cfg: SnykConfig, sast_dir: Path | None = None) -> ScanResult:
    """Run ``snyk code test`` against *local_path* and return a :class:`ScanResult`.

    Args:
        local_path: Absolute path to the source directory to scan.
        cfg: Snyk-specific configuration.
        sast_dir: If provided, the raw Snyk SARIF JSON is written to
            ``<sast_dir>/.snyk/raw_snyk_output.json`` before parsing.

    Returns:
        A :class:`ScanResult` containing all raw findings.

    Raises:
        RuntimeError: If Snyk exits with an error code ≥ 2, produces no output,
            or the output cannot be parsed as valid JSON.
    """
    if not shutil.which("snyk"):
        raise RuntimeError(
            "snyk is not installed or not on PATH.\n"
            "Install it from https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli\n"
            "then run: snyk auth"
        )

    repo_name = local_path.name

    cmd = ["snyk", "code", "test", "--json"]
    if cfg.severity_threshold:
        cmd += ["--severity-threshold", cfg.severity_threshold]
    cmd.append(str(local_path))

    print(f"\n[snyk] Scanning {local_path} ...")
    print(f"  $ {' '.join(cmd)}")

    ok, stdout, stderr = capture_cmd(cmd, cwd=local_path)

    # Snyk exits with 1 when findings are present — not an error.
    # Exit codes ≥ 2 indicate a genuine failure (e.g. auth error, bad path).
    # capture_cmd reports ok=False for any non-zero exit; we accept exit code 1
    # when there is valid JSON output and no auth-error keywords.
    has_valid_findings_output = bool(stdout.strip()) and not (
        "authentication" in (stdout + stderr).lower()
        or "not authenticated" in (stdout + stderr).lower()
    )

    if not ok and not has_valid_findings_output:
        hint = (
            "\n  Hint: run `snyk auth` to authenticate with Snyk before scanning."
            if "auth" in (stdout + stderr).lower()
            else ""
        )
        raise RuntimeError(
            f"snyk code test failed and produced no usable output.{hint}\n"
            f"stderr: {stderr[:500] if stderr else '(empty)'}\n"
            f"stdout: {stdout[:200] if stdout else '(empty)'}"
        )

    if sast_dir is not None and stdout.strip():
        snyk_dir = sast_dir / ".snyk"
        snyk_dir.mkdir(parents=True, exist_ok=True)
        raw_out = snyk_dir / "raw_snyk_output.json"
        raw_out.write_text(stdout, encoding="utf-8")
        print(f"[snyk] Raw output saved to {raw_out}")

    if stderr:
        for line in stderr.splitlines():
            logger.debug("[snyk stderr] %s", line)

    if not stdout.strip():
        # No output at all and exit was 0 → no findings.
        return ScanResult(
            repo_name=repo_name,
            repo_path=local_path,
            scan_engine="snyk",
            findings=[],
            total_raw=0,
        )

    try:
        data: dict[str, Any] = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"snyk output is not valid JSON: {exc}\n"
            f"stdout (first 500 chars): {stdout[:500]}"
        ) from exc

    # Snyk outputs SARIF 2.1.0; findings live under runs[0].
    runs: list[dict[str, Any]] = data.get("runs", [])
    if not runs:
        logger.debug("[snyk] No runs in SARIF output — zero findings.")
        return ScanResult(
            repo_name=repo_name,
            repo_path=local_path,
            scan_engine="snyk",
            findings=[],
            total_raw=0,
        )

    run = runs[0]
    rules: list[dict[str, Any]] = (
        run.get("tool", {}).get("driver", {}).get("rules", [])
    )
    rule_index = _build_rule_index(rules)

    raw_results: list[dict[str, Any]] = run.get("results", [])
    findings = [_parse_snyk_result(r, rule_index) for r in raw_results]

    logger.info("[snyk] %d findings parsed from %d SARIF results.", len(findings), len(raw_results))

    return ScanResult(
        repo_name=repo_name,
        repo_path=local_path,
        scan_engine="snyk",
        findings=findings,
        total_raw=len(findings),
    )
