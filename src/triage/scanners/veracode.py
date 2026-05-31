"""Veracode scanner — packages a repository and runs Veracode Pipeline Scan.

Requires:
- ``veracode`` CLI in PATH.
- ``VERACODE_API_ID`` and ``VERACODE_API_KEY`` environment variables set.

The Veracode Pipeline Scan sends the compiled package to Veracode's cloud API
for analysis.  Source code is packaged locally; only the package is uploaded.
"""

from __future__ import annotations

import json
import logging
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from triage.config import VeracodeConfig
from triage.models import Finding, ScanResult

from .base import run_cmd

logger = logging.getLogger(__name__)


def _normalize_veracode_trace(raw_stack_dumps: dict | None) -> list[dict] | None:
    """Convert Veracode's raw stack_dumps to the common dataflow trace schema.

    Veracode stores frames in call-stack order (sink at index 0, source last)
    and may provide multiple independent paths per finding (one per
    ``stack_dump`` entry).  This function reverses each frame list so every
    path is returned in source → sink order.
    """
    if not raw_stack_dumps:
        return None
    try:
        dump_list: list[dict] = raw_stack_dumps["stack_dump"]
    except (KeyError, TypeError):
        return None

    def _frame_step(f: dict) -> dict:
        return {
            "file": str(f.get("SourceFile", "")),
            "line": int(f.get("SourceLine", 0)),
            "snippet": "",  # left empty; result_enricher fills from source
        }

    paths: list[dict] = []
    for dump in dump_list:
        frames = dump.get("Frame") or []
        if not frames:
            continue
        ordered = list(reversed(frames))  # now [source, ..., sink]
        paths.append({
            "source": _frame_step(ordered[0]),
            "steps": [_frame_step(f) for f in ordered[1:-1]] if len(ordered) > 2 else [],
            "sink": _frame_step(ordered[-1]),
        })

    return paths if paths else None


def _parse_veracode_finding(raw: dict[str, Any], scan_file: str) -> Finding:
    """Map one Veracode finding dict to a :class:`Finding`."""
    src = raw.get("files", {}).get("source_file", {})
    return Finding(
        issue_id=str(raw.get("issue_id", "")),
        scan_file=scan_file,
        cwe_id=str(raw.get("cwe_id", "")),
        issue_type=str(raw.get("issue_type", "")),
        severity=int(raw.get("severity", 0)),
        file=str(src.get("file", "")),
        line=int(src.get("line", 0)),
        scan_engine="veracode",
        display_text=str(raw.get("display_text", "")),
        stack_dumps=_normalize_veracode_trace(raw.get("stack_dumps")),
    )


def _package(local_path: Path, pkg_dir: Path) -> list[Path]:
    """Run ``veracode package`` and return the produced package files."""
    pkg_dir.mkdir(parents=True, exist_ok=True)
    log_file = pkg_dir / "package.log"
    ok, _ = run_cmd(
        ["veracode", "package", "-v", "-s", str(local_path), "-a", "-o", str(pkg_dir)],
        cwd=pkg_dir,  # run from pkg_dir so any relative path resolution stays local
        log_file=log_file,
    )
    if not ok or not pkg_dir.is_dir():
        return []
    return [
        f for f in pkg_dir.iterdir()
        if f.is_file() and f.suffix not in (".json", ".log")
    ]


def _scan_package(package_file: Path, pkg_dir: Path) -> bool:
    """Run ``veracode static scan`` for one package file."""
    results_file = pkg_dir / f"{package_file.stem}.json"
    filtered_file = pkg_dir / f"filtered_{package_file.stem}.json"
    log_file = pkg_dir / f"{package_file.stem}.log"
    ok, _ = run_cmd(
        [
            "veracode", "static", "scan",
            str(package_file),
            "--results-file", str(results_file),
            "--filtered-json-output-file", str(filtered_file),
        ],
        cwd=pkg_dir,
        log_file=log_file,
    )
    return ok


def scan(
    local_path: Path,
    sast_dir: Path,
    cfg: VeracodeConfig,
) -> ScanResult:
    """Package and scan *local_path* with Veracode Pipeline Scan.

    Args:
        local_path: Absolute path to the source directory to scan.
        sast_dir: Directory where SAST outputs are written
            (``<output_dir>/<repo_name>/.sast-results``).
        cfg: Veracode-specific configuration.

    Returns:
        A :class:`ScanResult` containing all raw findings.

    Raises:
        RuntimeError: If packaging produces no packages, or if every scan
            invocation fails.
    """
    if not shutil.which("veracode"):
        raise RuntimeError(
            "veracode is not installed or not on PATH.\n"
            "Install the Veracode CLI from https://docs.veracode.com/r/c_about_veracode_cli\n"
            "and set VERACODE_API_ID and VERACODE_API_KEY environment variables."
        )

    repo_name = local_path.name
    pkg_dir = sast_dir / cfg.package_dir_name
    pkg_dir.mkdir(parents=True, exist_ok=True)

    # --- 1. Package ---
    print(f"\n[veracode] Packaging {local_path} ...")
    packages = _package(local_path, pkg_dir)
    if not packages:
        raise RuntimeError(
            f"veracode package produced no output in {pkg_dir}. "
            "Check that the Veracode CLI is installed and the repo is a "
            "supported language."
        )
    print(f"[veracode] Produced {len(packages)} package(s)")

    # --- 2. Scan each package ---
    print(f"[veracode] Scanning {len(packages)} package(s) ...")
    errors = 0
    with ThreadPoolExecutor(max_workers=max(1, cfg.scan_workers)) as pool:
        futures = {
            pool.submit(_scan_package, pkg, pkg_dir): pkg
            for pkg in sorted(packages)
        }
        for future in as_completed(futures):
            pkg = futures[future]
            ok = future.result()
            if not ok:
                logger.warning("scan failed for package %s", pkg.name)
                errors += 1

    if errors == len(packages):
        raise RuntimeError(
            f"All {len(packages)} Veracode scan(s) failed. "
            "Check credentials (VERACODE_API_ID, VERACODE_API_KEY) and network."
        )

    # --- 3. Parse filtered result JSON files ---
    findings: list[Finding] = []
    for filtered_file in sorted(pkg_dir.glob("filtered_*.json")):
        try:
            data: dict[str, Any] = json.loads(
                filtered_file.read_text(encoding="utf-8", errors="replace")
            )
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("could not read %s: %s", filtered_file, exc)
            continue

        for raw in data.get("findings", []):
            findings.append(_parse_veracode_finding(raw, filtered_file.name))

    print(f"[veracode] {len(findings)} raw finding(s) parsed")

    result = ScanResult(
        repo_name=repo_name,
        repo_path=local_path,
        scan_engine="veracode",
        findings=findings,
        total_raw=len(findings),
    )
    return result
