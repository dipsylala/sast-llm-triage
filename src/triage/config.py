"""Configuration loading for sast-llm-triage.

Loads ``config.yaml`` (bundled default or user-supplied path) and applies any
CLI overrides.  Environment variables for credentials are never read here —
they are consumed directly by the Veracode / Semgrep CLIs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Default qualifying CWE set — mirrors the set used by the reference pipeline
# and the scan-repo.md agent prompt.
# ---------------------------------------------------------------------------
_DEFAULT_QUALIFYING_CWES: frozenset[str] = frozenset({
    "22", "73", "77", "78", "79", "80", "88", "89", "94", "95", "98",
    "118", "120", "121", "125", "129", "134", "135", "170", "190", "191",
    "192", "193", "195", "196", "197", "209", "242", "295", "319", "327",
    "367", "415", "416", "502", "601", "611", "676", "787", "823", "824",
    "918",
})

# Path to the bundled default config shipped with the package.
_BUNDLED_CONFIG = Path(__file__).parent.parent.parent / "config" / "config.yaml"


# ---------------------------------------------------------------------------
# Sub-config dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SemgrepConfig:
    config: str = "auto"
    pro: bool = False


@dataclass
class VeracodeConfig:
    package_dir_name: str = ".veracode"
    scan_workers: int = 1


@dataclass
class SnykConfig:
    severity_threshold: str = "low"  # low | medium | high | critical


@dataclass
class TriageConfig:
    output_dir: Path
    context_lines: int
    max_findings: int
    qualifying_cwes: frozenset[str]
    semgrep: SemgrepConfig
    veracode: VeracodeConfig
    snyk: SnykConfig


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(
    config_path: str | None = None,
    *,
    output_dir_override: str | None = None,
    qualifying_cwes_override: str | None = None,
) -> TriageConfig:
    """Load configuration from YAML and apply optional CLI overrides.

    Args:
        config_path: Path to a YAML config file.  Defaults to the bundled
            ``config/config.yaml`` when ``None``.
        output_dir_override: ``--output-dir`` CLI value; overrides the YAML
            ``output.dir`` key when provided.
        qualifying_cwes_override: ``--qualifying-cwes`` CLI value (comma-
            separated CWE numbers); overrides the YAML list when provided.

    Returns:
        A populated :class:`TriageConfig` instance.

    Raises:
        FileNotFoundError: If the specified config file does not exist.
        ValueError: If the config file is invalid YAML or missing required keys.
    """
    path = Path(config_path) if config_path else _BUNDLED_CONFIG
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")

    try:
        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in config file {path}: {exc}") from exc

    # --- output dir ---
    if output_dir_override:
        output_dir = Path(output_dir_override)
    else:
        output_dir = Path(raw.get("output", {}).get("dir", "./output"))

    # Expand ~ and env vars, then resolve to absolute path so downstream
    # tools (e.g. veracode package -o) never receive a relative path.
    output_dir = Path(os.path.expandvars(os.path.expanduser(str(output_dir)))).resolve()

    # --- scan settings ---
    scan_cfg: dict[str, Any] = raw.get("scan", {})
    context_lines: int = int(scan_cfg.get("context_lines", 8))
    max_findings: int = int(scan_cfg.get("max_findings", 0))  # 0 = no cap

    if qualifying_cwes_override:
        qualifying_cwes = frozenset(
            c.strip() for c in qualifying_cwes_override.split(",") if c.strip()
        )
    else:
        raw_cwes = scan_cfg.get("qualifying_cwes")
        if raw_cwes:
            qualifying_cwes = frozenset(str(c) for c in raw_cwes)
        else:
            qualifying_cwes = _DEFAULT_QUALIFYING_CWES

    # --- semgrep ---
    sg_raw: dict[str, Any] = raw.get("semgrep", {})
    semgrep = SemgrepConfig(
        config=str(sg_raw.get("config", "auto")),
        pro=bool(sg_raw.get("pro", False)),
    )

    # --- veracode ---
    vc_raw: dict[str, Any] = raw.get("veracode", {})
    veracode = VeracodeConfig(
        package_dir_name=str(vc_raw.get("package_dir_name", ".veracode")),
        scan_workers=int(vc_raw.get("scan_workers", 1)),
    )

    # --- snyk ---
    sn_raw: dict[str, Any] = raw.get("snyk", {})
    snyk = SnykConfig(
        severity_threshold=str(sn_raw.get("severity_threshold", "low")),
    )

    return TriageConfig(
        output_dir=output_dir,
        context_lines=context_lines,
        max_findings=max_findings,
        qualifying_cwes=qualifying_cwes,
        semgrep=semgrep,
        veracode=veracode,
        snyk=snyk,
    )
