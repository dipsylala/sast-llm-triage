"""sast-llm-triage — single-repo SAST scan + LLM triage preparation tool."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

from triage.config import load_config
from triage.scanners import semgrep as semgrep_scanner
from triage.scanners import snyk as snyk_scanner
from triage.scanners import veracode as veracode_scanner
from triage.stages.normalizer import normalize
from triage.stages.repo_cloner import _is_url, clone
from triage.stages.result_enricher import enrich

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sast-llm-triage",
        description=(
            "Scan a Git repository with Veracode, Semgrep, or Snyk, enrich the "
            "findings, and write triage_findings.json for LLM triage."
        ),
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Git URL or local path to the repository to scan.",
    )
    parser.add_argument(
        "--scanner",
        required=True,
        choices=["veracode", "semgrep", "snyk"],
        help="SAST engine to use.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory where output files are written (default: ./output).",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to config.yaml (default: bundled config/config.yaml).",
    )
    parser.add_argument(
        "--qualifying-cwes",
        default=None,
        help=(
            "Comma-separated CWE IDs to include in triage_findings.json "
            "(overrides config file value)."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    parser.add_argument(
        "--llm-overlay",
        action="store_true",
        help=(
            "After scanning, triage each qualifying finding via LiteLLM and write "
            "triage_report.json.  Requires litellm (pip install litellm) and the "
            "appropriate API key env var (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)."
        ),
    )
    return parser


def _print_triage_instructions(
    repo_name: str,
    output_dir: Path,
    combined_path: Path,
    qualifying_count: int,
    total_raw: int,
) -> None:
    line = "-" * 60
    print(f"\n{line}")
    print("LLM triage ready.\n")
    print(f"  repo_name   : {repo_name}")
    print(f"  output_dir  : {output_dir.resolve()}")
    print(f"  findings    : {qualifying_count} qualifying / {total_raw} total")
    print(f"  input file  : {combined_path}")
    print()
    print(
        "Open agents/scan-repo.md in your IDE agent (Copilot, Claude Code, etc.)\n"
        "and provide the following task context:\n"
    )
    print(f"  repo_name  = {repo_name}")
    print(f"  output_dir = {output_dir.resolve()}")
    print(line)


def main() -> None:
    load_dotenv()  # load .env if present (does not override real env vars)

    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # --- Load config ---
    try:
        cfg = load_config(
            args.config,
            output_dir_override=args.output_dir,
            qualifying_cwes_override=args.qualifying_cwes,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    # --- Step 1: Clone or validate repo ---
    try:
        local_path, repo_name = clone(args.repo, cfg.output_dir)
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    # URL is available when the input looked like a remote URL; otherwise None.
    repo_url: str | None = args.repo if _is_url(args.repo) else None

    sast_dir = cfg.output_dir / repo_name / ".sast-results"
    sast_dir.mkdir(parents=True, exist_ok=True)

    # --- Step 2: Run SAST scanner ---
    try:
        if args.scanner == "veracode":
            result = veracode_scanner.scan(local_path, sast_dir, cfg.veracode)
        elif args.scanner == "semgrep":
            result = semgrep_scanner.scan(local_path, cfg.semgrep, sast_dir)
        else:
            result = snyk_scanner.scan(local_path, cfg.snyk, sast_dir)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    result.repo_url = repo_url

    # --- Step 3: Enrich findings with source context ---
    print(f"\n[enrich] Reading source context (±{cfg.context_lines} lines) ...")
    enrich(result.findings, local_path, cfg.context_lines)

    # --- Step 4: Normalise and write output files ---
    print("[normalise] Writing output files ...")
    combined_path = normalize(
        result,
        cfg.qualifying_cwes,
        sast_dir,
        repo_url=repo_url,
    )

    qualifying_count = sum(
        1 for f in result.findings if f.cwe_id in cfg.qualifying_cwes
    )

    if args.llm_overlay:
        # --- Step 5: LiteLLM triage overlay ---
        from triage.stages.llm_overlay import run_llm_overlay

        try:
            run_llm_overlay(
                sast_dir=sast_dir,
                repo_root=local_path,
                repo_name=repo_name,
                overlay_cfg=cfg.llm_overlay,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        _print_triage_instructions(
            repo_name=repo_name,
            output_dir=cfg.output_dir / repo_name,
            combined_path=combined_path,
            qualifying_count=qualifying_count,
            total_raw=result.total_raw,
        )


if __name__ == "__main__":
    main()
