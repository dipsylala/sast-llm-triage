# CLAUDE.md — Developer Guide for sast-llm-triage

Operational context for Claude Code (and similar AI coding assistants).

---

## Project Summary

`sast-llm-triage` is a CLI tool that runs a SAST scan on a single Git
repository and produces a structured `triage_findings.json` ready for
LLM-assisted exploitability triage. Optionally, `--llm-overlay` invokes
LiteLLM directly to produce a `triage_report.json` without manual IDE steps.

Full design specification: [SPEC.md](SPEC.md)

---

## Setup

```bash
# Create venv and install in editable mode (core deps only)
uv sync

# With optional extras
uv sync --extra semgrep          # adds semgrep
uv sync --extra llm-overlay      # adds litellm
```

Requires Python ≥ 3.11.  
Virtual env lives at `.venv/`.  
On Windows: `.\.venv\Scripts\python.exe` / `.\.venv\Scripts\activate`.

---

## Running the Tool

```bash
# Via uv (recommended)
uv run sast-llm-triage --repo <url-or-local-path> --scanner veracode|semgrep|snyk

# Via python module (useful during dev)
.\.venv\Scripts\python.exe -m triage --repo <url-or-local-path> --scanner veracode

# Skip clone+scan, re-use existing triage_findings.json
uv run sast-llm-triage --repo output\<repo-name> --scanner <any> --skip-scan

# Headless triage (requires litellm extra + API key)
OPENAI_API_KEY=sk-... uv run sast-llm-triage \
  --repo https://github.com/org/repo --scanner snyk --llm-overlay
```

### All CLI flags

| Flag | Default | Notes |
| --- | --- | --- |
| `--repo` | required | URL or local path (relative paths resolved from cwd) |
| `--scanner` | required | `veracode`, `semgrep`, or `snyk` |
| `--output-dir` | `./output` | Root directory for all outputs |
| `--config` | `config/config.yaml` | YAML config file |
| `--qualifying-cwes` | from config | Comma-separated CWE numbers, overrides config |
| `--llm-overlay` | off | Run LiteLLM triage after scan |
| `--skip-scan` | off | Skip clone+scan; read existing `triage_findings.json` |
| `--log` | off | Write LLM chat transcripts to `llm_chat.jsonl` (with `--llm-overlay`) |
| `--verbose` | off | Debug logging |

---

## Output Layout

```text
output/
  <repo-name>/
    <repo-name>/         ← cloned source (or symlink for local paths)
    .sast-results/
      triage_findings.json   ← qualifying findings (filtered, sorted)
      raw_findings.json      ← all findings before CWE filter
      triage_report.json     ← LLM verdicts (--llm-overlay only)
      .veracode/             ← Veracode packages + raw JSON
      .snyk/                 ← raw Snyk SARIF output
```

---

## Running Tests

```bash
uv run pytest                  # all tests
uv run pytest tests/test_normalizer.py   # single file
uv run pytest -k "snyk"        # by keyword
```

Tests live in `tests/`. Factories in `tests/factories.py`.  
No network calls in unit tests — scanners are mocked.

---

## Configuration

`config/config.yaml` controls:

- `qualifying_cwes` — list of CWE IDs to keep after scanning (currently 40 entries)
- `context_lines` — source lines of context per finding (default: 25)
- `llm_overlay.model` — LiteLLM model string (e.g. `openai/gpt-4o`, `anthropic/claude-opus-4-5`, `ollama/llama3`)
- `llm_overlay.max_turns` — max tool-call turns per finding (default: 10)

---

## Project Structure

```text
src/triage/
  __main__.py          ← CLI entry point, orchestrates all stages
  config.py            ← loads config.yaml, resolves paths
  models/
    finding.py         ← Finding dataclass
    scan_result.py     ← ScanResult dataclass
  scanners/
    base.py            ← BaseScanner ABC
    veracode.py        ← VeracodeScanner
    semgrep.py         ← SemgrepScanner
    snyk.py            ← SnykScanner
  stages/
    repo_cloner.py     ← clone URL or validate local path
    result_enricher.py ← attach source_excerpt to each finding
    normalizer.py      ← filter by CWE, sort, write JSON
    llm_overlay.py     ← optional LiteLLM triage loop

agents/
  scan-repo.md         ← IDE agent prompt: manual multi-finding triage
  triage-finding.md    ← system prompt for per-finding LLM worker

config/
  config.yaml          ← qualifying CWEs, context lines, LLM model

output/                ← gitignored scan outputs
```

---

## Key Conventions

- **No inline `print()` in stages** — use `logging`. CLI prints go through `__main__.py`.
- **Scanners raise `RuntimeError`** on fatal errors; the CLI catches and exits with code 1.
- **Path traversal guard** in `result_enricher.py` and `llm_overlay.py` — always validate that resolved paths stay within `repo_root` before reading.
- **`source_excerpt` is the source of truth** for the LLM overlay — the no-tools fallback uses it directly; don't re-read the file.
- **`--skip-scan` sets `total_raw = None`** — `_print_triage_instructions` handles this and prints `"N qualifying"` instead of `"N qualifying / M total"`.
- **Relative `--repo` paths** are resolved via `Path(repo).resolve()` in `repo_cloner.py` — they work fine when cwd is the project root.

---

## External Tool Requirements

| Scanner | Requirement |
| --- | --- |
| Veracode | `veracode` CLI in PATH; `~/.veracode/credentials` file (API ID + key) |
| Semgrep | `uv sync --extra semgrep`; optional `SEMGREP_APP_TOKEN` for Pro Engine |
| Snyk | `snyk` CLI in PATH; run `snyk auth` once |

Veracode Pipeline Scan uploads packages to the Veracode cloud API.  
Snyk Code uploads source to the Snyk cloud API.  
Semgrep runs entirely locally (pulls rule definitions from the Semgrep registry).
