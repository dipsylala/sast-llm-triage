# SPEC.md — Single-Repo SAST + LLM Triage Tool

## 1. Overview

This document specifies a command-line tool (`sast-llm-triage`) that takes a single
Git repository, runs a static analysis scan against it, enriches and scores the
findings, and writes a structured `combined_results.json` file ready for
LLM-assisted exploitability triage.

The tool is designed to support security researchers and developers who want a
quick, local, single-repo triage workflow without the overhead of the bulk
discovery pipeline.

---

## 2. Goals

1. Accept a single repository (URL or local path) as input.
2. Run a SAST scan using either **Veracode Pipeline Scan** or **Semgrep**.
3. Enrich each finding with surrounding source-code context.
4. Score findings by vulnerability type and file location.
5. Produce a normalised `combined_results.json` capped at 60 findings, ready
   for the LLM triage agent (`agents/scan-repo.md`).
6. Print clear post-run instructions so the user can invoke the triage agent in
   their IDE.

---

## 3. Non-Goals

- No bulk repository discovery or multi-repo orchestration.
- No automated LLM API calls. Triage is always performed manually by the user
  running the `agents/scan-repo.md` agent prompt in their IDE.
- No results forwarded to third-party services beyond what the scan tools
  themselves require (see §6 for tool data-handling notes).
- No taint tracking, data-flow analysis, or exploit generation.

---

## 4. System Architecture

```
CLI input (--repo URL | local-path, --scanner veracode|semgrep)
           ↓
     repo_cloner        →  local_path (cloned or validated)
           ↓
     scanner            →  ScanResult (raw Finding objects)
       veracode.py          veracode package + veracode static scan
       semgrep.py           semgrep --config auto [--pro]
           ↓
     result_enricher    →  Finding.source_excerpt populated (±8 lines)
           ↓
     result_scorer      →  Finding.score populated (CWE base + path boost)
           ↓
     normalizer         →  combined_results.json written to disk
           ↓
   [Manual step]
     LLM agent (agents/scan-repo.md)
       reads   <output_dir>/<repo_name>/.sast-results/combined_results.json
       writes  <output_dir>/<repo_name>/triage_report.json
```

---

## 5. CLI Interface

```
sast-llm-triage --repo <url-or-local-path> \
            --scanner veracode|semgrep \
            [--output-dir <dir>]         # default: ./output
            [--config <config.yaml>]     # default: bundled config/config.yaml
            [--qualifying-cwes 22,78,89] # overrides config default
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Success — `combined_results.json` written |
| 1    | Scan tool error (non-zero exit from veracode / semgrep) |
| 2    | Configuration or argument error |

---

## 6. Scan Engines

### 6.1 Veracode

- Requires the **Veracode CLI** (`veracode`) in PATH.
- Requires `VERACODE_API_ID` and `VERACODE_API_KEY` environment variables.
- `veracode package` runs locally and produces scan packages.
- `veracode static scan` sends packages to the **Veracode Pipeline Scan cloud
  API** for analysis. This is the expected behaviour for licensed users.
- Packages and raw result JSON land in
  `<output_dir>/<repo_name>/.sast-results/.veracode/`.

### 6.2 Semgrep

- Installed as a Python project dependency via `uv sync` (PyPI: `semgrep`).
- Engine runs **entirely locally** — source code is never uploaded.
- Always uses `--config auto` (pulls latest rules from Semgrep registry;
  semgrep's own cache handles repeated runs).
- Set `semgrep.pro: true` in `config.yaml` and export `SEMGREP_APP_TOKEN` to
  enable the Semgrep Pro Engine (interfile analysis). Free tier works without
  any token.

---

## 7. Data Models

### 7.1 Finding

| Field | Type | Description |
|-------|------|-------------|
| `issue_id` | `str` | Unique ID within this scan |
| `scan_file` | `str` | Source filename (Veracode: filtered JSON name; Semgrep: `"semgrep"`) |
| `cwe_id` | `str` | CWE number as string, e.g. `"89"` |
| `issue_type` | `str` | Human-readable flaw category |
| `severity` | `int` | 0–5 (Veracode scale: 4=High, 5=Very High) |
| `file` | `str` | Repo-relative source file path |
| `line` | `int` | Line number of the sink |
| `scan_engine` | `str` | `"veracode"` or `"semgrep"` |
| `display_text` | `str` | Tool description of the flaw class |
| `source_excerpt` | `str` | Sink line marked `>>>` plus ±8 context lines (set by enricher) |
| `score` | `int` | Priority score (set by scorer) |
| `stack_dumps` | `dict \| None` | Veracode data-flow trace (when present) |

### 7.2 ScanResult

| Field | Type | Description |
|-------|------|-------------|
| `repo_name` | `str` | Repository name (derived from URL or path) |
| `repo_path` | `Path` | Absolute path to the cloned/provided source |
| `scan_engine` | `str` | `"veracode"` or `"semgrep"` |
| `findings` | `list[Finding]` | All raw findings from the scan |
| `total_raw` | `int` | Count of raw findings before any filtering |

---

## 8. Stage Specifications

### 8.1 repo_cloner

Accepts a `--repo` value that is either:

- A **Git URL** (starts with `https://`, `git://`, `git@`, or ends with `.git`):
  clones with `git clone --depth 1 <url> <output_dir>/<repo_name>/`.
  `repo_name` is the last path segment of the URL with `.git` stripped.
- A **local path**: validated to be an existing directory; used as-is.
  `repo_name` is `Path(repo).name`.

Returns the absolute `local_path` and `repo_name`.

### 8.2 scanner

**VeracodeScanner.scan(local_path, sast_dir)**

1. Creates `sast_dir/.veracode/`.
2. Runs `veracode package -v -s <local_path> -a -o <pkg_dir>`.
3. For each produced package: runs `veracode static scan <pkg> --results-file
   <pkg_dir>/<stem>.json --filtered-json-output-file
   <pkg_dir>/filtered_<stem>.json`.
4. Parses every `filtered_*.json` in `pkg_dir` and maps findings to `Finding`
   objects.

**SemgrepScanner.scan(local_path)**

1. Runs `semgrep --config auto [--pro] --json <local_path>` and captures stdout.
2. Parses the JSON output (`results[]` array).
3. Maps each result to a `Finding`:
   - `issue_id` = `f"{check_id}:{path}:{line}"`
   - `cwe_id` = first CWE number found in `extra.metadata.cwe[]` (regex
     `CWE-(\d+)`), or `""` if absent
   - `severity` = `CRITICAL`→5, `ERROR`→4, `WARNING`→3, `INFO`→1
   - `issue_type` = `check_id`
   - `scan_file` = `"semgrep"`

Both scanners raise `RuntimeError` on non-zero exit.

### 8.3 result_enricher

For each `Finding` with a non-empty `file` field:

1. Resolves `local_path / finding.file` (validates it stays within `local_path`
   to prevent path traversal).
2. Reads ±8 lines around `finding.line` (1-based).
3. Formats the excerpt: each line is prefixed with its line number and `>>>` on
   the sink line.
4. Sets `finding.source_excerpt`.

Findings whose file does not exist or cannot be read receive
`"[source file not found]"` as `source_excerpt`.

### 8.4 result_scorer

Scores each `Finding` in place:

```
score = cwe_base_score + path_boost
```

**CWE base scores:**

| CWE(s) | Score | Category |
|--------|-------|----------|
| 77, 78 | 10 | Command injection |
| 120, 121, 787 | 10 | Buffer overflow |
| 415, 416 | 9 | Double free / use-after-free |
| 502 | 9 | Unsafe deserialization |
| 134 | 8 | Format string |
| 22, 73, 98 | 8 | Path traversal / file inclusion |
| 190, 191 | 7 | Integer overflow / underflow |
| 89 | 7 | SQL injection |
| 918 | 6 | SSRF |
| 79, 80 | 3 | XSS |
| (default) | 2 | Any other qualifying CWE |

**Path boosts (+3 each):**
- file path contains `controllers/`
- file path contains `routes/`

### 8.5 normalizer

1. Filters findings to the configured qualifying CWE set.
2. Sorts: severity descending, `int(cwe_id)` ascending, `issue_id` ascending.
3. Caps at `max_findings` (default 60); sets `capped: true` when truncated.
4. Writes `<sast_dir>/combined_results.json` with structure:

```json
{
  "repo": "<repo_name>",
  "repo_url": "<url-or-null>",
  "scan_engine": "veracode|semgrep",
  "total_qualifying": 42,
  "assessed_count": 42,
  "capped": false,
  "findings": [ ... ]
}
```

5. Also writes `<sast_dir>/raw_findings.json` with all pre-filter findings.

---

## 9. Output Layout

```
<output_dir>/
  <repo_name>/
    .sast-results/
      .veracode/             ← Veracode packages + raw scan JSON (veracode only)
      .semgrep/              ← raw semgrep JSON output (semgrep only)
      raw_findings.json      ← all findings before CWE filter
      combined_results.json  ← filtered, scored, enriched (LLM agent input)
    triage_report.json       ← written by LLM agent after manual triage
```

---

## 10. Configuration

`config/config.yaml`:

```yaml
output:
  dir: "./output"

scan:
  context_lines: 8       # source lines of context around each finding
  max_findings: 60       # cap for combined_results.json
  qualifying_cwes:       # CWE IDs to include (string values)
    - "22"
    - "73"
    # ... (full list in config.yaml)

semgrep:
  config: "auto"         # always pulls latest rules; semgrep caches locally
  pro: false             # set true + SEMGREP_APP_TOKEN for Pro Engine

veracode:
  package_dir_name: ".veracode"
  scan_workers: 1
```

Environment variables (never stored in config files):

| Variable | Used by |
|----------|---------|
| `VERACODE_API_ID` | Veracode CLI authentication |
| `VERACODE_API_KEY` | Veracode CLI authentication |
| `SEMGREP_APP_TOKEN` | Semgrep Pro Engine (optional) |

---

## 11. LLM Agent Integration

After `combined_results.json` is written the tool prints:

```
─────────────────────────────────────
LLM triage ready.

  repo_name   : <repo_name>
  output_dir  : <output_dir>
  findings    : <N> qualifying / <M> total

Open agents/scan-repo.md in your IDE agent (Copilot, Claude Code, etc.)
and provide the following task context:

  repo_name   = <repo_name>
  output_dir  = <absolute output_dir>
─────────────────────────────────────
```

The `agents/scan-repo.md` agent reads
`<output_dir>/<repo_name>/.sast-results/combined_results.json` and writes
`<output_dir>/<repo_name>/triage_report.json`.

---

## 12. Prerequisites

| Tool | How to obtain |
|------|--------------|
| Python ≥ 3.11 | System or pyenv |
| uv | `pip install uv` or `cargo install uv` |
| git | System |
| Veracode CLI | [Veracode docs](https://docs.veracode.com/r/c_about_veracode_static_cli) — must be in PATH |
| semgrep | Installed automatically by `uv sync` (PyPI dependency) |

Setup:

```bash
cd repo-triage
uv sync
uv run sast-llm-triage --help
```
