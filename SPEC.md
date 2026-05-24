# SPEC.md — Single-Repo SAST + LLM Triage Tool

## 1. Overview

This document specifies a command-line tool (`sast-llm-triage`) that takes a single
Git repository, runs a static analysis scan against it, enriches the
findings, and writes a structured `triage_findings.json` file ready for
LLM-assisted exploitability triage.

The tool is designed to support security researchers and developers who want a
quick, local, single-repo triage workflow without the overhead of the bulk
discovery pipeline.

---

## 2. Goals

1. Accept a single repository (URL or local path) as input.
2. Run a SAST scan using **Veracode Pipeline Scan**, **Semgrep**, or **Snyk Code**.
3. Enrich each finding with surrounding source-code context.
4. Produce a normalised `triage_findings.json` ready
   for the LLM triage agent (`agents/scan-repo.md`).
5. Print clear post-run instructions so the user can invoke the triage agent in
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

```text
CLI input (--repo URL | local-path, --scanner veracode|semgrep|snyk)
           ↓
     repo_cloner        →  local_path (cloned or validated)
           ↓
     scanner            →  ScanResult (raw Finding objects)
       veracode.py          veracode package + veracode static scan
       semgrep.py           semgrep --config auto [--pro]
       snyk.py              snyk code test --json
           ↓
     result_enricher    →  Finding.source_excerpt populated (±8 lines)
           ↓

     normalizer         →  triage_findings.json written to disk
           ↓
   [Manual step]
     LLM agent (agents/scan-repo.md)
       reads   <output_dir>/<repo_name>/.sast-results/triage_findings.json
       writes  <output_dir>/<repo_name>/triage_report.json
```

---

## 5. CLI Interface

```text
sast-llm-triage --repo <url-or-local-path> \
            --scanner veracode|semgrep|snyk \
            [--output-dir <dir>]         # default: ./output
            [--config <config.yaml>]     # default: bundled config/config.yaml
            [--qualifying-cwes 22,78,89] # overrides config default
```

### Exit codes

| Code | Meaning |
| ------ | --------- |
| 0 | Success — `triage_findings.json` written |
| 1 | Scan tool error (non-zero exit from veracode / semgrep / snyk) |
| 2 | Configuration or argument error |

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

- Installed as an optional Python dependency: `uv sync --extra semgrep` (PyPI: `semgrep`).
- Engine runs **entirely locally** — source code is never uploaded.
- Always uses `--config auto` (pulls latest rules from Semgrep registry;
  semgrep's own cache handles repeated runs).
- Set `semgrep.pro: true` in `config.yaml` and export `SEMGREP_APP_TOKEN` to
  enable the Semgrep Pro Engine (interfile analysis). Free tier works without
  any token.

### 6.3 Snyk Code

- Requires the **Snyk CLI** (`snyk`) in PATH.
  Install: [https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli](https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli)
- Requires a one-time `snyk auth` before first use.
- `snyk code test --json <local_path>` sends the source tree to the **Snyk
  cloud analysis API** and returns findings as a SARIF 2.1.0 document.
- Exit code 1 means findings were found (not an error); exit code ≥ 2 is a
  genuine failure.
- Raw SARIF output is saved to
  `<output_dir>/<repo_name>/.sast-results/.snyk/raw_snyk_output.json`.

---

## 7. Data Models

### 7.1 Finding

| Field | Type | Description |
| ------- | ------ | ------------- |
| `issue_id` | `str` | Unique ID within this scan |
| `scan_file` | `str` | Source filename (Veracode: filtered JSON name; Semgrep: `"semgrep"`; Snyk: `"snyk"`) |
| `cwe_id` | `str` | CWE number as string, e.g. `"89"` |
| `issue_type` | `str` | Human-readable flaw category |
| `severity` | `int` | 0–5 (Veracode scale: 4=High, 5=Very High; Snyk: `error`→5, `warning`→3, `note`/`none`→1) |
| `file` | `str` | Repo-relative source file path |
| `line` | `int` | Line number of the sink |
| `scan_engine` | `str` | `"veracode"`, `"semgrep"`, or `"snyk"` |
| `display_text` | `str` | Tool description of the flaw class |
| `source_excerpt` | `str` | Sink line marked `>>>` plus ±8 context lines (set by enricher) |
| `stack_dumps` | `dict \| None` | Normalised data-flow paths (source → sink) from Veracode, Semgrep, or Snyk when present |

### 7.2 ScanResult

| Field | Type | Description |
| ------- | ------ | ------------- |
| `repo_name` | `str` | Repository name (derived from URL or path) |
| `repo_path` | `Path` | Absolute path to the cloned/provided source |
| `scan_engine` | `str` | `"veracode"`, `"semgrep"`, or `"snyk"` |
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

**SnykScanner.scan(local_path)**

1. Runs `snyk code test --json [--severity-threshold <level>] <local_path>`
   and captures stdout.
2. Exit code 1 (findings present) is not treated as a failure; exit code ≥2
   or an authentication error raises `RuntimeError` with a hint to run
   `snyk auth`.
3. Parses the SARIF 2.1.0 output (`runs[0].results[]` array);
   builds a rule index from `runs[0].tool.driver.rules[]` for CWE lookup.
4. Maps each result to a `Finding`:
   - `issue_id` = `f"{ruleId}:{uri}:{startLine}"` (with `%SRCROOT%/` stripped)
   - `cwe_id` = first CWE number from `rule.properties.cwe[]`
   - `severity` = `error`→5, `warning`→3, `note`/`none`→1
   - `issue_type` = `rule.shortDescription.text`
   - `scan_file` = `"snyk"`
   - `stack_dumps` = normalised from SARIF `codeFlows[].threadFlows[].locations[]`
     (first location = source, last = sink, middle = steps)

All scanners raise `RuntimeError` on fatal errors.

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

### 8.4 normalizer

1. Filters findings to the configured qualifying CWE set.
2. Sorts: severity descending, `int(cwe_id)` ascending, `issue_id` ascending.
3. Writes `<sast_dir>/triage_findings.json` with structure:

    ```json
    {
      "repo": "<repo_name>",
      "repo_url": "<url-or-null>",
      "scan_engine": "veracode|semgrep|snyk",
      "total_qualifying": 42,
      "findings": [ ... ]
    }
    ```

4. Also writes `<sast_dir>/raw_findings.json` with all pre-filter findings.

---

## 9. Output Layout

```text
<output_dir>/
  <repo_name>/
    .sast-results/
      .veracode/             ← Veracode packages + raw scan JSON (veracode only)
      .semgrep/              ← raw Semgrep JSON output (semgrep only)
      .snyk/                 ← raw Snyk SARIF JSON output (snyk only)
      raw_findings.json      ← all findings before CWE filter
      triage_findings.json  ← filtered, enriched (LLM agent input)
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

snyk:
  severity_threshold: "low"  # low | medium | high | critical
```

Environment variables (never stored in config files):

| Variable | Used by |
| ---------- | --------- |
| `VERACODE_API_ID` | Veracode CLI authentication |
| `VERACODE_API_KEY` | Veracode CLI authentication |
| `SEMGREP_APP_TOKEN` | Semgrep Pro Engine (optional) |

---

## 11. LLM Agent Integration

After `triage_findings.json` is written the tool prints:

```text
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
`<output_dir>/<repo_name>/.sast-results/triage_findings.json` and writes
`<output_dir>/<repo_name>/triage_report.json`.

---

## 12. Prerequisites

| Tool | How to obtain |
| ------ | -------------- |
| Python ≥ 3.11 | System or pyenv |
| uv | `pip install uv` or `cargo install uv` |
| git | System |
| Veracode CLI | [Veracode docs](https://docs.veracode.com/r/c_about_veracode_static_cli) — must be in PATH |
| semgrep | Installed automatically by `uv sync` (PyPI dependency) |
| Snyk CLI | [Snyk docs](https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli) — must be in PATH; run `snyk auth` after install |

Setup:

```bash
cd repo-triage
uv sync
uv run sast-llm-triage --help
```
