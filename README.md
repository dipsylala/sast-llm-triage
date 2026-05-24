# sast-llm-triage

A CLI tool that scans a Git repository with **Veracode**, **Semgrep**, or **Snyk Code**,
enriches and scores the findings, and writes a structured `triage_findings.json` ready
for LLM-assisted exploitability triage via an IDE agent.

---

## Quick start

**Prerequisites:** Python 3.11+, [uv](https://docs.astral.sh/uv/)

```bash
# Install dependencies
uv sync

# Scan with Semgrep (runs entirely locally, no credentials required)
uv run sast-llm-triage --repo https://github.com/your-org/your-repo --scanner semgrep

# Scan with Snyk Code (requires Snyk CLI + snyk auth)
uv run sast-llm-triage --repo https://github.com/your-org/your-repo --scanner snyk

# Scan with Veracode (requires Veracode CLI and API keys)
uv run sast-llm-triage --repo https://github.com/your-org/your-repo --scanner veracode
```

Once the scan completes, open `agents/scan-repo.md` in your IDE agent (GitHub
Copilot, Claude Code, etc.) and supply the `repo_name` and `output_dir` values
printed at the end of the run.  The agent reads `triage_findings.json` and
writes `triage_report.json`.

---

## More information

### CLI options

```bash
sast-llm-triage --repo <url-or-local-path>
            --scanner veracode|semgrep|snyk
            [--output-dir <dir>]          # default: ./output
            [--config <config.yaml>]      # default: config/config.yaml
            [--qualifying-cwes 22,78,89]  # overrides config default
            [--verbose]
```

A local path can be supplied instead of a URL — the repo is used as-is and
nothing is cloned.

### Output layout

```bash
output/
  <repo_name>/
    .sast-results/
      .veracode/             ← Veracode packages + raw scan JSON (veracode only)
      .semgrep/              ← raw Semgrep JSON output (semgrep only)
      .snyk/                 ← raw Snyk SARIF JSON output (snyk only)
      raw_findings.json      ← all findings before CWE filtering
      triage_findings.json  ← filtered, scored, enriched — LLM agent input
    triage_report.json       ← written by the LLM agent after triage
```

### Scan engines

| Engine | How it runs | Credentials |
| -------- | ------------- | ------------- |
| Semgrep | Entirely local — source code never leaves the machine | None required for OSS; run `semgrep login` before enabling `semgrep.pro: true` in config |
| Snyk Code | Source tree sent to Snyk cloud analysis API | Install Snyk CLI ([docs](https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli)), then run `snyk auth` once |
| Veracode | Packages locally; analysis runs in Veracode Pipeline Scan cloud API | Veracode API keys required |

### Configuration

`config/config.yaml` controls the output directory, source-context window,
findings cap, qualifying CWE list, and scanner options.  Environment variables
for credentials are loaded from a `.env` file if present (never committed).

### Running tests

```bash
# Install dev dependencies plus the semgrep optional extra (needed for semgrep scanner tests)
uv sync --extra semgrep

uv run python -m pytest
```
