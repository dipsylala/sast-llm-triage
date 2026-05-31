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

Once the scan completes, either:

- **Headless triage** — add `--llm-overlay` and set your API key; the tool
  calls the LLM directly and writes `triage_report.json` without any IDE:

  ```bash
  OPENAI_API_KEY=sk-... uv run sast-llm-triage \
    --repo https://github.com/your-org/your-repo --scanner snyk --llm-overlay
  ```

- **Re-triage without re-scanning** — add `--skip-scan` to skip the clone and
  scan steps and run the overlay against an existing `triage_findings.json`:

  ```bash
  OPENAI_API_KEY=sk-... uv run sast-llm-triage \
    --repo output/your-repo --scanner snyk --skip-scan --llm-overlay
  ```

- **IDE triage** — open `agents/scan-repo.md` in your IDE agent (GitHub
  Copilot, Claude Code, etc.) and supply the `repo_name` and `output_dir`
  values printed at the end of the run.

---

## More information

### CLI options

```bash
sast-llm-triage --repo <url-or-local-path>
            --scanner veracode|semgrep|snyk
            [--output-dir <dir>]          # default: ./output
            [--config <config.yaml>]      # default: config/config.yaml
            [--qualifying-cwes 22,78,89]  # overrides config default
            [--llm-overlay]               # triage via LiteLLM instead of IDE agent
            [--skip-scan]                 # skip clone+scan; use existing triage_findings.json
            [--log]                       # write LLM chat transcripts to llm_chat.jsonl
            [--verbose]
```

A local path can be supplied instead of a URL — the repo is used as-is and
nothing is cloned.

### Output layout

```bash
output/
  <repo_name>/
    .sast-results/
      veracode/
        .veracode/             ← packages + raw scan JSON
        raw_findings.json
        triage_findings.json
        triage_report.json
      semgrep/
        raw_findings.json
        triage_findings.json
        triage_report.json
      snyk/
        .snyk/                 ← raw SARIF output
        raw_findings.json
        triage_findings.json
        triage_report.json
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

---

## Developer notes

### Running tests

```bash
uv sync --extra semgrep   # adds semgrep scanner to dev env
uv run pytest             # all tests
uv run pytest -k snyk     # filter by keyword
uv run pytest --cov       # with coverage report
```

### Linting

```bash
# Python — ruff (import order, unused imports, style)
uv run ruff check src tests

# Auto-fix everything ruff can fix
uv run ruff check --fix src tests

# Markdown — pymarkdownlnt
uv run pymarkdown scan README.md CLAUDE.md SPEC.md agents
```

Both linters are in the `dev` dependency group and installed by `uv sync`.
Ruff is configured in `[tool.ruff]` in `pyproject.toml`; pymarkdown rules in
`[tool.pymarkdown]`.

### Type checking

```bash
uv run mypy src
```

mypy is configured with `strict = true` in `[tool.mypy]`.

---

## LLM Overlay (`--llm-overlay`)

Adding `--llm-overlay` replaces the manual IDE agent step with direct LLM API
calls driven by **[LiteLLM](https://github.com/BerriAI/litellm)** — a single
library that wraps OpenAI, Anthropic, and many other providers behind one
uniform interface.

```bash
# Install the extra dependency
pip install litellm

# Full pipeline — scan + triage in one command
OPENAI_API_KEY=sk-... uv run sast-llm-triage \
  --repo https://github.com/your-org/your-repo --scanner snyk --llm-overlay
```

For each qualifying finding the tool runs a short tool-call loop: the model
receives the finding (with `source_excerpt` and `stack_dumps` already
attached) and may call `read_file` to inspect additional source files before
returning a JSON verdict.  All file reads are sandboxed to the cloned repo
root.

```python
while True:
    response = litellm.completion(model=model, messages=messages, tools=[READ_FILE_TOOL])
    msg = response.choices[0].message
    if msg.tool_calls:          # model wants to read more source
        messages.append(msg)
        for tc in msg.tool_calls:
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "content": read_file_sandboxed(tc, repo_root)})
    else:
        return msg.content      # final verdict JSON
```

Model and turn limit are set in `config.yaml` under `llm_overlay`:

```yaml
llm_overlay:
  model: "openai/gpt-4o"     # prefix selects provider; LiteLLM routes automatically
  max_turns: 10              # guard against runaway tool-call loops
```

Supported model string examples: `openai/gpt-4o`, `anthropic/claude-opus-4-5`,
`azure/gpt-4o` (set `AZURE_API_KEY` / `AZURE_API_BASE`).  Set the matching
env var (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.) before running.

`triage_findings.json` is the handoff contract for both paths — the IDE agent
and `--llm-overlay` read the same file.  `triage_report.json` format is
identical regardless of which path produced it.

**No-tools fallback:** Models that do not support the OpenAI tool-calling
wire format (e.g. many Ollama-hosted models) receive an automatic retry
without tools.  The `source_excerpt` already attached to each finding
provides the necessary context in that mode — no additional file reads are
performed.
