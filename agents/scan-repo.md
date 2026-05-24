# SAST Findings Exploitability Assessment — Single Repo

## Goal

For every finding with a relevant CWE ID in **one** scanned repository, assess
whether the flaw is genuinely exploitable, a theoretical risk requiring
unusually difficult conditions, or a false positive.  Write the results to
`<output_dir>/<repo_name>/.sast-results/triage_report.json`.

This agent acts as an **orchestrator**: it reads `triage_findings.json`, spawns
one `triage-finding` worker subagent per finding, collects the returned verdict
objects, and writes the final report.

---

## FIRST STEP — MANDATORY

**Before doing anything else**, check whether
`<output_dir>/<repo_name>/.sast-results/triage_findings.json` exists.

- **If it exists**: Use this file as your sole findings input.  It already
  contains the filtered, sorted findings with source excerpts attached.
  Skip directly to [Iteration](#iteration).
- **If it does not exist**: The `sast-llm-triage` tool has not been run yet, or
  something went wrong.  Stop and inform the user — do not proceed.
- **If it exists but is not valid JSON**: Stop and inform the user:
  `triage_findings.json exists but is not valid JSON — cannot proceed.`

After confirming the JSON is valid, also read
`<output_dir>/<repo_name>/.sast-results/findings_summary.md` if it exists.
It contains a compact Markdown table (issue_id, severity, CWE, file:line,
stack_dumps presence) plus per-severity and per-CWE counts.  Use it to
orient yourself.  Its absence does not block triage.

### Tool policy

- Allowed: `read_file` for `triage_findings.json` and `findings_summary.md`.
- Forbidden: terminal parsing commands (`Get-Content`, `ConvertFrom-Json`,
  `grep`, `rg`, or shell/PowerShell parsing) to read findings JSON.

---

## Inputs

- **`repo_name`** — the folder name inside `output_dir` (provided in the task
  context, e.g. `FUEL-CMS`).
- **`output_dir`** — absolute path to the output root (provided in the task
  context; default: the `output/` folder inside the `repo-triage` project).
- **Input file** — `<output_dir>/<repo_name>/.sast-results/triage_findings.json`
- **Source code** — the cloned repo lives at `<output_dir>/<repo_name>/` (when
  cloned from a URL) or at the path provided to `--repo` (when scanned from a
  local path).  For local-path scans the agent context should include the
  source root.

---

## Relevant CWE scope

The default triage scope mirrors the qualifying CWE set used by `sast-llm-triage`.
Treat CWE IDs as strings without the `CWE-` prefix.

Default CWE IDs:

```text
22, 73, 77, 78, 79, 80, 88, 89, 94, 95, 98, 118, 120, 121, 125, 129, 134,
135, 170, 190, 191, 192, 193, 195, 196, 197, 209, 242, 295, 319, 327, 367,
415, 416, 502, 601, 611, 676, 787, 823, 824, 918
```

If the task context provides extra CWE IDs, include them in the scope list you
pass to each worker.

---

## Iteration

Read `triage_findings.json`.  The file contains:

- `findings` — qualifying findings, filtered and sorted by severity desc / CWE asc.
- `total_pre_dedup` — total qualifying findings before sink deduplication.
- `total_qualifying` — unique sinks after deduplication (number of workers to spawn).

If `findings` is an empty array, write `[]` to `.sast-results/triage_report.json` and
respond with:
`[<repo_name>] done — 0 finding(s) assessed, written to <path>`.

### Per-finding worker invocation

For **each** finding in `findings`, spawn a `triage-finding` worker subagent
with a prompt in this exact format:

```text
repo_name: <repo_name>
repo_root: <absolute path to the repository source root>
cwe_scope: <comma-separated list of active CWE IDs, e.g. "22,78,79,89,...">

finding:
<the finding as a compact JSON object, all fields included>
```

Wait for the worker to return before spawning the next one.

### Collecting results

The worker's response is a single raw JSON object (no markdown fences).  Parse
it and append it to a results list.

If the worker's response cannot be parsed as JSON, insert a fallback entry:

```json
{
  "repo": "<repo_name>",
  "issue_id": "<from finding>",
  "scan_file": "<from finding>",
  "scan_engine": "<from finding>",
  "cwe_id": "<from finding>",
  "issue_type": "<from finding>",
  "severity": "<from finding>",
  "file": "<from finding>",
  "line": "<from finding>",
  "verdict": "needs_review",
  "confidence": "low",
  "summary": "Worker subagent returned unparseable output.",
  "reasoning": "Worker subagent returned unparseable output — manual review required.",
  "source_excerpt": ""
}
```

### Duplicate issue_id+scan_file handling

If two entries in `findings` share identical `issue_id` and `scan_file`, pass
both to separate workers.  When constructing each worker prompt, append:
`NOTE: This finding shares issue_id+scan_file with another entry — assess independently.`
so the worker can annotate its `reasoning` field accordingly.

---

## Output

Always overwrite `<output_dir>/<repo_name>/.sast-results/triage_report.json` for the current
run; do not append.

Write the collected results array to `<output_dir>/<repo_name>/.sast-results/triage_report.json`.

Your final message, sent only after successfully writing the file, must be
exactly one line:
`[<repo_name>] done — N finding(s) assessed, written to <path>`.
Do not include any other text, summary, or markdown in this final message.
