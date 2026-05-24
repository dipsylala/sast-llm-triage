# SAST Findings Exploitability Assessment — Single Repo

## Goal

For every finding with a relevant CWE ID in **one** scanned repository, assess
whether the flaw is genuinely exploitable, a theoretical risk requiring
unusually difficult conditions, or a false positive.  Write the results to
`<output_dir>/<repo_name>/triage_report.json`.

---

## FIRST STEP — MANDATORY

**Before doing anything else**, check whether
`<output_dir>/<repo_name>/.sast-results/triage_findings.json` exists.

- **If it exists**: Use this file as your sole findings input.  It already
  contains the filtered, sorted findings with source excerpts attached.
  Skip directly to the [Assessment process](#assessment-process).
  The source-file read rule defined there governs all repository source-file
  reads during analysis; it does not prevent reading source files, it only
  restricts when to do so.
- **If it does not exist**: The `sast-llm-triage` tool has not been run yet, or
  something went wrong.  Stop and inform the user — do not proceed.
- **If it exists but is not valid JSON**: Stop and inform the user:
  `triage_findings.json exists but is not valid JSON — cannot proceed.`

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

If the task context provides extra CWE IDs, include them.

If `triage_findings.json` contains a finding whose `cwe_id` is not in the
active scope, include it in the triage report but prepend the following to its
`reasoning`: `NOTE: cwe_id <X> is outside the active triage scope.`

---

## Finding schema (relevant fields)

```text
issue_id        — unique ID within this scan
scan_file       — source filename ("semgrep" for Semgrep findings; filtered
                  JSON filename for Veracode findings)
cwe_id          — CWE number as a string, e.g. "89"
issue_type      — human-readable flaw category
severity        — 0–5 (4 = High, 5 = Very High)
scan_engine     — "veracode" or "semgrep"
display_text    — tool description of the flaw class
file            — repo-relative path to the sink
line            — line number of the sink
source_excerpt  — sink line marked >>> plus ±8 lines of context
stack_dumps     — list of normalized data-flow paths (present only when the
                  scanner resolved at least one source → sink path; Semgrep
                  only emits this for taint-mode rules — pattern rules omit
                  it); each entry: {source, steps[], sink} where each node is
                  {file, line, snippet}; Veracode may yield multiple paths
                  (one per call chain) for a single finding
```

---

## Assessment process

### Tool policy

- Allowed: `read_file` for `triage_findings.json` and source analysis.
- Forbidden: terminal parsing commands (`Get-Content`, `ConvertFrom-Json`,
  `grep`, `rg`, or shell/PowerShell parsing) to read findings JSON.

### Reading triage_findings.json

The file was already loaded in the FIRST STEP.  Proceed directly using its
`findings` array.

The file contains:

- `findings` — the qualifying findings already filtered and sorted by
  severity desc / CWE asc.
- `total_qualifying` — total number of qualifying findings.
- Per finding: `issue_id`, `scan_file`, `scan_engine`, `cwe_id`, `issue_type`,
  `severity`, `file`, `line`, `source_excerpt`, and optionally
- `source_excerpt` — the sink line marked with `>>>` plus ±8 lines of context.
  **This is your primary sink read.**  When copying this field to the output
  report, trim it to the 4 lines nearest the flagged line.
- `stack_dumps` — when present, a list of data-flow paths; each path has
  `source`, `steps[]`, and `sink`; each node has `file` (repo-relative path),
  `line` (1-based), and `snippet` (expression text).  Veracode findings may
  have several paths (one per call chain).  Semgrep findings only have
  `stack_dumps` when the rule uses `mode: taint`; pattern-matching rules (the
  majority) produce no trace and will not have this field.

If `triage_findings.json` exists but parses as valid JSON with an empty
`findings` array, write `[]` to `triage_report.json` and respond with:
`[<repo_name>] done — 0 finding(s) assessed, written to <path>`.

If two entries share identical `issue_id` and `scan_file`, triage both
independently and annotate each `reasoning` field:
`NOTE: Duplicate issue_id+scan_file pair — assessed independently.`

Entries with the same `issue_id` but different `scan_file` values are findings
from different scan engines; treat them as entirely independent with no
annotation required.

**Source-file read rule (canonical):** Only call `read_file` on a repository
source file when the ±8-line `source_excerpt` does not reveal (a) the taint
origin, (b) whether effective sanitization is present between source and sink,
or (c) whether the code path is reachable.  Do not read source files to seek
confirming evidence when a verdict is already clear from the excerpt.

### 1. Read the sink

Use the `source_excerpt` from `triage_findings.json` as your starting point.
Only call `read_file` on the actual source file if you need context beyond the
±8 lines already provided.  Identify:

- What operation is being performed (eval, query, exec, redirect, etc.)
- What variable is tainted at the sink

If `line` is 0, null, or absent and no `source_excerpt` is available, assign
`needs_review` for that finding with `reasoning` noting the missing line
information, and continue to the next finding.

### 2. Trace the data flow

If `stack_dumps` is present and non-empty (either scanner), iterate
`stack_dumps[]` — each element is one complete source → sink path.  Within a
path, walk `source` → `steps[]` → `sink` in order.  When multiple paths are
present (Veracode findings), assess each one; use the path with the fewest
unresolvable steps (most snippets non-empty and files within the repo root) to
inform the verdict.  For each step, use `file` and `line` to read the source
file only if neither the step's `snippet` nor the existing `source_excerpt`
already reveals the taint path for that step.  If `stack_dumps` is absent or
is an empty array, infer the taint path from `source_excerpt`, `issue_type`,
and `display_text`.

If a step `file` resolves outside the repository root, do not read that
external file.  Proceed to Step 2a regardless of whether external files were
encountered.

Answer:

- Where does the tainted value originate? (HTTP input, file, database, config, constant)
- Is it user-controllable from outside the application?
- Does it pass through any sanitization, validation, or allow-listing?

### 2a. Check cross-language boundaries

Static tools often stop taint analysis at the language boundary of the reported
sink.  If the data-flow path, variable names, URLs, route names, DTO/model
names, generated clients, templates, build files, or source excerpt suggest
that the source or an intermediate hop crosses into another language in the same
repository, inspect that counterpart code before assigning the verdict.

Treat these as cross-language boundary indicators:

- Browser or Node.js code calling a backend endpoint (`fetch`, `XMLHttpRequest`,
  `axios`, `request`, `got`) that is implemented by another server-side language.
- Server-side code consuming a response from another in-repo service before
  passing it to the reported sink.
- Templates or server-rendered pages embedding values into JavaScript, HTML
  attributes, URLs, JSON blobs, or data attributes consumed by client-side code.
- Native/managed bridges such as JNI, P/Invoke, FFI, Node native addons,
  Python extensions, CLI wrappers, or subprocess calls.
- Shared API contracts, route constants, OpenAPI/Swagger specs, generated
  clients, or DTO/schema names that connect files in different languages.

When a boundary indicator exists, use repo-local evidence to connect both
sides.  Do not mark a finding `false_positive` merely because the scanner's
data-flow path stops at a language boundary.

### 3. Assess exploitability

Consider:

- **Reachability** — is this code path reachable in normal execution?
- **Input control** — can an unauthenticated or low-privilege attacker supply
  the tainted value?
- **Sanitization** — is there effective escaping, parameterization, type
  coercion, or allow-listing?
- **Cross-language propagation** — does attacker-controlled data cross language
  boundaries before reaching the sink?
- **Impact** — RCE, data exfiltration, privilege escalation, etc.
- **Native-code context** — for C/C++ memory findings, determine whether
  attacker-controlled input influences the size, index, format string, buffer
  contents, or object lifetime.

### 4. Assign a verdict

Unless the task context specifies otherwise, the **relevant threat actor** is
an unauthenticated external HTTP attacker.

**Before applying the tree:** If the source file is unreadable (missing, binary,
or minified with no unminified counterpart), assign `needs_review` for that
finding and continue to the next.

| Verdict | Meaning |
| --- | --- |
| `exploitable` | Attacker input reaches a dangerous sink with no effective sanitization. High confidence. |
| `likely_exploitable` | Path reachable and unsanitized but uncertainty remains (partial context, auth required, indirect input). |
| `needs_review` | Exploitability cannot be determined statically (opaque flow, unreadable dependency, partial trace). |
| `unlikely_exploitable` | Structural constraints or hard-to-bypass sanitization make exploitation unlikely in practice. |
| `mitigated_by_design` | Taint originates exclusively from outside the attack surface, OR effective sanitization is present that the threat actor cannot bypass. |
| `false_positive` | The flagged line is absent, the scanner misidentified the file/line, or the CWE class is inapplicable to this specific usage. |

**Attack surface definition:** The attack surface consists of inputs a user
can supply directly — HTTP request parameters, headers, cookies, form fields,
file uploads, CLI arguments, and interactive dialog inputs.  Config files,
environment variables, operator-managed database rows, and trusted internal
service responses are *outside* the attack surface.

**Decision tree** — apply in order; use the first match:

1. Is the sink line present in available source and a real instance of the
   flagged operation class?  If not → `false_positive`.
2. Does the tainted value originate *exclusively* from outside the attack
   surface (config, env vars, operator DB rows, trusted internal responses)?
   If yes → `mitigated_by_design`.
3. Is effective sanitization present between source and sink?  If present and
   not bypassable → `mitigated_by_design`.  If present but bypassable only
   with significant effort → `unlikely_exploitable`.
4. Are there structural constraints making exploitation unlikely in practice
   (admin auth required, endpoint not internet-exposed, dead code path)?
   If yes → `unlikely_exploitable`.
5. Is the data flow opaque, or would tracing the path require reading more than
   2–3 additional source files beyond those already read?
   If yes → `needs_review`.
6. Is the path reachable and unsanitized with remaining uncertainty (e.g. auth
   required, partial context)?  If yes → `likely_exploitable`.
7. Is attacker input reachable at the sink with no auth required, no
   sanitization, and the sink performs a directly high-impact operation?
   If yes → `exploitable`.

---

## Output

Always overwrite `<output_dir>/<repo_name>/triage_report.json` for the current
run; do not append.

If zero qualifying findings are present, write `[]` to `triage_report.json`.

`confidence` must be one of: `high`, `medium`, `low`.

- `high` — taint origin, reachability, and sink unsafety are directly
  evidenced in available code/excerpts.
- `medium` — one material uncertainty remains.
- `low` — multiple assumptions required or key context is missing.

Write results to `<output_dir>/<repo_name>/triage_report.json`.  Structure:

```json
[
  {
    "repo": "<repo_name>",
    "issue_id": "1042",
    "scan_file": "filtered_veracode-auto-pack-MyRepo-php.json",
    "scan_engine": "veracode",
    "cwe_id": "89",
    "issue_type": "SQL Injection",
    "severity": 4,
    "file": "app/controllers/UserController.php",
    "line": 142,
    "verdict": "likely_exploitable",
    "confidence": "medium",
    "summary": "One-sentence summary of the flaw and taint path.",
    "reasoning": "Detailed explanation: where taint originates, what sanitization (if any) was observed, why the verdict was assigned.",
    "source_excerpt": "Copy the source_excerpt value from triage_findings.json, trimmed to the 4 lines nearest the flagged line."
  }
]
```

Your final message, sent only after successfully writing the file, must be
exactly one line:
`[<repo_name>] done — N finding(s) assessed, written to <path>`.
Do not include any other text, summary, or markdown in this final message.
