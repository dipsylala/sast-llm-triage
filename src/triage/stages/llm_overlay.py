"""LiteLLM-based headless triage stage.

Reads ``triage_findings.json``, calls the configured LLM (via LiteLLM) with a
tool-call read-loop for each finding, collects verdict objects, and writes
``triage_report.json`` to the same ``.sast-results`` directory.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

# Suppress noisy startup warnings about optional AWS/Bedrock/SageMaker modules.
# Must be set BEFORE importing litellm so the Bedrock pre-load warning is silenced.
import logging as _logging
_logging.getLogger("LiteLLM").setLevel(_logging.ERROR)

try:
    import litellm
    import litellm.exceptions as _litellm_exc
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "litellm is required for --llm-overlay.  "
        "Install it with: pip install litellm"
    ) from _exc

litellm.suppress_debug_info = True

if TYPE_CHECKING:
    from triage.config import LlmOverlayConfig

log = logging.getLogger(__name__)

# Maximum lines returned per read_file call — prevents flooding the context window.
_MAX_LINES_PER_READ = 300

# Tool schema (OpenAI function-calling format; LiteLLM translates for other providers).
_READ_FILE_TOOL: dict = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": (
            "Read a range of lines from a source file in the repository. "
            "Call only when source_excerpt or stack_dumps are insufficient to assess the finding."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Repo-relative path to the file, "
                        "e.g. 'app/src/main/java/com/example/Foo.java'."
                    ),
                },
                "start_line": {
                    "type": "integer",
                    "description": "1-based start line (inclusive). Omit to read from line 1.",
                },
                "end_line": {
                    "type": "integer",
                    "description": "1-based end line (inclusive). Omit to read to end of file.",
                },
            },
            "required": ["path"],
        },
    },
}


def _load_system_prompt() -> str:
    """Load agents/triage-finding.md as the system prompt.

    Walks up from this file's location to find the project root.  Falls back
    to a minimal inline prompt if the file is absent (e.g. installed package).
    """
    candidate = (
        Path(__file__).parent  # stages/
        .parent                # triage/
        .parent                # src/
        .parent                # project root
        / "agents"
        / "triage-finding.md"
    )
    if candidate.is_file():
        return candidate.read_text(encoding="utf-8")
    log.warning(
        "agents/triage-finding.md not found at %s; using built-in fallback prompt.", candidate
    )
    return (
        "You are a security analyst triaging SAST findings for exploitability. "
        "Assess the provided finding and return ONLY a single JSON verdict object "
        "with these fields: repo, issue_id, scan_file, scan_engine, cwe_id, "
        "issue_type, severity, file, line, verdict, confidence, summary, reasoning, "
        "source_excerpt.  Use read_file when the source_excerpt is insufficient."
    )


def _safe_read_file(
    repo_root: Path,
    path: str,
    start_line: int | None,
    end_line: int | None,
) -> str:
    """Read a repository file, sandboxed to ``repo_root``.

    Returns formatted line-numbered text, or an error string on failure.
    """
    p = Path(path)
    candidate = (repo_root / p).resolve() if not p.is_absolute() else p.resolve()

    # Path-traversal guard
    try:
        candidate.relative_to(repo_root.resolve())
    except ValueError:
        return f"ERROR: '{path}' is outside the repository root — access denied."

    if not candidate.is_file():
        return f"ERROR: File not found: {path}"

    try:
        raw_lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"ERROR: Could not read file: {exc}"

    s = max(0, (start_line or 1) - 1)
    e = min(end_line if end_line is not None else len(raw_lines), s + _MAX_LINES_PER_READ)
    selected = raw_lines[s:e]
    return "\n".join(f"{s + i + 1:6d}  {ln}" for i, ln in enumerate(selected))


def _triage_one(
    finding: dict,
    repo_name: str,
    repo_root: Path,
    model: str,
    max_turns: int,
    system_prompt: str,
) -> dict:
    """Run the LiteLLM read-loop for a single finding and return its verdict dict."""
    user_content = (
        f"repo_name: {repo_name}\n"
        f"repo_root: {repo_root}\n\n"
        f"Finding:\n{json.dumps(finding, indent=2)}"
    )

    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]

    for turn in range(max_turns):
        log.debug("    turn %d/%d", turn + 1, max_turns)
        try:
            response = litellm.completion(
                model=model, messages=messages, tools=[_READ_FILE_TOOL]
            )
        except (_litellm_exc.AuthenticationError, _litellm_exc.RateLimitError) as exc:
            # Quota exhausted or bad key — no point continuing; re-raise so the
            # caller can print a clean error and exit.
            raise
        except Exception as exc:
            # Transient / per-finding error — mark this finding needs_review.
            log.warning("    LiteLLM error for %s: %s", finding.get("issue_id"), exc)
            return _error_verdict(
                finding, repo_name,
                f"API error during triage: {type(exc).__name__}",
                str(exc)[:500],
            )
        msg = response.choices[0].message

        # Detect models that return empty content when tools are passed (e.g. Ollama/qwen3).
        # Fall back to a single no-tools call with the source file pre-embedded.
        if not msg.tool_calls and not (msg.content or "").strip():
            log.debug("    empty response — model may not support tools; retrying without tools")
            file_path = finding.get("file", "")
            finding_line = finding.get("line", 1) or 1
            start = max(1, finding_line - 25)
            end = finding_line + 25
            file_content = _safe_read_file(repo_root, file_path, start, end)
            no_tools_content = (
                f"repo_name: {repo_name}\n"
                f"repo_root: {repo_root}\n\n"
                f"Finding:\n{json.dumps(finding, indent=2)}\n\n"
                f"Source file context ({file_path}, lines {start}-{end}):\n{file_content}"
            )
            no_tools_messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": no_tools_content},
            ]
            try:
                nt_response = litellm.completion(model=model, messages=no_tools_messages)
            except (_litellm_exc.AuthenticationError, _litellm_exc.RateLimitError):
                raise
            except Exception as exc:
                log.warning("    no-tools fallback error for %s: %s", finding.get("issue_id"), exc)
                return _error_verdict(finding, repo_name, f"API error: {type(exc).__name__}", str(exc)[:500])
            msg = nt_response.choices[0].message

        if msg.tool_calls:
            # Append assistant turn (with tool_calls) as a plain dict
            messages.append({
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ],
            })
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                path = args.get("path", "")
                start = args.get("start_line")
                end = args.get("end_line")
                log.debug("    read_file(%s, %s, %s)", path, start, end)
                result = _safe_read_file(repo_root, path, start, end)
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
        else:
            # Model returned a final answer — parse the JSON verdict
            raw_original = (msg.content or "")
            raw = raw_original.strip()
            # Strip <think>...</think> blocks (qwen3 and other reasoning models)
            import re as _re
            raw = _re.sub(r"<think>.*?</think>", "", raw, flags=_re.DOTALL).strip()
            # Strip markdown fences in case the model added them
            if raw.startswith("```"):
                raw = "\n".join(
                    line for line in raw.splitlines() if not line.startswith("```")
                ).strip()
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                # Last resort: extract first {...} block from the response
                m = _re.search(r"\{.*\}", raw, _re.DOTALL)
                if m:
                    try:
                        return json.loads(m.group())
                    except json.JSONDecodeError:
                        pass
                log.warning("    verdict was not valid JSON for %s", finding.get("issue_id"))
                log.warning("    raw response (first 1000 chars):\n%s", raw[:1000])
                return _error_verdict(finding, repo_name, "LLM returned non-JSON output.", raw[:500])

    log.warning(
        "    max_turns (%d) exceeded for %s", max_turns, finding.get("issue_id")
    )
    return _error_verdict(
        finding,
        repo_name,
        f"max_turns ({max_turns}) exceeded without a verdict.",
        "The model kept calling read_file without returning a final verdict.",
    )


def _error_verdict(finding: dict, repo_name: str, summary: str, reasoning: str) -> dict:
    return {
        "repo": repo_name,
        "issue_id": finding.get("issue_id", "unknown"),
        "scan_file": finding.get("scan_file", ""),
        "scan_engine": finding.get("scan_engine", ""),
        "cwe_id": finding.get("cwe_id", ""),
        "issue_type": finding.get("issue_type", ""),
        "severity": finding.get("severity", 0),
        "file": finding.get("file", ""),
        "line": finding.get("line", 0),
        "verdict": "needs_review",
        "confidence": "low",
        "summary": summary,
        "reasoning": reasoning,
        "source_excerpt": finding.get("source_excerpt", ""),
    }


def run_llm_overlay(
    sast_dir: Path,
    repo_root: Path,
    repo_name: str,
    overlay_cfg: "LlmOverlayConfig",
) -> Path:
    """Triage all qualifying findings via LiteLLM and write ``triage_report.json``.

    Args:
        sast_dir:     Path to the ``.sast-results`` directory.
        repo_root:    Absolute path to the cloned repository source root.
        repo_name:    Repository folder name (written into verdict objects).
        overlay_cfg:  LLM overlay configuration (model string, max_turns).

    Returns:
        Path to the written ``triage_report.json``.

    Raises:
        FileNotFoundError: If ``triage_findings.json`` does not exist in ``sast_dir``.
    """
    findings_path = sast_dir / "triage_findings.json"
    if not findings_path.is_file():
        raise FileNotFoundError(
            f"triage_findings.json not found at {findings_path}. "
            "Run the pipeline without --llm-overlay first to generate it."
        )

    data = json.loads(findings_path.read_text(encoding="utf-8"))
    findings: list[dict] = data.get("findings", [])

    system_prompt = _load_system_prompt()
    verdicts: list[dict] = []

    print(
        f"\n[llm-overlay] model={overlay_cfg.model}  "
        f"findings={len(findings)}  max_turns={overlay_cfg.max_turns}"
    )

    try:
        _supports_tools = litellm.supports_function_calling(model=overlay_cfg.model)
    except Exception:
        _supports_tools = None  # unknown — don't warn

    if _supports_tools is False:
        print(
            f"[llm-overlay] WARNING: {overlay_cfg.model!r} does not support tool calling. "
            "The no-tools fallback will be used (source file pre-embedded in prompt). "
            "Consider switching to a model with tool-calling support for better results."
        )
    for i, finding in enumerate(findings, 1):
        issue_id = finding.get("issue_id", f"finding-{i}")
        print(f"[llm-overlay] {i}/{len(findings)} {issue_id}")
        try:
            verdict = _triage_one(
                finding=finding,
                repo_name=repo_name,
                repo_root=repo_root,
                model=overlay_cfg.model,
                max_turns=overlay_cfg.max_turns,
                system_prompt=system_prompt,
            )
        except _litellm_exc.AuthenticationError as exc:
            raise RuntimeError(
                f"[llm-overlay] Authentication failed — check your API key.\n{exc}"
            ) from exc
        except _litellm_exc.RateLimitError as exc:
            # Distinguish quota exhausted (insufficient_quota) from true rate limit
            msg = str(exc)
            if "insufficient_quota" in msg:
                raise RuntimeError(
                    "[llm-overlay] OpenAI quota exhausted — add credits at "
                    "https://platform.openai.com/settings/organization/billing"
                ) from exc
            raise RuntimeError(
                f"[llm-overlay] Rate limit hit — slow down or switch model.\n{exc}"
            ) from exc
        verdicts.append(verdict)

    report_path = sast_dir / "triage_report.json"
    report_path.write_text(
        json.dumps(verdicts, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[llm-overlay] triage_report.json → {report_path}")
    return report_path
