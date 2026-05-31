"""Shared subprocess runner used by all scanners."""

from __future__ import annotations

import datetime
import subprocess
from pathlib import Path


def _tool_available(cmd: str | list[str], shell: bool = False) -> bool:
    """Return ``True`` if *cmd* exits with code 0.

    Pass the full command to run — nothing is appended automatically.

    Set ``shell=True`` for tools that ship as shell wrappers on Windows
    (e.g. ``snyk.ps1``, ``snyk.cmd``) so the OS shell resolves the wrapper
    rather than relying on ``CreateProcess`` finding the executable.
    ``shutil.which`` returns ``None`` for these wrappers, which is why
    subprocess invocation is used here instead.

    Examples::

        _tool_available(["veracode", "version"])
        _tool_available(["snyk", "version"], shell=sys.platform == "win32")
        _tool_available(["uv", "run", "semgrep", "show", "version"])
    """
    full_cmd = [cmd] if isinstance(cmd, str) else list(cmd)
    try:
        result = subprocess.run(
            full_cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=shell,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def run_cmd(
    cmd: list[str],
    cwd: Path,
    log_file: Path | None = None,
) -> tuple[bool, str]:
    """Run *cmd* in *cwd*, streaming output to stdout (and optionally *log_file*).

    Returns ``(success, combined_output)`` where *success* is ``True`` when the
    process exits with code 0.

    Note: *cmd* must never contain values derived from untrusted user input
    without prior validation — callers are responsible for sanitising any
    path or string arguments before passing them here.
    """
    cmd_str = " ".join(cmd)
    print(f"  $ {cmd_str}")

    log_fh = None
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_fh = log_file.open("w", encoding="utf-8")
        started = datetime.datetime.now().isoformat(timespec="seconds")
        log_fh.write(f"# Started : {started}\n")
        log_fh.write(f"# Command : {cmd_str}\n")
        log_fh.write(f"# Cwd     : {cwd}\n")
        log_fh.write("#" + "-" * 78 + "\n")
        log_fh.flush()

    output_lines: list[str] = []
    returncode: int = -1

    try:
        with subprocess.Popen(
            cmd,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        ) as proc:
            assert proc.stdout is not None
            for line in proc.stdout:
                print(line, end="")
                output_lines.append(line)
                if log_fh is not None:
                    log_fh.write(line)
            proc.wait()
            returncode = proc.returncode
    except FileNotFoundError as exc:
        msg = f"ERROR: executable not found — {exc}\n"
        print(f"  {msg}", end="")
        output_lines.append(msg)
        if log_fh is not None:
            log_fh.write(msg)
        returncode = -1
    finally:
        if log_fh is not None:
            finished = datetime.datetime.now().isoformat(timespec="seconds")
            log_fh.write("#" + "-" * 78 + "\n")
            log_fh.write(f"# Finished: {finished}\n")
            log_fh.write(f"# Exit    : {returncode}\n")
            log_fh.close()

    if returncode != 0:
        print(f"  ERROR: command exited with code {returncode}")

    return returncode == 0, "".join(output_lines)


def capture_cmd(cmd: list[str], cwd: Path, *, shell: bool = False) -> tuple[bool, str, str]:
    """Run *cmd* and capture stdout and stderr separately.

    Returns ``(success, stdout, stderr)``.  Does not stream to the console —
    callers must print what they need.

    Pass ``shell=True`` on Windows to let ``cmd.exe`` resolve shell wrappers
    such as ``.cmd`` files that ``CreateProcess`` cannot execute directly.
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=shell,
        )
    except FileNotFoundError as exc:
        return False, "", f"executable not found: {exc}"

    return result.returncode == 0, result.stdout, result.stderr
