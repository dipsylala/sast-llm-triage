"""Stage 1 — Repository cloner / validator.

Accepts either a remote Git URL or a local directory path.  Returns the
absolute local path to the source and the derived repository name.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

# Patterns that look like a remote Git URL.
_URL_PREFIXES = ("https://", "http://", "git://", "git@", "ssh://")
_GIT_SUFFIX_RE = re.compile(r"\.git$", re.IGNORECASE)


def _is_url(repo: str) -> bool:
    return any(repo.startswith(p) for p in _URL_PREFIXES)


def _repo_name_from_url(url: str) -> str:
    """Derive a safe directory name from a Git URL.

    ``https://github.com/owner/MyRepo.git``  →  ``MyRepo``
    ``git@github.com:owner/MyRepo``          →  ``MyRepo``
    """
    # Strip trailing slashes
    url = url.rstrip("/")
    # Take the last path/colon-separated segment
    segment = url.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    # Strip .git suffix
    name = _GIT_SUFFIX_RE.sub("", segment)
    # Replace any characters that would be unsafe in a directory name
    name = re.sub(r"[^\w\-.]", "_", name)
    return name or "repo"


def clone(repo: str, output_dir: Path) -> tuple[Path, str]:
    """Clone *repo* into *output_dir* or validate it as a local path.

    Args:
        repo: A Git URL or an absolute/relative local directory path.
        output_dir: Parent directory for cloned repos.  Ignored when *repo*
            is a local path.

    Returns:
        ``(local_path, repo_name)`` where *local_path* is the absolute path to
        the source directory and *repo_name* is derived from the URL or the
        final path component.

    Raises:
        ValueError: If a local path is provided but does not exist or is not a
            directory.
        RuntimeError: If ``git clone`` fails.
    """
    if _is_url(repo):
        repo_name = _repo_name_from_url(repo)
        dest = output_dir / repo_name

        if dest.exists():
            print(f"[clone] Using existing directory: {dest}")
        else:
            dest.mkdir(parents=True, exist_ok=True)
            print(f"[clone] Cloning {repo} → {dest} ...")
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo, str(dest)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode != 0:
                # Clean up the destination directory (may be partially populated)
                shutil.rmtree(dest, ignore_errors=True)
                raise RuntimeError(
                    f"git clone failed (exit {result.returncode}):\n"
                    f"{result.stderr.strip()}"
                )
            print(f"[clone] Clone complete: {dest}")

        return dest.resolve(), repo_name

    # Local path
    local = Path(repo).resolve()
    if not local.exists():
        raise ValueError(f"Local path does not exist: {local}")
    if not local.is_dir():
        raise ValueError(f"Local path is not a directory: {local}")

    local = local.resolve()
    repo_name = local.name
    return local, repo_name
