"""Tests for triage.stages.repo_cloner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from triage.stages.repo_cloner import _is_url, _repo_name_from_url, clone


class TestIsUrl:
    def test_https_is_url(self):
        assert _is_url("https://github.com/owner/repo")

    def test_http_is_url(self):
        assert _is_url("http://github.com/owner/repo")

    def test_git_protocol_is_url(self):
        assert _is_url("git://github.com/owner/repo")

    def test_git_at_is_url(self):
        assert _is_url("git@github.com:owner/repo.git")

    def test_ssh_is_url(self):
        assert _is_url("ssh://git@github.com/owner/repo")

    def test_local_abs_path_is_not_url(self):
        assert not _is_url("/home/user/myrepo")

    def test_local_rel_path_is_not_url(self):
        assert not _is_url("./myrepo")

    def test_windows_path_is_not_url(self):
        assert not _is_url(r"C:\projects\myrepo")


class TestRepoNameFromUrl:
    def test_strips_git_suffix(self):
        assert _repo_name_from_url("https://github.com/owner/MyRepo.git") == "MyRepo"

    def test_no_git_suffix(self):
        assert _repo_name_from_url("https://github.com/owner/MyRepo") == "MyRepo"

    def test_git_at_format(self):
        assert _repo_name_from_url("git@github.com:owner/MyRepo.git") == "MyRepo"

    def test_trailing_slash(self):
        assert _repo_name_from_url("https://github.com/owner/MyRepo/") == "MyRepo"

    def test_sanitizes_unsafe_chars(self):
        name = _repo_name_from_url("https://github.com/owner/my repo!")
        assert " " not in name
        assert "!" not in name

    def test_empty_segment_returns_repo(self):
        # Edge case: URL that ends with nothing useful
        result = _repo_name_from_url("https://github.com/owner/")
        assert result  # non-empty string


class TestCloneLocal:
    def test_valid_local_path_returns_resolved_path_and_name(self, fake_repo: Path):
        local_path, repo_name = clone(str(fake_repo), fake_repo.parent)
        assert local_path.resolve() == fake_repo.resolve()
        assert repo_name == "my-repo"

    def test_non_existent_path_raises_value_error(self, tmp_path: Path):
        with pytest.raises(ValueError, match="does not exist"):
            clone(str(tmp_path / "nonexistent"), tmp_path)

    def test_file_path_raises_value_error(self, tmp_path: Path):
        f = tmp_path / "afile.txt"
        f.write_text("x")
        with pytest.raises(ValueError, match="not a directory"):
            clone(str(f), tmp_path)


class TestCloneRemote:
    def test_successful_clone_returns_dest(self, tmp_path: Path):
        dest = tmp_path / "MyRepo"

        mock_result = MagicMock()
        mock_result.returncode = 0

        def fake_run(cmd, **kwargs):
            # Simulate git clone by creating the destination directory
            dest.mkdir(parents=True, exist_ok=True)
            return mock_result

        with patch("triage.stages.repo_cloner.subprocess.run", side_effect=fake_run) as mock_run:
            local_path, repo_name = clone(
                "https://github.com/owner/MyRepo.git", tmp_path
            )

        mock_run.assert_called_once()
        assert repo_name == "MyRepo"
        assert local_path == dest.resolve()

    def test_failed_clone_raises_runtime_error(self, tmp_path: Path):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "fatal: not a git repository"

        with patch("triage.stages.repo_cloner.subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="git clone"):
                clone("https://github.com/owner/SomeRepo.git", tmp_path)

    def test_existing_dest_skips_clone(self, tmp_path: Path):
        dest = tmp_path / "MyRepo"
        dest.mkdir()

        with patch("triage.stages.repo_cloner.subprocess.run") as mock_run:
            local_path, repo_name = clone(
                "https://github.com/owner/MyRepo.git", tmp_path
            )

        mock_run.assert_not_called()
        assert repo_name == "MyRepo"
        assert local_path == dest
