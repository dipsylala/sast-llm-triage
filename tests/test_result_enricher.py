"""Tests for triage.stages.result_enricher."""

from __future__ import annotations

from pathlib import Path

from factories import make_finding

from triage.stages.result_enricher import _build_excerpt, _safe_resolve, enrich


class TestSafeResolve:
    def test_valid_relative_path_resolves(self, fake_repo: Path):
        result = _safe_resolve(fake_repo, "app/db.py")
        assert result is not None
        assert result.is_file()

    def test_non_existent_file_returns_none(self, fake_repo: Path):
        assert _safe_resolve(fake_repo, "app/nonexistent.py") is None

    def test_path_traversal_blocked(self, fake_repo: Path):
        assert _safe_resolve(fake_repo, "../../etc/passwd") is None

    def test_empty_string_returns_none(self, fake_repo: Path):
        assert _safe_resolve(fake_repo, "") is None

    def test_absolute_path_in_rel_slot_blocked(self, fake_repo: Path, tmp_path: Path):
        # A path to a file outside the repo root should be blocked
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        # _safe_resolve strips leading slashes, so this becomes a relative lookup
        result = _safe_resolve(fake_repo, str(outside))
        assert result is None

    def test_veracode_extra_prefix_stripped(self, fake_repo: Path):
        """Veracode sometimes prefixes paths with package name — should be stripped."""
        # app/db.py exists; prepend a bogus top-level segment
        result = _safe_resolve(fake_repo, "bogus-prefix/app/db.py")
        assert result is not None
        assert result.name == "db.py"


class TestBuildExcerpt:
    def test_marker_on_sink_line(self):
        lines = ["line 1\n", "line 2\n", "line 3\n", "line 4\n", "line 5\n"]
        excerpt = _build_excerpt(lines, sink_line=3, context=1)
        assert ">>>" in excerpt
        # Only line 3 should have >>>
        for row in excerpt.splitlines():
            if ">>>" in row:
                assert "line 3" in row

    def test_context_window_size(self):
        lines = [f"line {i}\n" for i in range(1, 11)]
        excerpt = _build_excerpt(lines, sink_line=5, context=2)
        # Lines 3–7 should be present (5 lines total)
        for ln in range(3, 8):
            assert f"line {ln}" in excerpt

    def test_no_crash_at_boundary(self):
        lines = ["only line\n"]
        excerpt = _build_excerpt(lines, sink_line=1, context=5)
        assert "only line" in excerpt
        assert ">>>" in excerpt


class TestEnrich:
    def test_enrich_populates_source_excerpt(self, fake_repo: Path):
        f = make_finding(file="app/db.py", line=10)
        enrich([f], fake_repo, context_lines=2)
        assert f.source_excerpt  # non-empty
        assert ">>>" in f.source_excerpt

    def test_enrich_missing_file_leaves_excerpt_not_found(self, fake_repo: Path):
        f = make_finding(file="nonexistent.py", line=5)
        enrich([f], fake_repo, context_lines=2)
        assert "not found" in f.source_excerpt

    def test_enrich_path_traversal_leaves_excerpt_not_found(self, fake_repo: Path):
        f = make_finding(file="../../etc/passwd", line=1)
        enrich([f], fake_repo, context_lines=2)
        assert "not found" in f.source_excerpt

    def test_enrich_returns_same_list(self, fake_repo: Path):
        findings = [make_finding(file="app/db.py", line=5)]
        result = enrich(findings, fake_repo, context_lines=2)
        assert result is findings

    def test_enrich_line_out_of_range_does_not_crash(self, fake_repo: Path):
        f = make_finding(file="app/db.py", line=9999)
        enrich([f], fake_repo, context_lines=2)
        # excerpt may be empty or partial — just must not raise


class TestEnrichStackDumps:
    def test_empty_snippets_populated(self, fake_repo: Path):
        f = make_finding(
            file="app/db.py",
            line=10,
            stack_dumps=[
                {
                    "source": {"file": "app/db.py", "line": 6, "snippet": ""},
                    "steps": [],
                    "sink": {"file": "app/db.py", "line": 10, "snippet": ""},
                }
            ],
        )
        enrich([f], fake_repo, context_lines=2)
        p = f.stack_dumps[0]
        assert p["source"]["snippet"] != ""
        assert p["sink"]["snippet"] != ""

    def test_existing_snippets_not_overwritten(self, fake_repo: Path):
        f = make_finding(
            file="app/db.py",
            line=10,
            stack_dumps=[
                {
                    "source": {"file": "app/db.py", "line": 6, "snippet": "already set"},
                    "steps": [],
                    "sink": {"file": "app/db.py", "line": 10, "snippet": ""},
                }
            ],
        )
        enrich([f], fake_repo, context_lines=2)
        assert f.stack_dumps[0]["source"]["snippet"] == "already set"

    def test_unresolvable_file_leaves_snippet_unchanged(self, fake_repo: Path):
        f = make_finding(
            file="app/db.py",
            line=10,
            stack_dumps=[
                {
                    "source": {"file": "nonexistent.py", "line": 1, "snippet": ""},
                    "steps": [],
                    "sink": {"file": "app/db.py", "line": 10, "snippet": ""},
                }
            ],
        )
        enrich([f], fake_repo, context_lines=2)
        assert f.stack_dumps[0]["source"]["snippet"] == ""

    def test_none_stack_dumps_does_not_crash(self, fake_repo: Path):
        f = make_finding(file="app/db.py", line=10, stack_dumps=None)
        enrich([f], fake_repo, context_lines=2)  # must not raise

    def test_steps_snippets_populated(self, fake_repo: Path):
        f = make_finding(
            file="app/db.py",
            line=10,
            stack_dumps=[
                {
                    "source": {"file": "app/db.py", "line": 3, "snippet": ""},
                    "steps": [{"file": "app/db.py", "line": 6, "snippet": ""}],
                    "sink": {"file": "app/db.py", "line": 10, "snippet": ""},
                }
            ],
        )
        enrich([f], fake_repo, context_lines=2)
        assert f.stack_dumps[0]["steps"][0]["snippet"] != ""
