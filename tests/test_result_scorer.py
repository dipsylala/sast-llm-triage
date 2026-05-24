"""Tests for triage.stages.result_scorer."""

from __future__ import annotations

from factories import make_finding
from triage.stages.result_scorer import score


class TestCweBaseScores:
    def _score(self, cwe_id: str) -> int:
        f = make_finding(cwe_id=cwe_id, file="src/app.py")
        score([f])
        return f.score

    def test_command_injection_78(self):
        assert self._score("78") == 10

    def test_command_injection_77(self):
        assert self._score("77") == 10

    def test_buffer_overflow_120(self):
        assert self._score("120") == 10

    def test_buffer_overflow_121(self):
        assert self._score("121") == 10

    def test_double_free_415(self):
        assert self._score("415") == 9

    def test_use_after_free_416(self):
        assert self._score("416") == 9

    def test_deserialization_502(self):
        assert self._score("502") == 9

    def test_format_string_134(self):
        assert self._score("134") == 8

    def test_path_traversal_22(self):
        assert self._score("22") == 8

    def test_sql_injection_89(self):
        assert self._score("89") == 7

    def test_ssrf_918(self):
        assert self._score("918") == 6

    def test_xss_79(self):
        assert self._score("79") == 3

    def test_xss_80(self):
        assert self._score("80") == 3

    def test_unknown_cwe_defaults_to_2(self):
        assert self._score("999") == 2


class TestPathBoosts:
    def test_controllers_path_adds_3(self):
        f = make_finding(cwe_id="89", file="controllers/user.py")
        score([f])
        assert f.score == 7 + 3  # sql injection base + controllers boost

    def test_routes_path_adds_3(self):
        f = make_finding(cwe_id="89", file="routes/auth.py")
        score([f])
        assert f.score == 7 + 3

    def test_both_boosts_cumulative(self):
        # File path containing both "controllers/" and "routes/"
        f = make_finding(cwe_id="89", file="controllers/routes/app.py")
        score([f])
        assert f.score == 7 + 3 + 3

    def test_no_boost_for_plain_path(self):
        f = make_finding(cwe_id="89", file="src/db.py")
        score([f])
        assert f.score == 7

    def test_windows_backslash_path_still_boosted(self):
        f = make_finding(cwe_id="89", file=r"controllers\user.py")
        score([f])
        assert f.score == 7 + 3


class TestScoreReturnsList:
    def test_returns_same_list(self):
        findings = [make_finding()]
        result = score(findings)
        assert result is findings
