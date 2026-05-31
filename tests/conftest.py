"""Shared pytest fixtures for the repo-triage test suite.

Non-fixture helpers (make_finding, make_scan_result) and raw sample data
(SEMGREP_RESULT_DICT, VERACODE_FINDING_DICT) live in tests/factories.py so
they can be imported explicitly without relying on conftest's path magic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_repo(tmp_path: Path) -> Path:
    """A tiny fake repository directory with a few source files."""
    repo = tmp_path / "my-repo"
    repo.mkdir()

    app_dir = repo / "app"
    app_dir.mkdir()

    controller_dir = repo / "controllers"
    controller_dir.mkdir()

    (app_dir / "db.py").write_text(
        "\n".join(
            [
                "# line 1",
                "# line 2",
                "import sqlite3",
                "def connect():",
                "    pass",
                "def query(user_input):",
                "    conn = sqlite3.connect(':memory:')",
                "    cursor = conn.cursor()",
                "    # bad",
                "    cursor.execute('SELECT * FROM users WHERE id=' + user_input)",
                "    return cursor.fetchall()",
                "# line 12",
            ]
        ),
        encoding="utf-8",
    )

    (controller_dir / "user.py").write_text(
        "def index():\n    pass\n",
        encoding="utf-8",
    )

    return repo


@pytest.fixture()
def mini_repo(tmp_path: Path) -> Path:
    """A minimal repo with precisely known line numbers for integration tests.

    Layout
    ------
    app/db.py        — 12 lines; SQL sink at line 9 (cursor.execute)
    routes/api.py    — 5 lines;  taint source at line 4 (request.args.get)
    """
    repo = tmp_path / "mini-repo"
    repo.mkdir()

    app = repo / "app"
    app.mkdir()

    (app / "db.py").write_text(
        "\n".join([
            "import sqlite3",                                          # 1
            "",                                                        # 2
            "def get_user(user_id):",                                  # 3
            "    conn = sqlite3.connect(':memory:')",                  # 4
            "    cursor = conn.cursor()",                              # 5
            "    # tainted input flows here",                         # 6
            "    query = 'SELECT * FROM users WHERE id=' + user_id",  # 7
            "    # sink",                                              # 8
            "    cursor.execute(query)",                               # 9
            "    return cursor.fetchall()",                            # 10
            "",                                                        # 11
            "# end",                                                   # 12
        ]),
        encoding="utf-8",
    )

    routes = repo / "routes"
    routes.mkdir()

    (routes / "api.py").write_text(
        "\n".join([
            "from flask import request",          # 1
            "",                                   # 2
            "def search():",                      # 3
            "    uid = request.args.get('id')",  # 4
            "    return get_user(uid)",           # 5
        ]),
        encoding="utf-8",
    )

    return repo
