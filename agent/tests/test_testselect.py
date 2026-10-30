"""Tests for the rule-based smart test selection (testselect.py).

A synthetic repo tree is built under tmp_path for each test so the rules
can be exercised deterministically, independent of the real repository.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flowstallion_agent.testselect import TestSelection, select_tests

REPO_FILES = {
    "go.mod": "module example.com/demo\n",
    "go.sum": "",
    "Makefile": "all:\n\techo hi\n",
    "pyproject.toml": "[project]\nname = 'demo'\n",
    "requirements.txt": "pytest\n",
    "docs/notes.md": "# notes\n",
    "pkg/foo/foo.go": "package foo\n",
    "pkg/foo/foo_test.go": "package foo\n",
    "pkg/bar/bar.go": "package bar\n",
    "cmd/app/main.go": "package main\n",
    "agent/demo/moo.py": "def moo(): pass\n",
    "agent/demo/utils.py": "def helper(): pass\n",
    "agent/tests/test_moo.py": "def test_moo(): pass\n",
    "agent/tests/test_other.py": "def test_other(): pass\n",
    "agent/tests/util_helper.py": "def shared(): pass\n",
    "top.py": "def top(): pass\n",
}


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    for rel, content in REPO_FILES.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


def sel(changed: list[str], repo: Path) -> TestSelection:
    return select_tests(changed, repo)


# --- Go rules -----------------------------------------------------------


def test_changed_go_test_file_selects_itself(repo: Path) -> None:
    s = sel(["pkg/foo/foo_test.go"], repo)
    assert s.go_tests == ["pkg/foo/foo_test.go"]
    assert s.all_go is False


def test_changed_go_source_maps_to_package_tests(repo: Path) -> None:
    s = sel(["pkg/foo/foo.go"], repo)
    assert s.go_tests == ["pkg/foo/foo_test.go"]
    assert s.all_go is False


def test_changed_go_source_without_tests_contributes_nothing(repo: Path) -> None:
    s = sel(["pkg/bar/bar.go"], repo)
    assert s.go_tests == []
    assert s.all_go is False
    assert s.reasons["pkg/bar/bar.go"] == "no tests in package"


def test_go_build_file_selects_all_go_tests(repo: Path) -> None:
    for f in ("go.mod", "go.sum", "go.work"):
        s = sel([f], repo)
        assert s.all_go is True, f
        assert s.all_python is False, f


def test_cmd_package_without_tests_contributes_nothing(repo: Path) -> None:
    s = sel(["cmd/app/main.go"], repo)
    assert s.go_tests == []
    assert s.reasons["cmd/app/main.go"] == "no tests in package"


# --- Python rules -------------------------------------------------------


def test_changed_py_test_file_selects_itself(repo: Path) -> None:
    s = sel(["agent/tests/test_other.py"], repo)
    assert s.python_tests == ["agent/tests/test_other.py"]
    assert s.all_python is False


def test_changed_module_maps_to_named_test(repo: Path) -> None:
    s = sel(["agent/demo/moo.py"], repo)
    assert s.python_tests == ["agent/tests/test_moo.py"]


def test_changed_module_without_named_test_falls_back_to_dir(repo: Path) -> None:
    s = sel(["agent/demo/utils.py"], repo)
    assert s.python_tests == [
        "agent/tests/test_moo.py",
        "agent/tests/test_other.py",
    ]


def test_changed_test_helper_affects_whole_tests_dir(repo: Path) -> None:
    s = sel(["agent/tests/util_helper.py"], repo)
    assert s.python_tests == [
        "agent/tests/test_moo.py",
        "agent/tests/test_other.py",
    ]


def test_py_build_files_select_all_python_tests(repo: Path) -> None:
    for f in ("pyproject.toml", "requirements.txt"):
        s = sel([f], repo)
        assert s.all_python is True, f
        assert s.all_go is False, f


def test_makefile_change_selects_all_stacks(repo: Path) -> None:
    s = sel(["Makefile"], repo)
    assert s.all_python is True
    assert s.all_go is True


# --- Negatives / misc ---------------------------------------------------


def test_docs_change_selects_nothing(repo: Path) -> None:
    s = sel(["docs/notes.md"], repo)
    assert s.test_files() == []
    assert s.all_go is False
    assert s.all_python is False
    assert s.reasons["docs/notes.md"] == "no test mapping (ignored)"


def test_unrelated_package_change_has_no_false_positives(repo: Path) -> None:
    s = sel(["pkg/bar/bar.go"], repo)
    assert "pkg/foo/foo_test.go" not in s.go_tests
    assert s.test_files() == []


def test_mixed_change_is_sorted_deduped_union(repo: Path) -> None:
    s = sel(
        [
            "pkg/foo/foo.go",
            "pkg/foo/foo_test.go",
            "agent/demo/moo.py",
            "agent/demo/moo.py",  # duplicate
            "docs/notes.md",
        ],
        repo,
    )
    assert s.go_tests == ["pkg/foo/foo_test.go"]
    assert s.python_tests == ["agent/tests/test_moo.py"]
    assert s.test_files() == ["agent/tests/test_moo.py", "pkg/foo/foo_test.go"]


def test_repo_wide_path_selects_all(repo: Path) -> None:
    s = sel(["."], repo)
    assert s.all_go is True
    assert s.all_python is True


def test_top_level_module_without_tests_dir_contributes_nothing(repo: Path) -> None:
    s = sel(["top.py"], repo)
    assert s.python_tests == []
    assert s.reasons["top.py"] == "no tests dir for module"


def test_to_dict_round_trip(repo: Path) -> None:
    s = sel(["go.mod", "agent/demo/moo.py"], repo)
    d = s.to_dict()
    assert d["all_go"] is True
    assert d["python_tests"] == ["agent/tests/test_moo.py"]
    reasons = d["reasons"]
    assert isinstance(reasons, dict)
    assert str(reasons["go.mod"]).startswith("go build config")
    assert json.dumps(d)  # must be JSON-serializable


def test_empty_input_selects_nothing(repo: Path) -> None:
    s = sel([], repo)
    assert s.test_files() == []
    assert not s.all_go and not s.all_python


def test_backslash_paths_are_normalized(repo: Path) -> None:
    s = sel(["pkg\\foo\\foo.go"], repo)
    assert s.go_tests == ["pkg/foo/foo_test.go"]
