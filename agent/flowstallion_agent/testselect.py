"""Smart test selection v1 (rule-based): changed files -> affected tests.

Given a set of changed file paths (repo-relative), compute the minimal set
of tests that should run. This is a glue/data-processing module and lives
in the Python agent stack; it is repo-agnostic (pattern/directory rules)
and has no LLM involvement (LLM-based enhancement is a later phase).

Rules (v1):

Go:
- a changed ``*_test.go`` file is itself an affected test;
- a changed non-test ``.go`` file contributes every ``*_test.go`` in its
  package directory (0 if the package has no test files);
- a change to ``go.mod`` / ``go.sum`` / ``go.work`` affects every Go test
  (conservative, ``all_go``).

Python:
- a changed ``test_*.py`` / ``*_test.py`` file is itself an affected test;
- a changed module contributes ``<sibling tests dir>/test_<module>.py`` when
  that file exists, otherwise every test in that tests dir (conservative);
- a helper module that lives *inside* a tests dir affects every test in
  that dir;
- a change to ``pyproject.toml`` / ``Makefile`` / ``requirements*.txt``
  affects every Python test (conservative, ``all_python``); ``Makefile``
  additionally marks all Go tests since it drives both stacks here.

Files with no mapping (docs, arbitrary assets, ...) contribute nothing but
are recorded in ``reasons`` so the result stays auditable.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Sequence

__all__ = ["TestSelection", "select_tests", "main"]

_GO_BUILD_NAMES = frozenset({"go.mod", "go.sum", "go.work"})
_PY_BUILD_NAMES = frozenset({"pyproject.toml", "makefile"})
_TESTS_DIR_NAMES = frozenset({"tests", "test"})


def _is_go_test(name: str) -> bool:
    return name.endswith("_test.go")


def _is_py_test(name: str) -> bool:
    return (name.startswith("test_") or name.endswith("_test.py")) and name.endswith(".py")


@dataclass
class TestSelection:
    """Result of a selection run."""

    go_tests: list[str] = field(default_factory=list)
    python_tests: list[str] = field(default_factory=list)
    all_go: bool = False
    all_python: bool = False
    reasons: dict[str, str] = field(default_factory=dict)

    def test_files(self) -> list[str]:
        """All concrete selected test files, sorted and de-duplicated."""
        return sorted(set(self.go_tests) | set(self.python_tests))

    def to_dict(self) -> dict[str, object]:
        return {
            "go_tests": list(self.go_tests),
            "python_tests": list(self.python_tests),
            "all_go": self.all_go,
            "all_python": self.all_python,
            "reasons": dict(self.reasons),
        }


def _go_package_tests(rel: PurePosixPath, root: Path) -> list[str]:
    pkg = root / rel.parent
    out: list[str] = []
    if pkg.is_dir():
        for f in sorted(pkg.glob("*.go")):
            if _is_go_test(f.name):
                out.append(f.relative_to(root).as_posix())
    return out


def _py_tests_in_dir(tests_dir: Path, root: Path) -> list[str]:
    out: list[str] = []
    if tests_dir.is_dir():
        for f in sorted(tests_dir.glob("*.py")):
            if _is_py_test(f.name):
                out.append(f.relative_to(root).as_posix())
    return out


def _py_module_tests(rel: PurePosixPath, root: Path) -> tuple[list[str], str]:
    """Map one changed Python module to its tests.

    Returns (selected test paths, reason). The mapping is:
    module in a tests dir -> all tests in that dir;
    else sibling ``tests/`` dir: ``test_<module>.py`` if present,
    otherwise all tests in that dir;
    no tests dir at all -> no tests (recorded).
    """
    parts = list(rel.parts)
    if len(parts) >= 2 and parts[-2] in _TESTS_DIR_NAMES:
        return _py_tests_in_dir(root / rel.parent, root), "shared test helper"
    rel_tests = PurePosixPath(*parts[:-2], "tests")
    tests_dir = root / rel_tests
    if not tests_dir.is_dir():
        return [], "no tests dir for module"
    named = f"test_{rel.stem}.py"
    if (tests_dir / named).is_file():
        return [rel_tests.as_posix() + "/" + named], "named test for module"
    return _py_tests_in_dir(tests_dir, root), "no named test; whole tests dir"


def _contribute(rel: PurePosixPath, root: Path, sel: TestSelection) -> None:
    name = rel.name
    low = name.lower()
    if low in _GO_BUILD_NAMES:
        sel.all_go = True
        sel.reasons[str(rel)] = "go build config: all go tests"
        return
    if low in _PY_BUILD_NAMES or low.startswith("requirements") and low.endswith(".txt"):
        sel.all_python = True
        sel.reasons[str(rel)] = "python build config: all python tests"
        if low == "makefile":
            sel.all_go = True
            sel.reasons[str(rel)] += "; makefile also drives go: all go tests"
        return
    if _is_go_test(name):
        sel.go_tests.append(str(rel))
        sel.reasons[str(rel)] = "changed go test file"
        return
    if _is_py_test(name):
        sel.python_tests.append(str(rel))
        sel.reasons[str(rel)] = "changed python test file"
        return
    if name.endswith(".go"):
        found = _go_package_tests(rel, root)
        if found:
            sel.go_tests.extend(found)
            sel.reasons[str(rel)] = f"package tests: {', '.join(found)}"
        else:
            sel.reasons[str(rel)] = "no tests in package"
        return
    if name.endswith(".py"):
        found, reason = _py_module_tests(rel, root)
        sel.python_tests.extend(found)
        sel.reasons[str(rel)] = reason
        return
    sel.reasons[str(rel)] = "no test mapping (ignored)"


def select_tests(changed: Sequence[str], repo_root: str | Path = ".") -> TestSelection:
    """Compute the affected test set for ``changed`` repo-relative paths.

    ``changed`` entries must be POSIX-style paths relative to ``repo_root``
    (e.g. what ``git diff --name-only`` prints). The selection is
    deterministic and de-duplicated.
    """
    root = Path(repo_root)
    sel = TestSelection()
    for raw in changed:
        s = str(raw).strip().replace("\\", "/")
        # Repo-wide sentinels (PurePosixPath('.') collapses to no parts).
        if s in (".", "./", "..", "../", "/"):
            sel.all_go = True
            sel.all_python = True
            sel.reasons["." if s in (".", "./") else s] = "repo-wide path: all tests"
            continue
        rel = PurePosixPath(s)
        if not rel.parts:
            continue
        _contribute(rel, root, sel)
    sel.go_tests = sorted(set(sel.go_tests))
    sel.python_tests = sorted(set(sel.python_tests))
    return sel


def _files_from_diff(diff_range: str, repo: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", repo, "diff", "--name-only", diff_range],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m flowstallion_agent.testselect",
        description="Rule-based smart test selection: changed files -> affected tests.",
    )
    parser.add_argument("files", nargs="*", help="changed files (repo-relative paths)")
    parser.add_argument(
        "--diff",
        metavar="RANGE",
        help="git diff range (e.g. HEAD~1..HEAD); files are read from `git diff --name-only RANGE`",
    )
    parser.add_argument("--repo", default=".", help="repo root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    files: list[str] = list(args.files)
    if args.diff:
        files.extend(_files_from_diff(args.diff, args.repo))
    sel = select_tests(files, args.repo)

    if args.json:
        print(json.dumps(sel.to_dict(), indent=2))
    else:
        print(f"Go tests: {'ALL' if sel.all_go else len(sel.go_tests)}")
        for t in sel.go_tests:
            print(f"  {t}")
        print(f"Python tests: {'ALL' if sel.all_python else len(sel.python_tests)}")
        for t in sel.python_tests:
            print(f"  {t}")
        for f, why in sorted(sel.reasons.items()):
            print(f"  - {f}: {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
