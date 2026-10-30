"""Offline tests for flowstallion_agent.repocheck (real local git + fake transport).

The "GitHub" side (PR head sha lookup) is faked via an injectable transport;
the git side is the real git against a local bare repo, so the fetch/checkout
mechanics are exercised end-to-end without network access.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from flowstallion_agent import repocheck

REPO_URL = "https://github.com/octo/widget"


def _git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, env=env
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {args} failed: {proc.stderr.strip()}")
    return proc.stdout


def make_local_remote(base: Path) -> str:
    """Work tree + bare remote at <base>/octo/widget.git; returns head sha."""
    work = base / "work"
    work.mkdir()
    (work / "tests").mkdir()
    (work / "probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    (work / "tests" / "test_probe.py").write_text(
        "import probe\n\n\ndef test_value():\n    assert probe.VALUE == 1\n",
        encoding="utf-8",
    )
    _git(work, "init", "-q")
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "init")
    sha = _git(work, "rev-parse", "HEAD").strip()
    (base / "octo").mkdir()
    _git(work, "clone", "-q", "--bare", str(work), str(base / "octo" / "widget.git"))
    return sha


class FakePRTransport:
    """PR-metadata GET: fixed status, head.sha in the 200 payload."""

    def __init__(self, sha: str = "", status: int = 200) -> None:
        self.sha = sha
        self.status = status
        self.calls: list[str] = []

    def get(
        self, url: str, headers: dict[str, str], timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        self.calls.append(url)
        if self.status != 200:
            return self.status, {}, b'{"message": "Not Found"}'
        return 200, {}, json.dumps({"head": {"sha": self.sha}}).encode("utf-8")


def make_git_spy(tmp_path: Path) -> tuple[Path, Path]:
    """git wrapper that logs argv then forwards to the real git binary."""
    real = shutil.which("git")
    assert real is not None, "git not available on host"
    wrapper = tmp_path / "git-spy"
    log = tmp_path / "git-calls.log"
    wrapper.write_text(
        "#!/usr/bin/env python3\n"
        "import os, subprocess, sys\n"
        f"REAL = {real!r}\n"
        "log = os.environ.get('GITSPIE_LOG', '')\n"
        "if log:\n"
        "    with open(log, 'a') as f:\n"
        "        f.write(' '.join(sys.argv[1:]) + chr(10))\n"
        "sys.exit(subprocess.run([REAL] + sys.argv[1:]).returncode)\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return wrapper, log


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Local bare remote + git spy + env pointed at them."""
    base = tmp_path / "remotes"
    base.mkdir()
    sha = make_local_remote(base)
    wrapper, log = make_git_spy(tmp_path)
    monkeypatch.setenv("GITSPIE_LOG", str(log))
    monkeypatch.setenv(repocheck.ENV_GIT_BIN, str(wrapper))
    monkeypatch.setenv(repocheck.ENV_GIT_CLONE_BASE, str(base))
    monkeypatch.setenv(repocheck.ENV_GIT_PR_REF, "HEAD")
    return {"base": str(base), "sha": sha, "log": str(log)}


# --- build_clone_url ----------------------------------------------------------------


def test_build_clone_url_https_no_token() -> None:
    assert (
        repocheck.build_clone_url("https://github.com", "octo", "widget")
        == "https://github.com/octo/widget.git"
    )


def test_build_clone_url_token_embedded() -> None:
    assert (
        repocheck.build_clone_url("https://github.com", "octo", "widget", token="tok")
        == "https://x-access-token:tok@github.com/octo/widget.git"
    )


def test_build_clone_url_local_base_no_token() -> None:
    # File/local remotes must stay bare even with a token present.
    assert (
        repocheck.build_clone_url("/tmp/remotes", "octo", "widget", token="tok")
        == "/tmp/remotes/octo/widget.git"
    )
    assert repocheck.build_clone_url("https://github.com/", "octo", "widget") == (
        "https://github.com/octo/widget.git"
    )


# --- _parse_repo_url (strict shape) -------------------------------------------------


def test_parse_repo_url_accepts_plain_url() -> None:
    assert repocheck._parse_repo_url("https://github.com/octo/widget") == (
        "octo",
        "widget",
    )


def test_parse_repo_url_accepts_dot_git_suffix() -> None:
    assert repocheck._parse_repo_url("https://github.com/octo/widget.git") == (
        "octo",
        "widget",
    )


def test_parse_repo_url_accepts_query_and_fragment() -> None:
    assert repocheck._parse_repo_url("https://github.com/octo/widget?x=1") == (
        "octo",
        "widget",
    )
    assert repocheck._parse_repo_url("https://github.com/octo/widget#f") == (
        "octo",
        "widget",
    )


def test_parse_repo_url_rejects_extra_path_segments() -> None:
    # owner/repo/extra is not a GitHub repo URL; must not degrade into
    # silently cloning "a/b" (pin the rejection, not the truncation).
    assert repocheck._parse_repo_url("https://github.com/a/b/c") is None


def test_parse_repo_url_rejects_non_github_schemes() -> None:
    assert repocheck._parse_repo_url("git+ssh://git@github.com/octo/widget") is None
    assert repocheck._parse_repo_url("https://gitlab.com/octo/widget") is None
    assert repocheck._parse_repo_url("https://github.com/octo") is None
    assert repocheck._parse_repo_url("") is None


# --- resolve_pr_checkout ------------------------------------------------------------


def test_resolve_happy_path_creates_cache_entry(tmp_path: Path, env: dict[str, str]) -> None:
    cache = tmp_path / "cache"
    t = FakePRTransport(sha=env["sha"])
    result = repocheck.resolve_pr_checkout(
        REPO_URL,
        42,
        token="tok",
        api_base="http://fake",
        transport=t,
        cache_dir=str(cache),
    )
    assert result == str(cache / env["sha"])
    assert (Path(result) / "probe.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert (Path(result) / "tests" / "test_probe.py").is_file()
    assert t.calls == [f"http://fake/repos/octo/widget/pulls/42"]
    calls = Path(env["log"]).read_text(encoding="utf-8").splitlines()
    assert any(line.startswith("fetch ") for line in calls)
    assert any(line.startswith("checkout ") for line in calls)
    # The embedded PAT must not persist into the cached entry's .git/config.
    git_config = (Path(result) / ".git" / "config").read_text(encoding="utf-8")
    assert "x-access-token" not in git_config


def test_resolve_cache_hit_skips_git(tmp_path: Path, env: dict[str, str]) -> None:
    cache = tmp_path / "cache"
    t = FakePRTransport(sha=env["sha"])
    repocheck.resolve_pr_checkout(
        REPO_URL, 42, transport=t, cache_dir=str(cache)
    )
    fetches = sum(
        l.startswith("fetch ") for l in Path(env["log"]).read_text().splitlines()
    )
    assert fetches == 1
    t2 = FakePRTransport(sha=env["sha"])
    result = repocheck.resolve_pr_checkout(
        REPO_URL, 42, transport=t2, cache_dir=str(cache)
    )
    assert result == str(cache / env["sha"])
    fetches2 = sum(
        l.startswith("fetch ") for l in Path(env["log"]).read_text().splitlines()
    )
    assert fetches2 == 1  # cache hit: no second fetch


def test_resolve_bad_sha_degrades_to_none_and_cleans_up(
    tmp_path: Path, env: dict[str, str]
) -> None:
    cache = tmp_path / "cache"
    bad = "0" * 40  # sha not present in the remote
    t = FakePRTransport(sha=bad)
    # Fetch the sha itself: the local remote rejects it ("not our ref"),
    # mirroring what an unknown ref does on any origin.
    assert (
        repocheck.resolve_pr_checkout(
            REPO_URL,
            42,
            transport=t,
            cache_dir=str(cache),
            ref_spec=bad,
        )
        is None
    )
    entries = [p for p in cache.iterdir()] if cache.exists() else []
    assert not any(p.name.startswith(".inprogress-") for p in entries)
    assert not (cache / ("0" * 40)).exists()


def test_resolve_http_404_returns_none_without_cache(
    tmp_path: Path, env: dict[str, str]
) -> None:
    cache = tmp_path / "cache"
    t = FakePRTransport(sha=env["sha"], status=404)
    assert (
        repocheck.resolve_pr_checkout(REPO_URL, 42, transport=t, cache_dir=str(cache))
        is None
    )
    assert not cache.exists()  # cache dir only created after a successful sha fetch


def test_resolve_unsupported_url_returns_none_without_transport_calls(
    tmp_path: Path, env: dict[str, str]
) -> None:
    t = FakePRTransport(sha=env["sha"])
    assert (
        repocheck.resolve_pr_checkout(
            "https://gitlab.com/octo/widget", 42, transport=t, cache_dir=str(tmp_path / "c")
        )
        is None
    )
    assert t.calls == []


def test_resolve_pr_number_zero_returns_none(tmp_path: Path, env: dict[str, str]) -> None:
    t = FakePRTransport(sha=env["sha"])
    assert (
        repocheck.resolve_pr_checkout(REPO_URL, 0, transport=t, cache_dir=str(tmp_path))
        is None
    )
    assert t.calls == []


def test_resolve_missing_git_binary_returns_none(
    tmp_path: Path, env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(repocheck.ENV_GIT_BIN, "/nonexistent/git-bin-xyz")
    t = FakePRTransport(sha=env["sha"])
    assert (
        repocheck.resolve_pr_checkout(
            REPO_URL, 42, transport=t, cache_dir=str(tmp_path / "cache")
        )
        is None
    )


def test_resolve_prune_keeps_newest(
    tmp_path: Path, env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    now = 1_700_000_000.0
    old_names = []
    for i in range(16):
        name = f"{i:040x}"
        d = cache / name
        d.mkdir()
        (d / "marker").write_text(name, encoding="utf-8")
        mtime = now + i  # strictly increasing mtime
        os.utime(d, (mtime, mtime))
        old_names.append(name)
    t = FakePRTransport(sha=env["sha"])
    result = repocheck.resolve_pr_checkout(
        REPO_URL, 42, transport=t, cache_dir=str(cache), max_cached=16
    )
    assert result is not None
    dirs = sorted(p.name for p in cache.iterdir() if p.is_dir())
    assert len(dirs) == 16  # 16 pre-existing + 1 new, oldest pruned
    assert old_names[0] not in dirs  # the oldest (mtime now+0) was pruned
    assert old_names[1] in dirs
    assert env["sha"] in dirs


def test_resolve_no_prune_when_under_limit(
    tmp_path: Path, env: dict[str, str]
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    for i in range(3):
        (cache / f"{i:040x}").mkdir()
    t = FakePRTransport(sha=env["sha"])
    repocheck.resolve_pr_checkout(
        REPO_URL, 42, transport=t, cache_dir=str(cache), max_cached=16
    )
    assert len([p for p in cache.iterdir() if p.is_dir()]) == 4


def test_resolve_malicious_sha_rejected_no_rmtree(
    tmp_path: Path, env: dict[str, str]
) -> None:
    # head.sha comes from an external API payload. A value like ".." must be
    # rejected before it can name a cache subdirectory, otherwise
    # ``cache / ".."`` + rmtree would destroy the cache parent dir.
    marker_parent = tmp_path / "outside"
    marker_parent.mkdir()
    (marker_parent / "keep.txt").write_text("keep", encoding="utf-8")
    cache = marker_parent / "cache"
    for bad in ["..", "../evil", "evilsha", "abc", ""]:
        t = FakePRTransport(sha=bad)
        assert (
            repocheck.resolve_pr_checkout(
                REPO_URL, 42, transport=t, cache_dir=str(cache)
            )
            is None
        )
    assert not cache.exists()  # rejected before the cache dir is created
    assert (marker_parent / "keep.txt").exists()


def test_resolve_stale_inprogress_swept(
    tmp_path: Path, env: dict[str, str]
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    now = time.time()
    stale = cache / ".inprogress-deadbeef-999"
    stale.mkdir()
    os.utime(stale, (now - 3600, now - 3600))
    fresh = cache / ".inprogress-cafebabe-998"
    fresh.mkdir()  # mtime ~ now, must survive the sweep
    t = FakePRTransport(sha=env["sha"])
    result = repocheck.resolve_pr_checkout(
        REPO_URL, 42, transport=t, cache_dir=str(cache)
    )
    assert result is not None
    assert not stale.exists()  # crash residue older than 30 min is removed
    assert fresh.exists()  # recent in-progress dirs are left alone


def test_resolve_token_not_in_stdout(
    tmp_path: Path, env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    token = "tok-secret-123"
    cache = tmp_path / "cache"
    t = FakePRTransport(sha=env["sha"])
    result = repocheck.resolve_pr_checkout(
        REPO_URL,
        42,
        token=token,
        api_base="http://fake",
        transport=t,
        cache_dir=str(cache),
    )
    assert result is not None
    assert token not in capsys.readouterr().out
