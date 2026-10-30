"""On-demand PR-head checkout for real-repo smart test selection.

The test-selection mapper (``testselect``) needs the PR's own file tree:
mapping changed files against the agent's own checkout is meaningless for
foreign repos. This module resolves a PR's head commit to a local
directory on demand:

1. ``GET /repos/{owner}/{repo}/pulls/{n}`` (JSON) -> ``head.sha``;
2. shallow-fetch the PR head ref (``pull/{n}/head`` by default) into a
   scratch directory under the cache;
3. atomically move it to ``{cache}/{sha}`` (the sha is the cache key, so
   re-processing the same PR head is a cache hit);
4. prune the cache to the most recent ``max_cached`` checkouts.

Pure stdlib. Every failure path (unsupported URL, HTTP error, missing git
binary, git failure, filesystem error) degrades to ``None`` so the caller
can fall back to its configured ``repo_root``. The sidecar must never
block test selection on a failed checkout.

Environment overrides (explicit kwargs win; empty kwarg falls back to
env, then to the built-in default):

- ``FLOWSTALLION_REPO_CACHE``     cache directory (default
  ``~/.cache/flowstallion/repos``);
- ``FLOWSTALLION_GIT_BIN``        git executable (default ``git``);
- ``FLOWSTALLION_GIT_CLONE_BASE`` clone URL base (default
  ``https://github.com``; tests point it at a local directory);
- ``FLOWSTALLION_GIT_PR_REF``     fetch ref template with ``{pr}`` (default
  ``pull/{pr}/head``; tests may use ``HEAD`` against a local repo).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Protocol

__all__ = [
    "ENV_REPO_CACHE",
    "ENV_GIT_BIN",
    "ENV_GIT_CLONE_BASE",
    "ENV_GIT_PR_REF",
    "DEFAULT_REPO_CACHE",
    "DEFAULT_CLONE_BASE",
    "DEFAULT_REF_SPEC",
    "DEFAULT_MAX_CACHED",
    "Transport",
    "build_clone_url",
    "resolve_pr_checkout",
]

ENV_REPO_CACHE = "FLOWSTALLION_REPO_CACHE"
ENV_GIT_BIN = "FLOWSTALLION_GIT_BIN"
ENV_GIT_CLONE_BASE = "FLOWSTALLION_GIT_CLONE_BASE"
ENV_GIT_PR_REF = "FLOWSTALLION_GIT_PR_REF"

DEFAULT_REPO_CACHE = "~/.cache/flowstallion/repos"
DEFAULT_CLONE_BASE = "https://github.com"
DEFAULT_REF_SPEC = "pull/{pr}/head"
DEFAULT_MAX_CACHED = 16

_GITHUB_URL_RE = re.compile(r"^https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+)")
_OWNER_REPO_RE = re.compile(r"[A-Za-z0-9._-]+")
# External (GitHub API) sha before it names a cache subdirectory: hex only,
# so ``cache / sha`` can never escape the cache root ("..", absolute, NUL).
_SHA_RE = re.compile(r"[0-9a-fA-F]{7,64}")


class Transport(Protocol):
    """GET-only HTTP surface (structurally satisfied by aiwire transports)."""

    def get(
        self, url: str, headers: dict[str, str], timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        ...


class _UrllibTransport:
    """Default stdlib transport; returns (status, headers, body) for any HTTP
    status (non-2xx is the caller's decision, matching aiwire's protocol)."""

    def get(
        self, url: str, headers: dict[str, str], timeout_s: float
    ) -> tuple[int, dict[str, str], bytes]:
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                hdrs = {k: v for k, v in resp.headers.items() if v is not None}
                return resp.status, hdrs, resp.read()
        except urllib.error.HTTPError as exc:
            err_hdrs: dict[str, str] = {}
            if exc.headers is not None:
                err_hdrs = {k: v for k, v in exc.headers.items() if v is not None}
            return exc.code, err_hdrs, exc.read()
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower():
                raise TimeoutError(f"GitHub request to {url} timed out") from exc
            raise OSError(f"GitHub network error: {reason!r}") from exc


def _parse_repo_url(url: str) -> Optional[tuple[str, str]]:
    """``https://github.com/{owner}/{repo}`` -> ``(owner, repo)`` or None.

    Strict shape check: only a bare repo URL (optional ``.git`` suffix or
    query/fragment) is accepted; anything else (extra path segments,
    git+ssh, etc.) returns None so it can never reach the clone URL builder.
    """
    m = _GITHUB_URL_RE.match((url or "").strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    # Strict: nothing may follow the repo name except a query/fragment.
    rest = (url or "").strip()[m.end(2):]
    if rest and not rest.startswith((".", "?", "#")):
        return None
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if not _OWNER_REPO_RE.fullmatch(owner) or not _OWNER_REPO_RE.fullmatch(repo):
        return None
    return owner, repo


def _fetch_pr_head_sha(
    owner: str,
    repo: str,
    pr_number: int,
    *,
    token: str,
    api_base: str,
    transport: Transport,
    timeout_s: float,
) -> Optional[str]:
    """PR JSON -> ``head.sha``; None on any fetch/parse failure."""
    base = (
        api_base
        or os.environ.get("FLOWSTALLION_GITHUB_API", "")
        or "https://api.github.com"
    ).strip()
    base = base.rstrip("/") or "https://api.github.com"
    url = f"{base}/repos/{owner}/{repo}/pulls/{pr_number}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "flowstallion-agent"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        status, _hdrs, body = transport.get(url, headers, timeout_s)
    except (OSError, TimeoutError) as exc:
        print(f"[repocheck] PR fetch failed {url}: {exc}")
        return None
    if status != 200:
        print(f"[repocheck] PR fetch failed {url}: HTTP {status}")
        return None
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        print(f"[repocheck] PR fetch: bad JSON from {url}: {exc}")
        return None
    head = data.get("head") if isinstance(data, dict) else None
    sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
        print(f"[repocheck] PR fetch: invalid head.sha in payload for {url}")
        return None
    return sha


def _run_git(cwd: Path, git_bin: str, args: list[str], timeout_s: float) -> None:
    """Run one git command in ``cwd``; raise RuntimeError on non-zero exit."""
    proc = subprocess.run(
        [git_bin, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(
            f"git {' '.join(args[:2])} failed (exit {proc.returncode}): {detail[:300]}"
        )


def _prune_cache(cache: Path, max_cached: int) -> None:
    """Keep the ``max_cached`` newest checkout dirs; never raise."""
    if max_cached <= 0:
        return
    dirs = [d for d in cache.iterdir() if d.is_dir() and not d.name.startswith(".")]
    if len(dirs) <= max_cached:
        return
    dirs.sort(key=lambda d: d.stat().st_mtime)
    for old in dirs[: len(dirs) - max_cached]:
        shutil.rmtree(old, ignore_errors=True)


def _sweep_stale_inprogress(cache: Path, older_than_s: float = 1800.0) -> None:
    """Remove crashed ``.inprogress-*`` scratch dirs.

    A scratch dir left behind by a crash would otherwise accumulate in the
    cache (prune skips dot-dirs). Only dirs whose mtime is older than the
    threshold are removed, so live in-progress checkouts are never touched.
    """
    try:
        entries = list(cache.iterdir())
    except OSError:
        return
    now = time.time()
    for d in entries:
        try:
            if (
                d.is_dir()
                and d.name.startswith(".inprogress-")
                and now - d.stat().st_mtime > older_than_s
            ):
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


def build_clone_url(clone_base: str, owner: str, repo: str, *, token: str = "") -> str:
    """Clone URL for the PR head fetch.

    ``clone_base`` defaults to ``https://github.com`` but may be any base
    (tests point it at a local directory). A PAT is only embedded into
    ``https://`` remotes; file/local remotes are left bare.
    """
    url = f"{clone_base.rstrip('/')}/{owner}/{repo}.git"
    if token and clone_base.strip().startswith("https://"):
        url = url.replace("https://", f"https://x-access-token:{token}@", 1)
    return url


def resolve_pr_checkout(
    repo_url: str,
    pr_number: int,
    *,
    token: str = "",
    api_base: str = "",
    transport: Optional[Transport] = None,
    cache_dir: str = "",
    git_bin: str = "",
    clone_base: str = "",
    ref_spec: str = "",
    fetch_timeout_s: float = 60.0,
    git_timeout_s: float = 300.0,
    max_cached: int = DEFAULT_MAX_CACHED,
) -> Optional[str]:
    """Resolve a PR head to a local checkout path; ``None`` on any failure.

    ``cache_dir``/``git_bin``/``clone_base``/``ref_spec``: explicit value
    wins, else the matching env var, else the built-in default. The
    returned path is the cache entry ``{cache}/{sha}`` itself (a full
    detached checkout of the PR head commit).

    ``git_timeout_s`` is the *total* time budget shared by all git calls in
    this resolve (init/remote/fetch/checkout), not a per-call timeout, so a
    single hung git call cannot stall the watch loop for minutes on its own.
    """
    if pr_number <= 0:
        return None
    pair = _parse_repo_url(repo_url)
    if pair is None:
        print(f"[repocheck] unsupported repo URL: {repo_url!r}")
        return None
    owner, repo = pair

    do_get: Transport = transport if transport is not None else _UrllibTransport()
    sha = _fetch_pr_head_sha(
        owner,
        repo,
        pr_number,
        token=token,
        api_base=api_base,
        transport=do_get,
        timeout_s=fetch_timeout_s,
    )
    if sha is None:
        return None

    git_bin = (
        git_bin
        or os.environ.get(ENV_GIT_BIN, "").strip()
        or "git"
    )
    clone_base = (
        clone_base
        or os.environ.get(ENV_GIT_CLONE_BASE, "").strip()
        or DEFAULT_CLONE_BASE
    ).rstrip("/")
    ref_spec = ref_spec or os.environ.get(ENV_GIT_PR_REF, "").strip() or DEFAULT_REF_SPEC

    cache = Path(cache_dir or os.environ.get(ENV_REPO_CACHE, "") or DEFAULT_REPO_CACHE)
    cache = cache.expanduser()
    try:
        cache.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"[repocheck] cannot create cache dir {cache}: {exc}")
        return None
    _sweep_stale_inprogress(cache)

    # ``sha`` came from an external API payload before it names a cache
    # subdirectory: the hex validation in ``_fetch_pr_head_sha`` plus this
    # containment check keep ``cache / sha`` from escaping the cache root.
    target = cache / sha
    try:
        target_resolved = target.resolve()
        cache_resolved = cache.resolve()
    except OSError as exc:
        print(f"[repocheck] cannot resolve cache path {cache}: {exc}")
        return None
    if cache_resolved != target_resolved and cache_resolved not in target_resolved.parents:
        print(f"[repocheck] refusing cache target outside cache root: {target}")
        return None
    if (target / ".git").is_dir():
        print(f"[repocheck] cache hit {target}")
        return str(target)

    clone_url = build_clone_url(clone_base, owner, repo, token=token)

    tmp = cache / f".inprogress-{sha}-{os.getpid()}"
    deadline = time.monotonic() + git_timeout_s
    try:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir()

        def _budget() -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                raise RuntimeError("git time budget exhausted")
            return left

        _run_git(tmp, git_bin, ["init", "-q"], _budget())
        _run_git(tmp, git_bin, ["remote", "add", "origin", clone_url], _budget())
        _run_git(
            tmp,
            git_bin,
            ["fetch", "--depth", "1", "-q", "origin", ref_spec.format(pr=pr_number)],
            _budget(),
        )
        _run_git(tmp, git_bin, ["checkout", "-q", "FETCH_HEAD"], _budget())
        # Strip the embedded PAT from the persisted cache entry so the token
        # does not rest on the cache volume inside .git/config.
        _run_git(tmp, git_bin, ["remote", "remove", "origin"], _budget())
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        os.replace(tmp, target)
        print(
            f"[repocheck] checked out {owner}/{repo} PR #{pr_number} "
            f"head {sha[:12]} -> {target}"
        )
        _prune_cache(cache, max_cached)
        return str(target)
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        print(f"[repocheck] checkout failed for {owner}/{repo} PR #{pr_number}: {exc}")
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
        return None
