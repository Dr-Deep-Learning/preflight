"""Ingestion: mode A-local.

The spec describes three ingestion modes (repo connect, backend connect, URL
probe). This week only one exists: a local directory the operator already owns.
That is deliberate -- the guardrail in spec section 6 says never point this at
infrastructure you do not control, and a local path is the only mode where that
is true by construction.

`FileIndex` is the seam. Every rule reads the project through it, so adding a
GitHub-clone or tarball source later means implementing one more `SourceLoader`
and changing nothing in the rules.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Protocol

import pathspec

SKIP_DIRS = frozenset(
    {
        ".git",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".turbo",
        ".vercel",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "out",
        "target",
        "venv",
        "vendor",
    }
)

# Extensions worth reading as text. Anything else is skipped rather than sniffed:
# a scanner that opens arbitrary binaries on a stranger's machine is a liability.
TEXT_SUFFIXES = frozenset(
    {
        "",
        ".astro",
        ".cjs",
        ".config",
        ".css",
        ".env",
        ".example",
        ".graphql",
        ".html",
        ".ini",
        ".js",
        ".json",
        ".jsx",
        ".local",
        ".lock",
        ".md",
        ".mjs",
        ".mts",
        ".php",
        ".prisma",
        ".py",
        ".rb",
        ".rules",
        ".sh",
        ".sql",
        ".svelte",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".vue",
        ".yaml",
        ".yml",
    }
)

MAX_FILE_BYTES = 1_000_000

_BRACE_GROUP = re.compile(r"\{([^{}]*)\}")


def expand_braces(pattern: str) -> list[str]:
    """Expand shell-style alternation in a glob.

    `pathlib` and `pathspec` both understand `*` and `**`; neither understands
    `{a,b}`, and a pattern containing it silently matches nothing. Since the
    defect catalog is written with alternation -- `**/*.{js,jsx,ts,tsx}` is the
    natural way to say it -- expanding here is cheaper than forbidding it and
    writing four patterns everywhere.

    >>> expand_braces("app/**/*.{js,ts}")
    ['app/**/*.js', 'app/**/*.ts']
    >>> expand_braces("**/*.sql")
    ['**/*.sql']
    """
    match = _BRACE_GROUP.search(pattern)
    if match is None:
        return [pattern]
    head, tail = pattern[: match.start()], pattern[match.end() :]
    expanded: list[str] = []
    for option in match.group(1).split(","):
        expanded.extend(expand_braces(f"{head}{option.strip()}{tail}"))
    return expanded


class ScanTargetError(ValueError):
    """The requested target is missing, or outside the roots we are allowed to read."""


@dataclass
class GitInfo:
    """What git can tell us about the project.

    This matters for F2. "There is a .env on disk" is weak. "There is a .env and
    git is tracking it" is a confirmed finding, because the secret is in history
    and on every clone. Where git is unavailable we downgrade rather than guess.
    """

    is_repo: bool = False
    tracked: frozenset[str] = frozenset()

    def is_tracked(self, relpath: str) -> bool | None:
        """True / False when git answered, None when we could not tell."""
        if not self.is_repo:
            return None
        return relpath in self.tracked


def read_git_info(root: Path) -> GitInfo:
    """Ask git what it is tracking under `root`.

    `git -C <root> ls-files` returns paths relative to `root` and works when the
    target is a subdirectory of a repository, which is the common case: people
    scan `apps/web`, not the repository root. Checking for a `.git` directory
    would miss that.
    """
    if not _git_says_yes(root, "rev-parse", "--is-inside-work-tree"):
        return GitInfo()
    output = _git_output(root, "ls-files", "-z")
    if output is None:
        return GitInfo()
    names = output.split("\0")
    return GitInfo(is_repo=True, tracked=frozenset(n for n in names if n))


def _git_output(root: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace")


def _git_says_yes(root: Path, *args: str) -> bool:
    output = _git_output(root, *args)
    return output is not None and output.strip() == "true"


@dataclass
class FileIndex:
    """An immutable, cached view of the project's text files.

    Paths are POSIX-relative strings everywhere above this class, so that reports
    and test assertions are identical on Windows and Linux.
    """

    root: Path
    paths: tuple[str, ...]
    _cache: dict[str, str] = field(default_factory=dict, repr=False)

    def read_text(self, relpath: str) -> str:
        cached = self._cache.get(relpath)
        if cached is None:
            try:
                cached = (self.root / relpath).read_text(encoding="utf-8", errors="replace")
            except OSError:
                cached = ""
            self._cache[relpath] = cached
        return cached

    def with_suffix(self, *suffixes: str) -> tuple[str, ...]:
        wanted = {s.lower() for s in suffixes}
        return tuple(p for p in self.paths if PurePosixPath(p).suffix.lower() in wanted)

    def named(self, *names: str) -> tuple[str, ...]:
        wanted = {n.lower() for n in names}
        return tuple(p for p in self.paths if PurePosixPath(p).name.lower() in wanted)

    def matching(self, *globs: str) -> tuple[str, ...]:
        """Paths matching any of these globs, using gitignore semantics.

        Not `PurePath.match`, which treats a mid-pattern `**` as a single `*` --
        so `supabase/migrations/**/*.sql` matched nothing at all. gitignore
        semantics are what anyone writing these patterns already expects, and
        `pathspec` implements them: a pattern containing a slash is anchored to
        the project root, one without it matches at any depth.
        """
        patterns: list[str] = []
        for glob in globs:
            patterns.extend(expand_braces(glob))
        spec = pathspec.PathSpec.from_lines("gitignore", patterns)
        return tuple(p for p in self.paths if spec.match_file(p))

    def exists(self, relpath: str) -> bool:
        return relpath in set(self.paths)


class SourceLoader(Protocol):
    """The ingestion seam. Mode B (backend connect) and Mode C (URL probe) will
    each be a different implementation of a sibling protocol, not a branch here."""

    def load(self) -> tuple[Path, FileIndex, GitInfo]: ...


@dataclass
class LocalDirectorySource:
    """Mode A: a directory on this machine that the operator owns."""

    root: Path

    def load(self) -> tuple[Path, FileIndex, GitInfo]:
        root = self.root.resolve()
        if not root.is_dir():
            raise ScanTargetError(f"not a directory: {root}")
        return root, FileIndex(root=root, paths=tuple(_walk(root))), read_git_info(root)


def _walk(root: Path) -> list[str]:
    found: list[str] = []
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    stack.append(entry)
                continue
            if not entry.is_file():
                continue
            if entry.suffix.lower() not in TEXT_SUFFIXES and not entry.name.startswith(".env"):
                continue
            try:
                if entry.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            found.append(entry.relative_to(root).as_posix())
    return sorted(found)


def resolve_target(raw: str | Path, allowed_roots: list[Path] | None = None) -> Path:
    """Resolve a scan target, enforcing the ownership guardrail.

    The service passes `allowed_roots` from configuration. This is the code-level
    expression of spec section 6: the scanner must not be pointable at arbitrary
    paths just because someone can reach the API.
    """
    target = Path(raw).expanduser().resolve()
    if not target.is_dir():
        raise ScanTargetError(f"not a directory: {target}")
    if allowed_roots:
        roots = [r.expanduser().resolve() for r in allowed_roots]
        if not any(target == r or r in target.parents for r in roots):
            raise ScanTargetError(
                f"{target} is outside the allowed scan roots ({', '.join(str(r) for r in roots)})"
            )
    return target
