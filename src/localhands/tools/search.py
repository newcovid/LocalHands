"""Filesystem search and listing tools."""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.types import Tool

from ..security import PathGuardError
from .base import (
    MAX_GLOB_RESULTS,
    MAX_GREP_RESULTS,
    MAX_TREE_ENTRIES,
    LocalProvider,
    err,
    ok,
)
from .encryption import head_is_encrypted, parse_markers, staging_dir

logger = logging.getLogger(__name__)

# Directories that are noise in every search on this kind of project.
SKIP_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vs",
})

# Locations to try for ripgrep when it is not on PATH. Several tools vendor a
# copy, and reusing one avoids asking the user to install anything.
_RG_FALLBACKS = (
    r"%LOCALAPPDATA%\ziva\bin-deps\windows_x86_64\rg.exe",
    r"%APPDATA%\npm\node_modules\@openai\codex\node_modules\@openai"
    r"\codex-win32-x64\vendor\x86_64-pc-windows-msvc\codex-path\rg.exe",
)


def _find_ripgrep(configured: str | None) -> str | None:
    """Locate a ripgrep binary, or return None to fall back to pure Python."""
    if configured:
        expanded = os.path.expandvars(configured)
        if Path(expanded).is_file():
            return expanded
        logger.warning("Configured ripgrep_path does not exist: %s", configured)

    found = shutil.which("rg")
    if found:
        return found

    for candidate in _RG_FALLBACKS:
        expanded = os.path.expandvars(candidate)
        if Path(expanded).is_file():
            return expanded
    return None


class SearchProvider(LocalProvider):
    """Finding files by name, by content, and inspecting directory structure."""

    name = "search"

    requires_dlp = frozenset({"scan_encrypted"})

    tools: list[Tool] = [
        Tool(
            name="glob",
            description=(
                "Find files by name pattern (glob syntax: *, ?, **). Results are "
                "sorted by modification time, newest first, so the files most "
                "likely to matter appear at the top."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob pattern, e.g. '**/*.py' or '*.scl'."},
                    "path": {"type": "string", "description": "Root directory to search in. Default: first allowed path."},
                    "head_limit": {
                        "type": "integer",
                        "description": f"Maximum results to return. Default {MAX_GLOB_RESULTS}.",
                    },
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="grep",
            description=(
                "Search file contents with a regular expression.\n"
                "\n"
                "output_mode controls the shape of the result:\n"
                "  content            — matching lines (default)\n"
                "  files_with_matches — just the file paths, much cheaper\n"
                "  count              — match count per file\n"
                "\n"
                "Start with files_with_matches when exploring; switch to content "
                "once you know which files matter."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regular expression to search for."},
                    "path": {"type": "string", "description": "Root directory to search in. Default: first allowed path."},
                    "glob": {"type": "string", "description": "Filter files by name pattern, e.g. '*.py'."},
                    "output_mode": {
                        "type": "string",
                        "enum": ["content", "files_with_matches", "count"],
                        "description": "Result shape. Default 'content'.",
                        "default": "content",
                    },
                    "case_insensitive": {"type": "boolean", "description": "Ignore case. Default false.", "default": False},
                    "context_lines": {
                        "type": "integer",
                        "description": "Lines of context before and after each match. Default 0.",
                        "default": 0,
                    },
                    "head_limit": {
                        "type": "integer",
                        "description": f"Maximum results to return. Default {MAX_GREP_RESULTS}.",
                    },
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="list_directory",
            description=(
                "List a directory's contents with name, type, size, and "
                "modification time in both epoch and ISO-8601 form."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path to list."},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="get_project_tree",
            description=(
                "Render a directory structure as a text tree, up to max_depth "
                "levels. Respects .gitignore and skips build/cache directories."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Root directory. Default: first allowed path."},
                    "max_depth": {"type": "integer", "description": "Maximum depth to traverse. Default 3.", "default": 3},
                },
                "required": [],
            },
        ),
        Tool(
            name="scan_encrypted",
            description=(
                "Report which files under a directory are encrypted by the local "
                "DLP driver and therefore unreadable by this daemon.\n"
                "\n"
                "Run this before planning work over a set of documents: encrypted "
                "files cannot be read, copied into readability, or recovered by "
                "retrying, so knowing up front avoids wasting turns discovering it "
                "one file at a time."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory to scan. Default: first allowed path."},
                    "pattern": {"type": "string", "description": "Only check files matching this glob, e.g. '*.scl'."},
                    "max_files": {"type": "integer", "description": "Stop after checking this many files. Default 2000.", "default": 2000},
                },
                "required": [],
            },
        ),
    ]

    # ------------------------------------------------------------------ #
    #  Tool: glob
    # ------------------------------------------------------------------ #

    def _glob(
        self,
        pattern: str,
        path: str | None = None,
        head_limit: int | None = None,
    ) -> dict[str, Any]:
        """Find files by glob pattern, most recently modified first."""
        search_root = self._resolve_root(path)
        if isinstance(search_root, dict):
            return search_root

        limit = min(head_limit or MAX_GLOB_RESULTS, MAX_GLOB_RESULTS)
        entries: list[tuple[float, str]] = []
        escaped = 0
        try:
            for entry in search_root.glob(pattern):
                if any(part in SKIP_DIRS for part in entry.parts):
                    continue
                # Validating only the search root is not enough: a pattern like
                # "../secrets/*" is resolved by glob() relative to that root and
                # yields paths outside it. Without this re-check the whitelist
                # leaks filenames from anywhere on the disk.
                if not self.guard.is_allowed(str(entry)):
                    escaped += 1
                    continue
                try:
                    entries.append((entry.stat().st_mtime, str(entry)))
                except OSError:
                    continue
        except (OSError, ValueError) as e:
            return err(f"Glob failed: {e}", "GlobError")

        if escaped:
            logger.warning(
                "glob pattern %r under %s produced %d match(es) outside the whitelist",
                pattern, search_root, escaped,
            )

        # Recency beats alphabetical order for an agent orienting in a project:
        # the file someone just touched is almost always the relevant one.
        entries.sort(key=lambda pair: pair[0], reverse=True)
        matches = [p for _, p in entries[:limit]]

        return ok(
            root=str(search_root),
            pattern=pattern,
            matches=matches,
            count=len(matches),
            total_found=len(entries),
            truncated=len(entries) > limit,
            sorted_by="modified_desc",
            excluded_outside_whitelist=escaped,
        )

    # ------------------------------------------------------------------ #
    #  Tool: grep
    # ------------------------------------------------------------------ #

    def _grep(
        self,
        pattern: str,
        path: str | None = None,
        glob: str | None = None,
        output_mode: str = "content",
        case_insensitive: bool = False,
        context_lines: int = 0,
        head_limit: int | None = None,
    ) -> dict[str, Any]:
        """Search file contents, preferring ripgrep and falling back to Python."""
        search_root = self._resolve_root(path)
        if isinstance(search_root, dict):
            return search_root

        if output_mode not in ("content", "files_with_matches", "count"):
            return err(f"Unknown output_mode: {output_mode!r}", "InvalidArguments")

        try:
            re.compile(pattern)
        except re.error as e:
            return err(f"Invalid regex: {e}", "RegexError")

        limit = min(head_limit or MAX_GREP_RESULTS, MAX_GREP_RESULTS)
        rg = _find_ripgrep(getattr(self.config, "ripgrep_path", "") or None)
        if rg:
            return self._grep_ripgrep(
                rg, pattern, search_root, glob, output_mode,
                case_insensitive, context_lines, limit,
            )
        return self._grep_python(
            pattern, search_root, glob, output_mode,
            case_insensitive, context_lines, limit,
        )

    def _grep_ripgrep(
        self,
        rg: str,
        pattern: str,
        root: Path,
        glob: str | None,
        output_mode: str,
        case_insensitive: bool,
        context_lines: int,
        limit: int,
    ) -> dict[str, Any]:
        """Run ripgrep and normalise its output.

        ``--json`` rather than the default text output: a Windows path contains a
        drive-letter colon, so parsing ``path:line:text`` by splitting on colons
        mangles every result.
        """
        argv = [rg, "--json", "--no-messages"]
        if case_insensitive:
            argv.append("-i")
        if glob:
            argv.extend(["--glob", glob])
        if context_lines and output_mode == "content":
            argv.extend(["-C", str(context_lines)])
        for skip in SKIP_DIRS:
            argv.extend(["--glob", f"!{skip}/"])
        argv.extend(["--", pattern, str(root)])

        try:
            proc = subprocess.run(argv, capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.warning("ripgrep failed (%s); falling back to Python", e)
            return self._grep_python(
                pattern, root, glob, output_mode, case_insensitive, context_lines, limit
            )

        matches: list[dict[str, Any]] = []
        per_file: dict[str, int] = {}
        # ripgrep reports -C lines as "context" events, separate from "match".
        # Keeping only matches would silently drop the context the caller asked
        # for and make the result shape depend on which engine happened to be
        # available. Lines are indexed by number rather than folded onto the
        # nearest match as they stream past: leading context arrives *before*
        # its match, so positional attachment misfiles every one of them.
        seen_lines: dict[str, dict[int, str]] = {}

        for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            kind = event.get("type")
            if kind not in ("match", "context"):
                continue

            data = event["data"]
            file_path = data["path"].get("text", "")
            text = data["lines"].get("text", "").rstrip("\n")
            line_no = data.get("line_number")
            if line_no is not None:
                seen_lines.setdefault(file_path, {})[line_no] = text

            if kind != "match":
                continue

            per_file[file_path] = per_file.get(file_path, 0) + 1
            if output_mode == "content" and len(matches) < limit:
                matches.append({
                    "file": file_path,
                    "line_number": line_no,
                    "content": text,
                })

        if context_lines and output_mode == "content":
            for entry in matches:
                centre = entry["line_number"]
                if centre is None:
                    continue
                window = seen_lines.get(entry["file"], {})
                entry["context"] = [
                    {"line_number": n, "content": window[n], "match": n == centre}
                    for n in range(centre - context_lines, centre + context_lines + 1)
                    if n in window
                ]

        return self._grep_result(
            output_mode, matches, per_file, root, pattern, glob, limit, engine="ripgrep"
        )

    def _grep_python(
        self,
        pattern: str,
        root: Path,
        glob: str | None,
        output_mode: str,
        case_insensitive: bool,
        context_lines: int,
        limit: int,
    ) -> dict[str, Any]:
        """Pure-Python fallback used only when no ripgrep binary is available."""
        regex = re.compile(pattern, re.IGNORECASE if case_insensitive else 0)
        matches: list[dict[str, Any]] = []
        per_file: dict[str, int] = {}

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for filename in filenames:
                if glob and not fnmatch.fnmatch(filename, glob):
                    continue
                filepath = Path(dirpath) / filename
                try:
                    raw = filepath.read_bytes()
                except OSError:
                    continue
                # Skip binaries: matching a regex against decoded noise wastes
                # time and produces results no one can use.
                if b"\x00" in raw[:8192]:
                    continue
                try:
                    lines = raw.decode("utf-8").splitlines()
                except UnicodeDecodeError:
                    lines = raw.decode("gbk", errors="ignore").splitlines()

                for i, line in enumerate(lines):
                    if not regex.search(line):
                        continue
                    key = str(filepath)
                    per_file[key] = per_file.get(key, 0) + 1
                    if output_mode == "content" and len(matches) < limit:
                        entry: dict[str, Any] = {
                            "file": key,
                            "line_number": i + 1,
                            "content": line,
                        }
                        if context_lines > 0:
                            lo = max(0, i - context_lines)
                            hi = min(len(lines), i + context_lines + 1)
                            entry["context"] = [
                                {"line_number": lo + j + 1, "content": lines[lo + j], "match": lo + j == i}
                                for j in range(hi - lo)
                            ]
                        matches.append(entry)

        return self._grep_result(
            output_mode, matches, per_file, root, pattern, glob, limit, engine="python"
        )

    @staticmethod
    def _grep_result(
        output_mode: str,
        matches: list[dict[str, Any]],
        per_file: dict[str, int],
        root: Path,
        pattern: str,
        glob: str | None,
        limit: int,
        engine: str,
    ) -> dict[str, Any]:
        """Shape the collected hits according to output_mode."""
        base = {
            "root": str(root),
            "pattern": pattern,
            "glob": glob,
            "engine": engine,
            "files_with_matches": len(per_file),
            "total_matches": sum(per_file.values()),
        }
        if output_mode == "files_with_matches":
            files = sorted(per_file)[:limit]
            return ok(**base, files=files, count=len(files), truncated=len(per_file) > limit)
        if output_mode == "count":
            counts = [{"file": f, "count": c} for f, c in sorted(per_file.items())][:limit]
            return ok(**base, counts=counts, count=len(counts), truncated=len(per_file) > limit)
        return ok(
            **base,
            matches=matches,
            count=len(matches),
            truncated=sum(per_file.values()) > len(matches),
        )

    # ------------------------------------------------------------------ #
    #  Tool: list_directory
    # ------------------------------------------------------------------ #

    def _list_directory(self, path: str) -> dict[str, Any]:
        """List directory contents with file metadata."""
        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        if not resolved.exists():
            return err(f"Directory not found: {resolved}", "NotFound")
        if not resolved.is_dir():
            return err(f"Not a directory: {resolved}", "NotADirectory")

        entries: list[dict[str, Any]] = []
        try:
            for entry in sorted(resolved.iterdir(), key=lambda p: p.name.lower()):
                try:
                    stat = entry.lstat()
                    if entry.is_symlink():
                        ftype = "symlink"
                    elif entry.is_dir():
                        ftype = "directory"
                    else:
                        ftype = "file"
                    entries.append({
                        "name": entry.name,
                        "type": ftype,
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                        # Epoch seconds are unreadable in a transcript; the ISO
                        # form is what the agent actually reasons about.
                        "modified_iso": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).astimezone().isoformat(timespec="seconds"),
                    })
                except OSError:
                    entries.append({"name": entry.name, "type": "unknown", "size": 0,
                                    "modified": 0, "modified_iso": None})
        except OSError as e:
            return err(f"Failed to list directory: {e}", "ListError")

        return ok(path=str(resolved), entries=entries, count=len(entries))

    # ------------------------------------------------------------------ #
    #  Tool: get_project_tree
    # ------------------------------------------------------------------ #

    def _get_project_tree(self, path: str | None = None, max_depth: int = 3) -> dict[str, Any]:
        """Render a directory tree, honouring .gitignore."""
        root = self._resolve_root(path)
        if isinstance(root, dict):
            return root

        max_depth = max(1, min(max_depth, 10))
        ignore_patterns = _load_gitignore_patterns(root)
        ignore_spec = compile_ignore_spec(ignore_patterns)

        tree_lines: list[str] = [str(root)]
        entry_count = 0

        def _visible(dir_path: Path) -> list[Path]:
            """Children that survive filtering, in display order."""
            try:
                children = sorted(dir_path.iterdir(), key=lambda p: p.name.lower())
            except OSError:
                return []
            kept = []
            for child in children:
                if child.is_dir() and child.name in SKIP_DIRS:
                    continue
                # A symlink or junction can point outside the whitelist; walking
                # into it would list names from anywhere on the disk. The root
                # check alone does not cover paths reached by following one.
                if child.is_symlink() and not self.guard.is_allowed(str(child)):
                    continue
                rel = str(child.relative_to(root)).replace(os.sep, "/")
                if _is_ignored(rel, child.is_dir(), ignore_spec, ignore_patterns):
                    continue
                kept.append(child)
            return kept

        def _walk(dir_path: Path, prefix: str, depth: int) -> None:
            nonlocal entry_count
            if depth > max_depth or entry_count >= MAX_TREE_ENTRIES:
                return

            # "Is this the last item?" must be decided against the FILTERED list.
            # Testing against the raw listing draws a tee instead of an elbow
            # whenever the true last child happens to be ignored.
            children = _visible(dir_path)
            for index, child in enumerate(children):
                is_last = index == len(children) - 1
                tree_lines.append(f"{prefix}{'└── ' if is_last else '├── '}{child.name}")

                entry_count += 1
                if entry_count >= MAX_TREE_ENTRIES:
                    tree_lines.append(f"{prefix}{'    ' if is_last else '│   '}...<truncated>")
                    return

                if child.is_dir():
                    _walk(child, prefix + ("    " if is_last else "│   "), depth + 1)

        _walk(root, "", 1)

        return ok(
            root=str(root),
            max_depth=max_depth,
            tree="\n".join(tree_lines),
            entries=entry_count,
            truncated=entry_count >= MAX_TREE_ENTRIES,
        )

    # ------------------------------------------------------------------ #
    #  Tool: scan_encrypted
    # ------------------------------------------------------------------ #

    def _scan_encrypted(
        self,
        path: str | None = None,
        pattern: str | None = None,
        max_files: int = 2000,
    ) -> dict[str, Any]:
        """Report which files under a directory carry a DLP encryption marker."""
        root = self._resolve_root(path)
        if isinstance(root, dict):
            return root

        markers = parse_markers(self.config.encrypted_file_markers)
        limit = max(1, min(int(max_files), 20000))

        encrypted: list[str] = []
        readable = checked = 0
        by_extension: dict[str, dict[str, int]] = {}

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                if pattern and not fnmatch.fnmatch(filename, pattern):
                    continue
                if checked >= limit:
                    break
                filepath = Path(dirpath) / filename
                try:
                    with filepath.open("rb") as fh:
                        head = fh.read(16)
                except OSError:
                    continue

                checked += 1
                ext = filepath.suffix.lower() or "(none)"
                bucket = by_extension.setdefault(ext, {"encrypted": 0, "readable": 0})
                if head_is_encrypted(head, markers):
                    bucket["encrypted"] += 1
                    if len(encrypted) < 500:
                        encrypted.append(str(filepath))
                else:
                    bucket["readable"] += 1
                    readable += 1
            if checked >= limit:
                break

        return ok(
            root=str(root),
            files_checked=checked,
            encrypted_count=len(encrypted),
            readable_count=readable,
            encrypted_files=encrypted,
            by_extension=dict(sorted(by_extension.items())),
            truncated=checked >= limit,
            staging_dir=str(staging_dir(self.config.staging_dir)),
            note=(
                "Encrypted files cannot be read by this daemon and copying does "
                "not decrypt them. Re-export them from the owning application "
                "into staging_dir, which the encryption driver excludes."
            ),
        )


# ====================================================================== #
#  .gitignore helpers
# ====================================================================== #

def _load_gitignore_patterns(root: Path) -> list[str]:
    """Collect .gitignore patterns from the root directory."""
    patterns: list[str] = [".git/", "__pycache__/", "*.pyc", ".DS_Store"]

    gitignore = root / ".gitignore"
    if gitignore.is_file():
        try:
            for line in gitignore.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
        except OSError:
            pass

    return patterns


def compile_ignore_spec(patterns: list[str]) -> Any:
    """Compile gitignore patterns once, for reuse across a whole tree walk.

    Compiling per entry — which is what a naive ``_is_ignored(path, patterns)``
    helper does — reparses every pattern for every file in the tree, and on
    pathspec 1.x also emits a deprecation warning each time.

    pathspec renamed the ``gitwildmatch`` style to ``gitignore`` in 1.0; try the
    current name first so we neither warn on new versions nor break on old ones.
    """
    import pathspec

    for style in ("gitignore", "gitwildmatch"):
        try:
            return pathspec.PathSpec.from_lines(style, patterns)
        except (ValueError, KeyError, LookupError):
            continue
    return None


def _is_ignored(rel_path: str, is_dir: bool, spec: Any, patterns: list[str]) -> bool:
    """Check whether a relative path is ignored, given a precompiled spec."""
    candidate = rel_path + ("/" if is_dir else "")
    if spec is not None:
        try:
            return bool(spec.match_file(candidate))
        except Exception:  # noqa: BLE001 — fall through rather than fail the walk
            pass

    name = rel_path.rsplit("/", 1)[-1]
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if fnmatch.fnmatch(name, clean) or fnmatch.fnmatch(rel_path, clean):
            return True
    return False
