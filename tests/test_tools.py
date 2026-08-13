"""Tests for the tool providers, driven through the real dispatcher.

Every call goes through ``ToolHandler.call_tool`` rather than poking a provider
method directly, so the routing table, the argument binding, the audit log, and
the error containment are all exercised on the way in.  The ``call_tool``
fixture unwraps the ``CallToolResult`` and returns the decoded JSON payload.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from localhands.tools import ToolHandler
from localhands.tools.base import MAX_GLOB_RESULTS, MAX_GREP_RESULTS

Call = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]
WriteLines = Callable[[Path, Sequence[str]], Path]


def _records(log_path: Path) -> list[dict[str, Any]]:
    """Decode the JSONL audit log written during a test."""
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line
    ]


# ====================================================================== #
#  read_file
# ====================================================================== #

class TestReadFile:
    """Reading is the most-used tool; its pagination contract is what stops a
    large file from flooding the model's context."""

    async def test_round_trips_utf8_including_non_ascii(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        # Non-ASCII paths and contents are routine, and a mis-declared encoding
        # shows up as mojibake rather than as an error.
        target = write_lines(allowed_root / "notes.txt", ["hello", "中文内容", "café"])
        result = await call_tool("read_file", {"path": str(target)})

        assert result["status"] == "success"
        assert result["encoding"] == "utf-8"
        # Line numbers are prefixed onto each line by default, so the assertion
        # is containment rather than equality.
        for expected in ("hello", "中文内容", "café"):
            assert expected in result["content"]

    async def test_reports_total_lines_regardless_of_the_page_returned(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        # total_lines is how the caller knows to ask for another page; if it
        # reported only the page size, pagination would silently stop early.
        target = write_lines(allowed_root / "big.txt", [f"line{i}" for i in range(50)])
        result = await call_tool("read_file", {"path": str(target), "limit": 5})

        assert result["lines_returned"] == 5
        assert result["total_lines"] == 50

    async def test_offset_and_limit_select_a_window(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        target = write_lines(allowed_root / "ten.txt", [f"line{i}" for i in range(10)])
        result = await call_tool("read_file", {"path": str(target), "offset": 2, "limit": 3})

        assert result["offset"] == 2
        assert result["lines_returned"] == 3
        assert "line2" in result["content"]
        assert "line4" in result["content"]
        assert "line1" not in result["content"]
        assert "line5" not in result["content"]

    async def test_offset_past_the_end_returns_an_empty_page(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        # An out-of-range page is not an error: the caller may be walking a file
        # that shrank between calls.
        target = write_lines(allowed_root / "ten.txt", [f"line{i}" for i in range(10)])
        result = await call_tool("read_file", {"path": str(target), "offset": 999})

        assert result["status"] == "success"
        assert result["lines_returned"] == 0
        assert result["content"] == ""
        assert result["total_lines"] == 10

    async def test_missing_file_is_reported_not_raised(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        result = await call_tool("read_file", {"path": str(allowed_root / "absent.txt")})
        assert result["error_type"] == "FileNotFound"

    async def test_directory_is_refused(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        result = await call_tool("read_file", {"path": str(allowed_root)})
        assert result["error_type"] == "NotAFile"


# ====================================================================== #
#  write_file
# ====================================================================== #

class TestWriteFile:
    """Writing has to be able to create structure, and has to say what it did."""

    async def test_creates_missing_parent_directories(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        target = allowed_root / "new" / "nested" / "file.txt"
        result = await call_tool("write_file", {"path": str(target), "content": "hi"})

        assert result["status"] == "success"
        assert result["action"] == "created"
        assert target.read_text(encoding="utf-8") == "hi"

    async def test_overwriting_is_reported_as_such(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # The distinction matters to the caller: "overwritten" means content it
        # never read is now gone.
        target = allowed_root / "existing.txt"
        target.write_text("old", encoding="utf-8")

        result = await call_tool("write_file", {"path": str(target), "content": "new"})
        assert result["action"] == "overwritten"
        assert target.read_text(encoding="utf-8") == "new"

    async def test_non_ascii_content_survives_the_round_trip(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        target = allowed_root / "chinese.txt"
        await call_tool("write_file", {"path": str(target), "content": "报告完成\n"})
        assert target.read_text(encoding="utf-8") == "报告完成\n"

    async def test_reported_byte_count_is_utf8_bytes_not_characters(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # Three Chinese characters are nine bytes; reporting three would make
        # the size limits meaningless for any non-ASCII content.
        result = await call_tool(
            "write_file", {"path": str(allowed_root / "cn.txt"), "content": "报告书"}
        )
        assert result["bytes_written"] == 9

    async def test_reported_byte_count_matches_the_file_on_disk(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # bytes_written is measured on the string handed in, so the write must
        # not translate newlines behind it. Windows text mode would turn each
        # "\n" into "\r\n", leaving the reported count one byte per line short
        # of the file it just created — and that count is what a size check
        # would be built on.
        target = allowed_root / "counted.txt"
        result = await call_tool("write_file", {"path": str(target), "content": "one\ntwo\n"})

        assert result["bytes_written"] == 8
        assert target.stat().st_size == 8
        assert target.read_bytes() == b"one\ntwo\n"

    async def test_writing_over_a_directory_is_refused(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        result = await call_tool("write_file", {"path": str(allowed_root), "content": "x"})
        assert result["status"] == "error"


# ====================================================================== #
#  edit_file
# ====================================================================== #

class TestEditFile:
    """The refusal cases are the point: a remote model cannot inspect the
    damage afterwards, so an imprecise edit has to fail rather than guess."""

    async def test_unique_match_is_replaced_and_counted(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        target = allowed_root / "code.py"
        target.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")

        result = await call_tool("edit_file", {
            "path": str(target), "old_string": "beta", "new_string": "delta",
        })
        assert result["status"] == "success"
        assert result["replacements"] == 1
        assert "delta" in target.read_text(encoding="utf-8")

    async def test_replace_all_reports_every_occurrence(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        target = allowed_root / "code.py"
        target.write_bytes(b"x = 1\ny = 1\nz = 1\n")

        result = await call_tool("edit_file", {
            "path": str(target), "old_string": "1", "new_string": "2",
            "replace_all": True,
        })
        assert result["replacements"] == 3
        assert target.read_text(encoding="utf-8") == "x = 2\ny = 2\nz = 2\n"

    async def test_editing_leaves_lf_line_endings_alone(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # Writing back through Windows text mode would translate every "\n" to
        # "\r\n", so editing one word would rewrite the line endings of the
        # whole file — a change the caller never asked for and cannot see in
        # the result.
        target = allowed_root / "unix.py"
        target.write_bytes(b"alpha\nbeta\n")

        await call_tool("edit_file", {
            "path": str(target), "old_string": "alpha", "new_string": "ALPHA",
        })
        assert target.read_bytes() == b"ALPHA\nbeta\n"

    async def test_repeated_edits_of_a_crlf_file_do_not_accumulate_carriage_returns(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # The damaging half of the case above.  The file is read as bytes, so
        # its "\r\n" survives; translating on write would yield "\r\r\n", then
        # one more CR on every line with each further edit.  Repeated editing is
        # the normal case, so the corruption compounds silently.
        target = allowed_root / "windows.py"
        target.write_bytes(b"alpha\r\nbeta\r\n")

        await call_tool("edit_file", {
            "path": str(target), "old_string": "alpha", "new_string": "ALPHA",
        })
        assert target.read_bytes() == b"ALPHA\r\nbeta\r\n"

        await call_tool("edit_file", {
            "path": str(target), "old_string": "beta", "new_string": "BETA",
        })
        assert target.read_bytes() == b"ALPHA\r\nBETA\r\n"

    async def test_ambiguous_match_is_refused_when_replace_all_is_false(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # Two matches and no instruction to replace both means the caller's
        # old_string was not specific enough to know which one it meant.
        target = allowed_root / "code.py"
        target.write_text("value = 1\nvalue = 1\n", encoding="utf-8")

        result = await call_tool("edit_file", {
            "path": str(target), "old_string": "value = 1", "new_string": "value = 2",
            "replace_all": False,
        })
        assert result["error_type"] == "AmbiguousMatch"

    async def test_file_is_untouched_when_an_edit_is_refused(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # A refusal that had already written half the change would be worse
        # than no guard at all.
        target = allowed_root / "code.py"
        original = "value = 1\nvalue = 1\n"
        target.write_text(original, encoding="utf-8")

        await call_tool("edit_file", {
            "path": str(target), "old_string": "value = 1", "new_string": "value = 2",
            "replace_all": False,
        })
        assert target.read_text(encoding="utf-8") == original

    async def test_missing_string_is_reported_as_string_not_found(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        target = allowed_root / "code.py"
        target.write_text("alpha\n", encoding="utf-8")

        result = await call_tool("edit_file", {
            "path": str(target), "old_string": "nowhere", "new_string": "x",
        })
        assert result["error_type"] == "StringNotFound"

    async def test_editing_a_missing_file_is_reported(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        result = await call_tool("edit_file", {
            "path": str(allowed_root / "absent.py"), "old_string": "a", "new_string": "b",
        })
        assert result["error_type"] == "FileNotFound"


# ====================================================================== #
#  glob
# ====================================================================== #

class TestGlob:
    """Name search, and the cap that keeps a wildcard from returning a disk."""

    async def test_finds_files_matching_the_pattern(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        (allowed_root / "a.py").write_text("", encoding="utf-8")
        (allowed_root / "b.py").write_text("", encoding="utf-8")
        (allowed_root / "c.txt").write_text("", encoding="utf-8")

        result = await call_tool("glob", {"pattern": "*.py", "path": str(allowed_root)})
        assert {Path(m).name for m in result["matches"]} == {"a.py", "b.py"}
        assert result["count"] == 2

    async def test_double_star_descends_into_subdirectories(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        nested = allowed_root / "pkg" / "sub"
        nested.mkdir(parents=True)
        (nested / "deep.py").write_text("", encoding="utf-8")

        result = await call_tool("glob", {"pattern": "**/*.py", "path": str(allowed_root)})
        assert [Path(m).name for m in result["matches"]] == ["deep.py"]

    async def test_no_match_is_an_empty_success_not_an_error(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        result = await call_tool("glob", {"pattern": "*.nothing", "path": str(allowed_root)})
        assert result["status"] == "success"
        assert result["matches"] == []
        assert result["truncated"] is False

    async def test_results_are_capped_and_the_truncation_is_declared(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # Without the cap one "**/*" against a large tree would return a result
        # far bigger than the context it has to fit in.
        for i in range(MAX_GLOB_RESULTS + 5):
            (allowed_root / f"f{i:04d}.dat").write_text("", encoding="utf-8")

        result = await call_tool("glob", {"pattern": "*.dat", "path": str(allowed_root)})
        assert result["count"] == MAX_GLOB_RESULTS
        assert result["truncated"] is True

    async def test_relative_pattern_cannot_reach_outside_the_whitelist(
        self, call_tool: Call, allowed_root: Path, outside_root: Path
    ) -> None:
        # Validating only the search root is not enough: glob() resolves "../"
        # relative to that root and happily yields paths outside it.  Every match
        # is re-checked against PathGuard, so the pattern returns nothing rather
        # than leaking filenames from a directory the caller was never granted.
        result = await call_tool(
            "glob", {"pattern": "../outside/*", "path": str(allowed_root)}
        )
        assert result["status"] == "success"
        assert result["matches"] == []
        assert result["excluded_outside_whitelist"] >= 1

    async def test_leaked_path_still_cannot_be_read(
        self, call_tool: Call, allowed_root: Path, outside_root: Path
    ) -> None:
        # The other half of the bug above: knowing the name buys nothing,
        # because every read re-resolves the path against the whitelist.
        escaped = str(allowed_root / ".." / "outside" / "secret.txt")
        result = await call_tool("read_file", {"path": escaped})
        assert result["error_type"] == "PathGuardError"


# ====================================================================== #
#  grep
# ====================================================================== #

class TestGrep:
    """Content search.  The engine may be ripgrep or the Python fallback, so
    the assertions stay on the fields both engines promise."""

    async def test_finds_matching_lines_with_their_line_numbers(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        write_lines(allowed_root / "a.py", ["import os", "def handler():", "    pass"])

        result = await call_tool("grep", {"pattern": r"def \w+", "path": str(allowed_root)})
        assert result["count"] == 1
        hit = result["matches"][0]
        assert hit["line_number"] == 2
        assert "def handler" in hit["content"]

    async def test_glob_filter_restricts_which_files_are_searched(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        write_lines(allowed_root / "a.py", ["TARGET"])
        write_lines(allowed_root / "b.txt", ["TARGET"])

        result = await call_tool("grep", {
            "pattern": "TARGET", "path": str(allowed_root), "glob": "*.py",
        })
        assert result["count"] == 1
        assert result["matches"][0]["file"].endswith("a.py")

    async def test_invalid_regex_is_reported_not_raised(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        result = await call_tool("grep", {"pattern": "([unclosed", "path": str(allowed_root)})
        assert result["error_type"] == "RegexError"

    async def test_no_match_is_an_empty_success(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        write_lines(allowed_root / "a.py", ["nothing here"])
        result = await call_tool("grep", {"pattern": "ABSENT", "path": str(allowed_root)})
        assert result["status"] == "success"
        assert result["count"] == 0

    async def test_results_are_capped_and_the_truncation_is_declared(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        write_lines(
            allowed_root / "many.txt",
            [f"MATCH {i}" for i in range(MAX_GREP_RESULTS + 50)],
        )
        result = await call_tool("grep", {"pattern": "MATCH", "path": str(allowed_root)})

        assert result["count"] == MAX_GREP_RESULTS
        assert result["truncated"] is True

    async def test_files_with_matches_mode_returns_paths_only(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        # The cheap exploration mode: one entry per file instead of one per line.
        write_lines(allowed_root / "a.py", ["hit", "hit", "hit"])
        result = await call_tool("grep", {
            "pattern": "hit", "path": str(allowed_root),
            "output_mode": "files_with_matches",
        })
        assert result["count"] == 1
        assert result["files"][0].endswith("a.py")

    async def test_context_lines_are_honoured_by_either_engine(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        # ripgrep reports context on separate "context" events, so an
        # implementation that keeps only "match" events silently drops the
        # argument.  The caller cannot choose which engine runs, so both must
        # produce the same shape.
        write_lines(allowed_root / "ctx.txt", ["before", "NEEDLE", "after"])
        result = await call_tool("grep", {
            "pattern": "NEEDLE", "path": str(allowed_root), "context_lines": 1,
        })

        hit = result["matches"][0]
        assert [c["content"] for c in hit["context"]] == ["before", "NEEDLE", "after"]
        assert [c["match"] for c in hit["context"]] == [False, True, False]

    async def test_context_lines_zero_omits_the_context_field(
        self, call_tool: Call, allowed_root: Path, write_lines: WriteLines
    ) -> None:
        write_lines(allowed_root / "ctx.txt", ["before", "NEEDLE", "after"])
        result = await call_tool("grep", {"pattern": "NEEDLE", "path": str(allowed_root)})
        assert "context" not in result["matches"][0]


# ====================================================================== #
#  list_directory
# ====================================================================== #

class TestListDirectory:
    async def test_reports_each_entry_with_its_type(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        (allowed_root / "sub").mkdir()
        (allowed_root / "file.txt").write_text("abc", encoding="utf-8")

        result = await call_tool("list_directory", {"path": str(allowed_root)})
        by_name = {e["name"]: e for e in result["entries"]}
        assert by_name["sub"]["type"] == "directory"
        assert by_name["file.txt"]["type"] == "file"
        assert by_name["file.txt"]["size"] == 3

    async def test_a_file_is_not_a_directory(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        target = allowed_root / "file.txt"
        target.write_text("x", encoding="utf-8")
        result = await call_tool("list_directory", {"path": str(target)})
        assert result["error_type"] == "NotADirectory"


# ====================================================================== #
#  get_project_tree
# ====================================================================== #

class TestProjectTree:
    """Depth limiting and .gitignore filtering are what keep the tree small
    enough to be worth sending."""

    @staticmethod
    def _build(root: Path) -> None:
        (root / "d1" / "d2" / "d3").mkdir(parents=True)
        (root / "top.txt").write_text("", encoding="utf-8")
        (root / "d1" / "level2.txt").write_text("", encoding="utf-8")
        (root / "d1" / "d2" / "level3.txt").write_text("", encoding="utf-8")
        (root / "d1" / "d2" / "d3" / "level4.txt").write_text("", encoding="utf-8")

    async def test_max_depth_one_lists_only_the_immediate_children(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        self._build(allowed_root)
        result = await call_tool(
            "get_project_tree", {"path": str(allowed_root), "max_depth": 1}
        )
        tree = result["tree"]
        assert "top.txt" in tree
        assert "d1" in tree
        assert "level2.txt" not in tree

    async def test_max_depth_two_reaches_one_level_further(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        self._build(allowed_root)
        result = await call_tool(
            "get_project_tree", {"path": str(allowed_root), "max_depth": 2}
        )
        tree = result["tree"]
        assert "level2.txt" in tree
        assert "level3.txt" not in tree

    async def test_max_depth_is_clamped_to_the_supported_range(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # An unbounded depth from a model that picked a large number would walk
        # the whole volume, so the value is clamped rather than trusted.
        self._build(allowed_root)
        result = await call_tool(
            "get_project_tree", {"path": str(allowed_root), "max_depth": 9999}
        )
        assert result["max_depth"] == 10

    async def test_gitignored_entries_are_skipped(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # Build output and virtualenvs dwarf the source they surround; including
        # them would make the tree useless at any depth.
        (allowed_root / ".gitignore").write_text("build/\n*.log\n", encoding="utf-8")
        (allowed_root / "build").mkdir()
        (allowed_root / "build" / "artifact.o").write_text("", encoding="utf-8")
        (allowed_root / "noise.log").write_text("", encoding="utf-8")
        (allowed_root / "keep.py").write_text("", encoding="utf-8")

        tree = (await call_tool(
            "get_project_tree", {"path": str(allowed_root), "max_depth": 3}
        ))["tree"]
        assert "keep.py" in tree
        assert "build" not in tree
        assert "noise.log" not in tree

    async def test_cache_directories_are_skipped_without_a_gitignore(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        (allowed_root / "__pycache__").mkdir()
        (allowed_root / "__pycache__" / "x.pyc").write_text("", encoding="utf-8")
        (allowed_root / "keep.py").write_text("", encoding="utf-8")

        tree = (await call_tool("get_project_tree", {"path": str(allowed_root)}))["tree"]
        assert "keep.py" in tree
        assert "__pycache__" not in tree

    async def test_a_gitignore_above_the_root_is_not_consulted(
        self, call_tool: Call, allowed_root: Path, tmp_path: Path
    ) -> None:
        # Only the root's own .gitignore is read.  Walking up would mean reading
        # files outside the whitelist to decide what to show inside it.
        (tmp_path / ".gitignore").write_text("keep.py\n", encoding="utf-8")
        (allowed_root / "keep.py").write_text("", encoding="utf-8")

        tree = (await call_tool(
            "get_project_tree", {"path": str(allowed_root)}
        ))["tree"]
        assert "keep.py" in tree


# ====================================================================== #
#  run_bash
# ====================================================================== #

class TestRunBash:
    """Arbitrary execution by design, but it must never hang the daemon or
    swallow a failure."""

    async def test_captures_stdout(self, call_tool: Call, allowed_root: Path) -> None:
        result = await call_tool("run_bash", {
            "command": "echo bridge_marker", "cwd": str(allowed_root),
        })
        assert result["status"] == "success"
        assert "bridge_marker" in result["stdout"]
        assert result["exit_code"] == 0

    async def test_reports_a_non_zero_exit_code_as_a_successful_call(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # The tool call succeeded; the *command* failed.  Conflating the two
        # would leave the caller unable to see the exit code at all.
        result = await call_tool("run_bash", {
            "command": "echo failing && exit 3", "cwd": str(allowed_root),
        })
        assert result["status"] == "success"
        assert result["exit_code"] == 3
        assert "failing" in result["stdout"]

    async def test_times_out_cleanly_instead_of_hanging(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # A command that never returns would otherwise pin a worker thread for
        # the lifetime of the daemon.
        sleeper = f'"{sys.executable}" -c "import time; time.sleep(5)"'
        result = await call_tool("run_bash", {
            "command": sleeper, "cwd": str(allowed_root), "timeout": 1,
        })
        assert result["error_type"] == "TimeoutError"
        assert "1s" in result["error"]

    async def test_the_timeout_actually_bounds_the_call(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # shell=True runs the command under cmd.exe, and whatever cmd spawns
        # inherits the stdout/stderr pipes.  Killing only cmd leaves the
        # grandchild holding them, so the read blocks until it finishes anyway —
        # the timeout reports but does not bound, and a runaway command keeps a
        # worker thread for as long as it likes.  The whole process tree has to
        # go for the timeout to mean anything.
        sleeper = f'"{sys.executable}" -c "import time; time.sleep(10)"'
        start = time.monotonic()
        result = await call_tool("run_bash", {
            "command": sleeper, "cwd": str(allowed_root), "timeout": 1,
        })
        elapsed = time.monotonic() - start

        assert result["error_type"] == "TimeoutError"
        assert elapsed < 6, f"timeout did not bound the call: returned after {elapsed:.1f}s"

    async def test_runs_in_the_requested_working_directory(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        workdir = allowed_root / "workdir"
        workdir.mkdir()
        result = await call_tool("run_bash", {"command": "cd", "cwd": str(workdir)})
        assert str(workdir).lower() in result["stdout"].lower()

    async def test_irreversible_command_is_blocked_before_it_runs(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        # The guard rail exists for exactly one failure mode: a model acting on
        # a misread instruction emitting one unrecoverable command.
        result = await call_tool("run_bash", {
            "command": "format C: /q", "cwd": str(allowed_root),
        })
        assert result["error_type"] == "CommandBlocked"


# ====================================================================== #
#  Dispatcher behaviour
# ====================================================================== #

class TestDispatcher:
    """Contract of ToolHandler itself, independent of any one provider."""

    async def test_unknown_tool_name_is_reported_as_unknown_tool(
        self, call_tool: Call
    ) -> None:
        result = await call_tool("no_such_tool", {})
        assert result["error_type"] == "UnknownTool"

    async def test_missing_required_argument_is_reported_as_invalid_arguments(
        self, call_tool: Call
    ) -> None:
        # A model that omits a field should get a correctable error, not a
        # stack trace surfaced as a server crash.
        result = await call_tool("read_file", {})
        assert result["error_type"] == "InvalidArguments"

    async def test_unexpected_argument_is_reported_as_invalid_arguments(
        self, call_tool: Call, allowed_root: Path
    ) -> None:
        target = allowed_root / "a.txt"
        target.write_text("x", encoding="utf-8")
        result = await call_tool("read_file", {"path": str(target), "not_a_field": 1})
        assert result["error_type"] == "InvalidArguments"

    async def test_a_failing_tool_never_raises_out_of_call_tool(
        self, handler: ToolHandler
    ) -> None:
        # The MCP server has no recovery path if a tool call propagates, so
        # every failure has to come back as a normal result.
        result = await handler.call_tool("read_file", {})
        assert result.content[0].text

    async def test_every_call_is_written_to_the_audit_log(
        self, call_tool: Call, allowed_root: Path, log_path: Path
    ) -> None:
        # list_directory rather than a file tool: this asserts that the
        # dispatcher audits, and should not fail because of whatever any one
        # provider happens to be doing.
        await call_tool("list_directory", {"path": str(allowed_root)})

        record = _records(log_path)[-1]
        assert record["tool"] == "list_directory"
        assert record["status"] == "success"
        assert record["arguments"]["path"] == str(allowed_root)

    async def test_a_refused_call_is_audited_with_its_error(
        self, call_tool: Call, outside_root: Path, log_path: Path
    ) -> None:
        # The audit trail's whole purpose is to show what was attempted, so a
        # blocked attempt has to be recorded as loudly as a successful one.
        await call_tool("read_file", {"path": str(outside_root / "secret.txt")})

        record = _records(log_path)[-1]
        assert record["status"] == "error"
        assert "outside all allowed directories" in record["error"]

    async def test_no_two_providers_declare_the_same_tool_name(
        self, handler: ToolHandler
    ) -> None:
        # The routing table is a dict, so a collision would make one tool
        # silently shadow the other.
        names = [tool.name for tool in await handler.list_tools()]
        assert len(names) == len(set(names))

    async def test_advertised_tools_are_all_callable(
        self, handler: ToolHandler
    ) -> None:
        # A schema with no handler behind it wastes a turn and a tool slot.
        for tool in await handler.list_tools():
            provider = handler._route[tool.name]  # noqa: SLF001 — no public accessor
            assert hasattr(provider, f"_{tool.name}"), f"{tool.name} has no handler"


# ====================================================================== #
#  Operator switches that withhold a tool
# ====================================================================== #

def _handler_with(config: Any, log_path: Path, tickets: Any) -> ToolHandler:
    """Build the real dispatcher around a one-off config."""
    from localhands.security import OperationLogger, PathGuard

    return ToolHandler(
        config, PathGuard(config), OperationLogger(str(log_path), max_bytes=0), tickets
    )


class TestScreenshotCanBeDisabled:
    """``screenshot_enabled: false`` has to actually remove the capability.

    Screen capture is the one tool that can send content the task never named —
    whatever happens to be on the user's monitors. An operator who sets the flag
    and is not obeyed is worse off than one who was never offered it, so both
    the advertised list and the call path are asserted here.
    """

    async def test_screenshot_is_advertised_by_default(
        self, handler: ToolHandler
    ) -> None:
        assert "screenshot" in [t.name for t in await handler.list_tools()]

    async def test_disabling_it_withholds_the_schema(
        self, make_config: Any, log_path: Path, tickets: Any
    ) -> None:
        handler = _handler_with(make_config(screenshot_enabled=False), log_path, tickets)
        assert "screenshot" not in [t.name for t in await handler.list_tools()]

    async def test_disabling_it_leaves_no_route_to_call(
        self, make_config: Any, log_path: Path, tickets: Any
    ) -> None:
        # A client holding a cached tool list must not reach the screen just
        # because it never re-read list_tools.
        handler = _handler_with(make_config(screenshot_enabled=False), log_path, tickets)
        result = json.loads((await handler.call_tool("screenshot", {})).content[0].text)
        assert result["status"] == "error"

    async def test_the_provider_itself_refuses_when_disabled(
        self, make_config: Any, log_path: Path, tickets: Any
    ) -> None:
        # Defence in depth: the withheld schema is the first line, but the
        # handler must not capture the screen even if something calls it.
        from localhands.security import OperationLogger, PathGuard
        from localhands.tools.base import ProviderContext
        from localhands.tools.media import MediaProvider

        config = make_config(screenshot_enabled=False)
        provider = MediaProvider(ProviderContext(
            config=config,
            guard=PathGuard(config),
            op_logger=OperationLogger(str(log_path), max_bytes=0),
            tickets=tickets,
        ))
        assert await provider.call("screenshot", {}) == {
            "status": "error",
            "error": "Screen capture is disabled on this server (screenshot_enabled: false).",
            "error_type": "ToolDisabled",
        }

    async def test_disabling_it_leaves_every_other_media_tool_alone(
        self, make_config: Any, log_path: Path, tickets: Any
    ) -> None:
        handler = _handler_with(make_config(screenshot_enabled=False), log_path, tickets)
        names = [t.name for t in await handler.list_tools()]
        assert {"read_image", "process_image", "image_info"} <= set(names)


# ====================================================================== #
#  Whitelist enforcement across every path-taking tool
# ====================================================================== #

# (tool, argument holding the path, other required arguments, path is a dir)
_PATH_TOOLS: list[tuple[str, str, dict[str, Any], bool]] = [
    ("read_file", "path", {}, False),
    ("write_file", "path", {"content": "x"}, False),
    ("edit_file", "path", {"old_string": "a", "new_string": "b"}, False),
    ("glob", "path", {"pattern": "*"}, True),
    ("grep", "path", {"pattern": "x"}, True),
    ("list_directory", "path", {}, True),
    ("get_project_tree", "path", {}, True),
    ("run_bash", "cwd", {"command": "echo hi"}, True),
    ("prepare_download", "path", {}, False),
    ("prepare_upload", "dest_path", {}, False),
]


@pytest.mark.parametrize(
    ("tool", "path_key", "extra", "is_dir"),
    _PATH_TOOLS,
    ids=[t[0] for t in _PATH_TOOLS],
)
async def test_tool_refuses_a_path_outside_the_whitelist(
    tool: str,
    path_key: str,
    extra: dict[str, Any],
    is_dir: bool,
    call_tool: Call,
    outside_root: Path,
) -> None:
    """Every tool that accepts a path enforces the whitelist.

    One tool that forgets is enough to make the whole boundary decorative, and
    a new tool is exactly the kind of change that forgets — hence the sweep
    rather than one test per tool.
    """
    target = outside_root if is_dir else outside_root / "secret.txt"
    result = await call_tool(tool, {path_key: str(target), **extra})

    assert result["status"] == "error"
    assert result["error_type"] == "PathGuardError"


@pytest.mark.parametrize(
    ("tool", "path_key", "extra", "is_dir"),
    _PATH_TOOLS,
    ids=[t[0] for t in _PATH_TOOLS],
)
async def test_tool_refuses_a_symlink_that_escapes_the_whitelist(
    tool: str,
    path_key: str,
    extra: dict[str, Any],
    is_dir: bool,
    call_tool: Call,
    allowed_root: Path,
    outside_root: Path,
    make_symlink: Callable[[Path, Path], Path],
) -> None:
    """A link inside the whitelist pointing out of it is still outside it.

    The link's own path passes any textual check, so this is the case a
    string-prefix implementation would wave through.
    """
    link = make_symlink(allowed_root / "hatch", outside_root)
    target = link if is_dir else link / "secret.txt"
    result = await call_tool(tool, {path_key: str(target), **extra})

    assert result["error_type"] == "PathGuardError"
