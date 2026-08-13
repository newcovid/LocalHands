"""File reading, writing, editing, and relocation tools."""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.types import Tool

from ..security import PathGuardError
from .base import LocalProvider, err, ok
from .encryption import encrypted_error, head_is_encrypted, parse_markers, staging_dir

logger = logging.getLogger(__name__)

# A NUL byte in the first block is the classic "this is not text" signal; no
# real source file or document markup contains one.
_BINARY_PROBE_BYTES = 8192

# Batch read limits. The path cap is about the response, not the filesystem: a
# batch big enough to be worth splitting is also big enough to bury whatever the
# agent was actually looking for.
_MAX_BATCH_PATHS = 50
_DEFAULT_BATCH_BYTES = 65_536

# Decode failures that mean "the buffer ended mid-character" rather than "these
# bytes are not this encoding". Only the former is forgivable, and only at the
# very end of a byte-capped read.
_CUT_TAIL_REASONS = ("unexpected end of data", "incomplete multibyte sequence")


@dataclass(frozen=True)
class TextFile:
    """A file successfully decoded as text, plus how that decoding went."""

    path: Path
    text: str
    encoding: str
    size_bytes: int  # Size on disk, which exceeds len(text) when capped.
    truncated: bool


def _decode_text(raw: bytes, tail_may_be_cut: bool = False) -> tuple[str, str]:
    """Decode file bytes, reporting which codec actually succeeded.

    Legacy Chinese encodings are common here (files touched by older Windows
    tooling), so GBK is tried before giving up on a faithful decode.
    """
    for encoding in ("utf-8", "gbk"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError as e:
            # A byte cap can slice a multibyte character in half. Dropping that
            # trailing fragment keeps the file's real encoding in the result;
            # without it one cut character would push an ordinary UTF-8 file all
            # the way down to lossy replacement decoding.
            cut_tail = e.end >= len(raw) and any(r in e.reason for r in _CUT_TAIL_REASONS)
            if tail_may_be_cut and cut_tail:
                return raw[: e.start].decode(encoding), encoding
    return raw.decode("utf-8", errors="replace"), "utf-8 (with replacements)"


def _number_lines(lines: list[str], start: int = 0) -> str:
    """Prefix each line with its 1-based number, in read_file's exact layout."""
    return "".join(f"{start + i + 1:6d}→{line}" for i, line in enumerate(lines))


def _measure(path: Path) -> tuple[int, int]:
    """Return ``(file_count, total_bytes)`` for a file or a whole directory tree.

    Individual stat failures are skipped rather than raised: this figure is
    reported alongside an operation, and a permission quirk on one file should
    not turn a successful move into an error.
    """
    if not path.is_dir() or path.is_symlink():
        try:
            return 1, path.stat().st_size
        except OSError:
            return 1, 0

    files = total = 0
    for root, _dirs, names in os.walk(path):
        for name in names:
            files += 1
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
    return files, total


def _remove_tree(path: Path) -> None:
    """Delete a file or an entire directory, whichever the path turns out to be."""
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


class FileProvider(LocalProvider):
    """Reading, writing, and exact-string editing of local files."""

    name = "files"

    tools: list[Tool] = [
        Tool(
            name="read_file",
            description=(
                "Read a text file. Supports line-based pagination via offset "
                "(0-indexed first line) and limit (max lines). Line numbers are "
                "included by default so you can quote an exact snippet back to "
                "edit_file.\n"
                "\n"
                "Text only. For images, PDFs, archives, spreadsheets, or any "
                "other binary, use prepare_download instead — this tool will "
                "refuse them rather than return mojibake."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute or relative path to the file."},
                    "offset": {
                        "type": "integer",
                        "description": "Line number to start reading from (0-indexed). Default 0.",
                        "default": 0,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of lines to return. Default 1000.",
                        "default": 1000,
                    },
                    "line_numbers": {
                        "type": "boolean",
                        "description": "Prefix each line with its 1-based number. Default true.",
                        "default": True,
                    },
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="write_file",
            description=(
                "Write text to a file, replacing any existing content. Creates "
                "parent directories as needed. To modify part of an existing "
                "file, prefer edit_file — it will not clobber content you have "
                "not read."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file to write."},
                    "content": {"type": "string", "description": "Full content to write (overwrites existing file)."},
                },
                "required": ["path", "content"],
            },
        ),
        Tool(
            name="edit_file",
            description=(
                "Replace an exact string in a file.\n"
                "\n"
                "By default old_string must match EXACTLY ONCE; if it appears "
                "more than once the edit is refused so you can add surrounding "
                "context to disambiguate. Only set replace_all=true when you "
                "genuinely intend to change every occurrence — a rename, for "
                "example."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file to edit."},
                    "old_string": {"type": "string", "description": "Exact text to find, including indentation."},
                    "new_string": {"type": "string", "description": "Replacement text."},
                    "replace_all": {
                        "type": "boolean",
                        "description": (
                            "Replace every occurrence. Default false, which requires "
                            "a unique match."
                        ),
                        "default": False,
                    },
                },
                "required": ["path", "old_string", "new_string"],
            },
        ),
        Tool(
            name="multi_edit",
            description=(
                "Apply several exact-string replacements to ONE file in a single "
                "call, in the order given.\n"
                "\n"
                "All or nothing: every edit is validated against the running text "
                "first and the file is written only if all of them succeed. A "
                "failure reports which edit index failed and why, and leaves the "
                "file byte-for-byte unchanged.\n"
                "\n"
                "Each edit sees the result of the previous ones, so a later edit "
                "may legitimately match text an earlier edit produced. As in "
                "edit_file, each old_string must match EXACTLY ONCE unless that "
                "edit sets replace_all=true.\n"
                "\n"
                "Prefer this over a run of edit_file calls on the same file: one "
                "round trip instead of several, and no half-edited intermediate "
                "state if one of them turns out not to match."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file to edit."},
                    "edits": {
                        "type": "array",
                        "description": "Replacements to apply, in order.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "old_string": {
                                    "type": "string",
                                    "description": "Exact text to find, including indentation.",
                                },
                                "new_string": {"type": "string", "description": "Replacement text."},
                                "replace_all": {
                                    "type": "boolean",
                                    "description": (
                                        "Replace every occurrence for this edit. Default "
                                        "false, which requires a unique match."
                                    ),
                                    "default": False,
                                },
                            },
                            "required": ["old_string", "new_string"],
                        },
                    },
                },
                "required": ["path", "edits"],
            },
        ),
        Tool(
            name="read_many_files",
            description=(
                "Read several text files in one call. Every path gets its own "
                "result entry, so a missing, binary, or encrypted file reports "
                "its own error instead of failing the whole batch.\n"
                "\n"
                "Use this whenever you want more than one file: each tool call is "
                "a full round trip, so one batch of ten files is far cheaper than "
                "ten read_file calls. Stay with read_file when you need "
                "pagination (offset/limit) inside one large file.\n"
                "\n"
                f"At most {_MAX_BATCH_PATHS} paths per call, each truncated at "
                "max_bytes_each. The response reports total_bytes so the cost of "
                "the call is visible."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": f"File paths to read. Maximum {_MAX_BATCH_PATHS}.",
                    },
                    "max_bytes_each": {
                        "type": "integer",
                        "description": (
                            f"Byte cap applied to each file separately. Default "
                            f"{_DEFAULT_BATCH_BYTES}."
                        ),
                        "default": _DEFAULT_BATCH_BYTES,
                    },
                    "line_numbers": {
                        "type": "boolean",
                        "description": (
                            "Prefix each line with its 1-based number. Default false "
                            "— turn it on when you intend to quote a snippet back to "
                            "edit_file."
                        ),
                        "default": False,
                    },
                },
                "required": ["paths"],
            },
        ),
        Tool(
            name="move_path",
            description=(
                "Move or rename a file or a whole directory.\n"
                "\n"
                "dest is the complete new path, NOT a folder to drop the source "
                "into: moving 'a.txt' to 'sub' produces a file named 'sub', not "
                "'sub/a.txt'. Missing parent directories of dest are created.\n"
                "\n"
                "An existing dest is refused (DestinationExists) unless "
                "overwrite=true — and overwrite DELETES whatever is already "
                "there, including an entire directory tree, before moving. "
                "Moving a directory into its own subtree is always refused."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "src": {"type": "string", "description": "Existing file or directory to move."},
                    "dest": {"type": "string", "description": "Complete destination path, including the new name."},
                    "overwrite": {
                        "type": "boolean",
                        "description": (
                            "Replace an existing destination, deleting it first. "
                            "Default false."
                        ),
                        "default": False,
                    },
                },
                "required": ["src", "dest"],
            },
        ),
        Tool(
            name="copy_path",
            description=(
                "Copy a file, or recursively copy a directory tree.\n"
                "\n"
                "dest is the complete new path, NOT a folder to copy into. "
                "Missing parent directories of dest are created. Metadata "
                "(timestamps, mode) is preserved.\n"
                "\n"
                "An existing dest is refused (DestinationExists) unless "
                "overwrite=true — and overwrite DELETES whatever is already "
                "there, including an entire directory tree, before copying. "
                "Copying a directory into its own subtree is always refused."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "src": {"type": "string", "description": "Existing file or directory to copy."},
                    "dest": {"type": "string", "description": "Complete destination path, including the new name."},
                    "overwrite": {
                        "type": "boolean",
                        "description": (
                            "Replace an existing destination, deleting it first. "
                            "Default false."
                        ),
                        "default": False,
                    },
                },
                "required": ["src", "dest"],
            },
        ),
        Tool(
            name="delete_path",
            description=(
                "Delete a file or directory.\n"
                "\n"
                "By default the delete is RECOVERABLE: the target is moved into "
                "the server's trash directory under a timestamped folder, and the "
                "result returns trash_path, which move_path can put back. "
                "permanent=true instead unlinks the target for real and NOTHING "
                "can restore it — only pass it when permanent destruction is "
                "explicitly what was asked for. If the server has no trash "
                "directory configured every delete is permanent, and the result "
                "says so.\n"
                "\n"
                "A non-empty directory is refused (DirectoryNotEmpty) unless "
                "recursive=true, which takes everything underneath it."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File or directory to delete."},
                    "recursive": {
                        "type": "boolean",
                        "description": (
                            "Required to delete a directory that is not empty. "
                            "Default false."
                        ),
                        "default": False,
                    },
                    "permanent": {
                        "type": "boolean",
                        "description": (
                            "Skip the trash directory and unlink irreversibly. "
                            "Default false."
                        ),
                        "default": False,
                    },
                },
                "required": ["path"],
            },
        ),
    ]

    # ------------------------------------------------------------------ #
    #  Shared helpers
    # ------------------------------------------------------------------ #

    def _read_text_file(
        self,
        resolved: Path,
        max_bytes: int | None = None,
    ) -> TextFile | dict[str, Any]:
        """Read one file as text, or return the error payload explaining why not.

        Shared by read_file, read_many_files, and multi_edit so that an
        encrypted, binary, or GBK-encoded file gets an identical verdict
        whichever tool ran into it — the tools differ only in what they do with
        the text afterwards.

        Returns an error dict rather than raising, because every caller forwards
        it straight back as (part of) the tool result.
        """
        if not resolved.exists():
            return err(f"File not found: {resolved}", "FileNotFound")
        if not resolved.is_file():
            return err(f"Not a regular file: {resolved}", "NotAFile")

        try:
            size = resolved.stat().st_size
            with resolved.open("rb") as fh:
                raw = fh.read() if max_bytes is None else fh.read(max_bytes)
        except OSError as e:
            return err(f"Failed to read file: {e}", "ReadError")

        # Order matters: an encrypted file is also "binary", but the encryption
        # message tells the agent something it can act on, so test for it first.
        markers = parse_markers(self.config.encrypted_file_markers)
        if head_is_encrypted(raw[:16], markers):
            return encrypted_error(resolved, staging_dir(self.config.staging_dir))

        if b"\x00" in raw[:_BINARY_PROBE_BYTES]:
            return err(
                f"{resolved.name} is a binary file, not text.",
                "BinaryFile",
                path=str(resolved),
                size_bytes=size,
                remedy=(
                    "Use prepare_download to fetch the raw bytes over HTTP. "
                    "Decoding this as text would return meaningless characters."
                ),
            )

        truncated = len(raw) < size
        text, encoding = _decode_text(raw, tail_may_be_cut=truncated)
        return TextFile(
            path=resolved,
            text=text,
            encoding=encoding,
            size_bytes=size,
            truncated=truncated,
        )

    def _check_relocation(
        self,
        src: str,
        dest: str,
        overwrite: bool,
    ) -> tuple[Path, Path, bool] | dict[str, Any]:
        """Validate a src/dest pair, returning ``(src, dest, replaced)`` or an error.

        Both sides go through the guard: a caller-supplied destination escapes
        the whitelist exactly as easily as a source does, and writing outside it
        is the more damaging of the two.

        On success the destination does not exist — an existing one has either
        been refused or (with ``overwrite``) already deleted, and ``replaced``
        records which.
        """
        try:
            src_path = self.guard.check(src)
        except PathGuardError as e:
            return err(str(e), "PathGuardError", side="src")
        try:
            dest_path = self.guard.check(dest)
        except PathGuardError as e:
            return err(str(e), "PathGuardError", side="dest")

        if not src_path.exists():
            return err(f"Source not found: {src_path}", "FileNotFound")
        if dest_path == src_path:
            return err(
                f"Source and destination are the same path: {src_path}",
                "InvalidDestination",
            )

        # A directory that contains its own destination either loses the data it
        # was supposed to preserve or recurses while copying, and the caller
        # cannot see either outcome until afterwards.
        if src_path.is_dir() and src_path in dest_path.parents:
            return err(
                f"Destination {dest_path} is inside the source directory {src_path}. "
                "Choose a destination outside the tree being moved or copied.",
                "InvalidDestination",
            )

        replaced = dest_path.exists()
        if replaced:
            if not overwrite:
                return err(
                    f"Destination already exists: {dest_path}. Pass overwrite=true "
                    "to replace it, or choose another destination.",
                    "DestinationExists",
                )
            try:
                # Clearing the destination up front also keeps shutil.move off
                # its "drop the source inside the existing directory" branch,
                # which would silently produce dest/<name> instead of dest.
                _remove_tree(dest_path)
            except OSError as e:
                return err(f"Failed to replace existing destination: {e}", "WriteError")

        try:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return err(f"Failed to create destination directory: {e}", "WriteError")

        return src_path, dest_path, replaced

    def _trash_root(self) -> Path | None:
        """Resolve the recycle-bin directory, creating it on demand.

        Returns None only when ``trash_dir`` is unset, which is the operator's
        way of saying deletes are permanent. A directory that cannot be created
        raises instead, so a broken configuration can never be mistaken for that
        choice and quietly upgrade a delete to irreversible.

        Deliberately not passed through the path guard: trash_dir is server
        configuration, not caller input, and an operator who parks the bin
        outside allowed_paths still expects deletes to land in it.
        """
        configured = (self.config.trash_dir or "").strip()
        if not configured:
            return None

        expanded = Path(os.path.expandvars(configured)).expanduser()
        # A relative trash_dir belongs to the daemon's working directory, not to
        # whichever directory the file being deleted happened to live in.
        root = expanded if expanded.is_absolute() else Path.cwd() / expanded
        root = root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    # ------------------------------------------------------------------ #
    #  Tool: read_file
    # ------------------------------------------------------------------ #

    def _read_file(
        self,
        path: str,
        offset: int = 0,
        limit: int = 1000,
        line_numbers: bool = True,
    ) -> dict[str, Any]:
        """Read a text file with optional line-based pagination."""
        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        loaded = self._read_text_file(resolved)
        if isinstance(loaded, dict):
            return loaded

        lines = loaded.text.splitlines(keepends=True)
        total_lines = len(lines)
        start = max(0, offset)
        end = min(total_lines, start + max(1, limit))
        selected = lines[start:end]

        body = _number_lines(selected, start) if line_numbers else "".join(selected)

        # Truncate on a byte boundary, then drop any partial character. Slicing
        # by character count while comparing byte counts under-counts multibyte
        # text badly enough to blow the cap on Chinese content.
        encoded = body.encode("utf-8")
        truncated = len(encoded) > self.config.max_file_size
        if truncated:
            body = encoded[: self.config.max_file_size].decode("utf-8", errors="ignore")
            encoded = body.encode("utf-8")

        return ok(
            path=str(resolved),
            content=body,
            encoding=loaded.encoding,
            offset=start,
            lines_returned=len(selected),
            total_lines=total_lines,
            bytes_returned=len(encoded),
            truncated=truncated,
            has_more=end < total_lines,
        )

    # ------------------------------------------------------------------ #
    #  Tool: write_file
    # ------------------------------------------------------------------ #

    def _write_file(self, path: str, content: str) -> dict[str, Any]:
        """Write content to a file (overwrite mode), creating parent dirs."""
        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        content_bytes = len(content.encode("utf-8"))
        limit = self.config.max_file_size * 10
        if content_bytes > limit:
            return err(
                f"Content too large ({content_bytes:,} bytes). Limit: {limit:,} bytes.",
                "ContentTooLarge",
            )

        if resolved.exists() and resolved.is_dir():
            return err(f"Path is a directory: {resolved}", "NotAFile")

        existed = resolved.exists()
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            # newline="" disables universal-newline translation. Without it
            # every LF becomes CRLF on Windows, so content the caller supplied
            # as LF silently lands as CRLF and bytes_written no longer matches
            # the file on disk.
            resolved.write_text(content, encoding="utf-8", newline="")
        except OSError as e:
            return err(f"Failed to write file: {e}", "WriteError")

        return ok(
            path=str(resolved),
            bytes_written=content_bytes,
            action="overwritten" if existed else "created",
        )

    # ------------------------------------------------------------------ #
    #  Tool: edit_file
    # ------------------------------------------------------------------ #

    def _edit_file(
        self,
        path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
    ) -> dict[str, Any]:
        """Replace an exact string in a file.

        ``replace_all`` defaults to False: requiring a unique match means an
        imprecise old_string fails loudly instead of silently rewriting every
        occurrence in the file. The caller driving this is a remote model, and a
        too-broad match is not something it can detect afterwards.
        """
        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        if not resolved.exists():
            return err(f"File not found: {resolved}", "FileNotFound")
        if not resolved.is_file():
            return err(f"Not a regular file: {resolved}", "NotAFile")

        try:
            raw = resolved.read_bytes()
        except OSError as e:
            return err(f"Failed to read file: {e}", "ReadError")

        markers = parse_markers(self.config.encrypted_file_markers)
        if head_is_encrypted(raw[:16], markers):
            return encrypted_error(resolved, staging_dir(self.config.staging_dir))

        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            return err(f"File is not valid UTF-8 text: {e}", "ReadError")

        if old_string == new_string:
            return err("old_string and new_string are identical.", "NoOpEdit")

        count = content.count(old_string)
        if count == 0:
            return err(
                "old_string not found in file. Check whitespace and indentation "
                "against what read_file returned.",
                "StringNotFound",
            )

        if not replace_all and count > 1:
            return err(
                f"old_string appears {count} times but replace_all is false. "
                "Include surrounding lines to make the match unique, or set "
                "replace_all=true if every occurrence should change.",
                "AmbiguousMatch",
                occurrences=count,
            )

        new_content = content.replace(old_string, new_string) if replace_all \
            else content.replace(old_string, new_string, 1)
        replaced = count if replace_all else 1

        try:
            # newline="" for the same reason as write_file, and here it also
            # compounds: the read preserves existing CRLF, so translating on
            # write turns each one into CR-CR-LF, then CR-CR-CR-LF on the next
            # edit, degrading every line of the file on each call.
            resolved.write_text(new_content, encoding="utf-8", newline="")
        except OSError as e:
            return err(f"Failed to write file: {e}", "WriteError")

        return ok(path=str(resolved), replacements=replaced)

    # ------------------------------------------------------------------ #
    #  Tool: multi_edit
    # ------------------------------------------------------------------ #

    def _multi_edit(self, path: str, edits: list[dict[str, Any]]) -> dict[str, Any]:
        """Apply an ordered list of exact-string replacements to one file.

        Atomic by construction: the edits run against an in-memory copy and the
        file is written only once every one of them has succeeded. A partially
        applied list would leave the file in a state the caller never requested
        and cannot reconstruct from the error, which is far worse than a clean
        refusal it can retry.
        """
        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        if not isinstance(edits, list) or not edits:
            return err(
                "edits must be a non-empty array of {old_string, new_string} objects.",
                "InvalidArguments",
            )

        loaded = self._read_text_file(resolved)
        if isinstance(loaded, dict):
            return loaded
        if loaded.encoding != "utf-8":
            # Editing writes the file back as UTF-8. For anything that only
            # decoded via GBK or replacement characters, that silently rewrites
            # every byte in the file, not just the requested spans.
            return err(
                f"File is not valid UTF-8 text (decoded as {loaded.encoding}). "
                "Editing it would rewrite the entire file in a different encoding.",
                "ReadError",
            )

        def fail(message: str, error_type: str, **fields: Any) -> dict[str, Any]:
            """Reject the batch, stating the guarantee the caller depends on."""
            return err(message, error_type, file_unchanged=True, **fields)

        content = loaded.text
        applied: list[dict[str, Any]] = []

        for index, edit in enumerate(edits):
            if not isinstance(edit, dict):
                return fail(
                    f"edits[{index}] must be an object with old_string and new_string.",
                    "InvalidArguments",
                    edit_index=index,
                )
            old_string = edit.get("old_string")
            new_string = edit.get("new_string")
            if not isinstance(old_string, str) or not isinstance(new_string, str):
                return fail(
                    f"edits[{index}] needs both old_string and new_string as strings.",
                    "InvalidArguments",
                    edit_index=index,
                )
            replace_all = bool(edit.get("replace_all", False))

            if old_string == new_string:
                return fail(
                    f"edits[{index}]: old_string and new_string are identical.",
                    "NoOpEdit",
                    edit_index=index,
                )

            count = content.count(old_string)
            if count == 0:
                # The earlier edits had already been applied to the text this one
                # searched, so their output is the first thing to suspect.
                prior = (
                    f" Edits 0..{index - 1} had already been applied to the text "
                    "this one searched, so check what they produced first."
                    if index
                    else ""
                )
                return fail(
                    f"edits[{index}]: old_string not found. Check whitespace and "
                    f"indentation against what read_file returned.{prior}",
                    "StringNotFound",
                    edit_index=index,
                )
            if not replace_all and count > 1:
                return fail(
                    f"edits[{index}]: old_string appears {count} times but replace_all "
                    "is false. Include surrounding lines to make the match unique, or "
                    "set replace_all=true on this edit if every occurrence should change.",
                    "AmbiguousMatch",
                    edit_index=index,
                    occurrences=count,
                )

            content = (
                content.replace(old_string, new_string)
                if replace_all
                else content.replace(old_string, new_string, 1)
            )
            applied.append({"index": index, "replacements": count if replace_all else 1})

        try:
            # newline="" writes the string through unchanged. Text mode would
            # re-translate every "\n" that came out of a CRLF file into "\r\n",
            # doubling its carriage returns — a file asked to change in two
            # places would come back with every line rewritten.
            resolved.write_text(content, encoding="utf-8", newline="")
        except OSError as e:
            return err(f"Failed to write file: {e}", "WriteError", file_unchanged=True)

        return ok(
            path=str(resolved),
            edits_applied=len(applied),
            replacements=sum(a["replacements"] for a in applied),
            per_edit=applied,
            bytes_written=len(content.encode("utf-8")),
        )

    # ------------------------------------------------------------------ #
    #  Tool: read_many_files
    # ------------------------------------------------------------------ #

    def _read_many_files(
        self,
        paths: list[str],
        max_bytes_each: int = _DEFAULT_BATCH_BYTES,
        line_numbers: bool = False,
    ) -> dict[str, Any]:
        """Read several files, reporting success or failure for each one.

        The batch never fails as a whole for a single bad path: the agent asked
        for N files, and losing the other N-1 to one missing or binary file
        costs it another full round trip to find out which one was at fault.
        """
        if not isinstance(paths, list) or not paths:
            return err("paths must be a non-empty array of file paths.", "InvalidArguments")
        if len(paths) > _MAX_BATCH_PATHS:
            return err(
                f"{len(paths)} paths requested; the limit is {_MAX_BATCH_PATHS} per "
                "call. Split them across several calls.",
                "TooManyPaths",
                limit=_MAX_BATCH_PATHS,
            )

        # Clamped to the server's single-file limit so a generous max_bytes_each
        # cannot turn one batch into more context than read_file would ever return.
        cap = max(1, min(int(max_bytes_each), self.config.max_file_size))

        results: list[dict[str, Any]] = []
        total_bytes = 0

        for raw_path in paths:
            requested = str(raw_path)
            try:
                resolved = self.guard.check(requested)
            except PathGuardError as e:
                results.append({"path": requested, **err(str(e), "PathGuardError")})
                continue

            loaded = self._read_text_file(resolved, max_bytes=cap)
            if isinstance(loaded, dict):
                results.append({"path": str(resolved), **loaded})
                continue

            lines = loaded.text.splitlines(keepends=True)
            body = _number_lines(lines) if line_numbers else loaded.text
            total_bytes += len(body.encode("utf-8"))
            results.append(
                ok(
                    path=str(resolved),
                    content=body,
                    encoding=loaded.encoding,
                    lines=len(lines),
                    size_bytes=loaded.size_bytes,
                    truncated=loaded.truncated,
                )
            )

        succeeded = sum(1 for r in results if r["status"] == "success")
        return ok(
            files=results,
            requested=len(paths),
            succeeded=succeeded,
            failed=len(results) - succeeded,
            total_bytes=total_bytes,
            max_bytes_each=cap,
        )

    # ------------------------------------------------------------------ #
    #  Tool: move_path
    # ------------------------------------------------------------------ #

    def _move_path(self, src: str, dest: str, overwrite: bool = False) -> dict[str, Any]:
        """Move or rename a file or directory tree."""
        checked = self._check_relocation(src, dest, overwrite)
        if isinstance(checked, dict):
            return checked
        src_path, dest_path, replaced = checked

        is_dir = src_path.is_dir() and not src_path.is_symlink()
        # Measured first: after the move there is nothing left at src to count.
        files, size_bytes = _measure(src_path)

        try:
            # shutil.move falls back to copy-then-delete when the two sides sit
            # on different drives — routine when the whitelist spans volumes,
            # and exactly the case a bare os.replace would fail.
            shutil.move(str(src_path), str(dest_path))
        except (OSError, shutil.Error) as e:
            return err(f"Failed to move: {e}", "MoveError")

        return ok(
            src=str(src_path),
            dest=str(dest_path),
            kind="directory" if is_dir else "file",
            files=files,
            size_bytes=size_bytes,
            replaced_existing=replaced,
        )

    # ------------------------------------------------------------------ #
    #  Tool: copy_path
    # ------------------------------------------------------------------ #

    def _copy_path(self, src: str, dest: str, overwrite: bool = False) -> dict[str, Any]:
        """Copy a file, or recursively copy a directory tree."""
        checked = self._check_relocation(src, dest, overwrite)
        if isinstance(checked, dict):
            return checked
        src_path, dest_path, replaced = checked

        is_dir = src_path.is_dir() and not src_path.is_symlink()
        try:
            if is_dir:
                shutil.copytree(src_path, dest_path)
            else:
                shutil.copy2(src_path, dest_path)
        except (OSError, shutil.Error) as e:
            return err(f"Failed to copy: {e}", "CopyError")

        # Counted on the destination rather than the source, so the figure
        # reports what actually landed.
        files, size_bytes = _measure(dest_path)
        return ok(
            src=str(src_path),
            dest=str(dest_path),
            kind="directory" if is_dir else "file",
            files=files,
            size_bytes=size_bytes,
            replaced_existing=replaced,
        )

    # ------------------------------------------------------------------ #
    #  Tool: delete_path
    # ------------------------------------------------------------------ #

    def _delete_path(
        self,
        path: str,
        recursive: bool = False,
        permanent: bool = False,
    ) -> dict[str, Any]:
        """Delete a file or directory, via the trash directory unless told otherwise.

        The caller is a remote model acting on inference, so the default is made
        undoable: an unrecoverable delete triggered by a misread instruction is
        the worst outcome this server can produce, and moving the target aside
        costs nothing that a later permanent delete cannot reclaim.
        """
        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        if not resolved.exists():
            return err(f"Path not found: {resolved}", "FileNotFound")

        # An allowed root is the workspace itself. Deleting one takes every
        # future call's working directory with it, and no plausible instruction
        # means it.
        if resolved in self.config.resolved_allowed_paths:
            return err(
                f"{resolved} is a configured allowed_paths root and cannot be "
                "deleted. Delete the entries inside it individually if that is "
                "genuinely the intent.",
                "ProtectedPath",
            )

        is_dir = resolved.is_dir() and not resolved.is_symlink()
        if is_dir and not recursive and any(resolved.iterdir()):
            return err(
                f"Directory is not empty: {resolved}. Pass recursive=true to delete "
                "it together with everything underneath it.",
                "DirectoryNotEmpty",
            )

        files, size_bytes = _measure(resolved)
        kind = "directory" if is_dir else "file"

        try:
            trash_root = self._trash_root()
        except OSError as e:
            return err(
                f"Cannot prepare the trash directory ({self.config.trash_dir}): {e}. "
                "Refusing to fall back to a permanent delete — fix the configuration, "
                "or pass permanent=true if destruction is genuinely intended.",
                "TrashUnavailable",
            )

        if permanent or trash_root is None:
            try:
                _remove_tree(resolved)
            except OSError as e:
                return err(f"Failed to delete: {e}", "DeleteError")

            result = ok(
                path=str(resolved),
                kind=kind,
                files=files,
                size_bytes=size_bytes,
                permanent=True,
                recoverable=False,
            )
            if not permanent:
                result["note"] = (
                    "No trash_dir is configured on this server, so there was no "
                    "recycle bin to move this into — the delete was permanent."
                )
            return result

        if trash_root == resolved or resolved in trash_root.parents:
            return err(
                f"The trash directory {trash_root} is inside {resolved}, so it "
                "cannot hold it. Pass permanent=true, or point trash_dir elsewhere.",
                "TrashUnavailable",
            )

        # One bucket per delete, named by timestamp: the original filename is
        # preserved inside it, and two deletes of the same name never collide.
        bucket = trash_root / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        trashed = bucket / resolved.name
        try:
            bucket.mkdir(parents=True, exist_ok=False)
            shutil.move(str(resolved), str(trashed))
        except (OSError, shutil.Error) as e:
            return err(f"Failed to move to trash: {e}", "DeleteError")

        return ok(
            path=str(resolved),
            kind=kind,
            files=files,
            size_bytes=size_bytes,
            permanent=False,
            recoverable=True,
            trash_path=str(trashed),
            restore_hint=(
                f"Call move_path with src={trashed} and dest={resolved} to put it back."
            ),
        )
