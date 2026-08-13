"""Shell command execution."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import sys
from typing import Any

from mcp.types import Tool

from ..security import CommandBlocked, CommandGuard, PathGuardError
from .base import BASH_OUTPUT_CAP, LocalProvider, ProviderContext, err, ok

logger = logging.getLogger(__name__)

# Console output on a Chinese Windows install is GBK far more often than UTF-8,
# but tools ported from Unix emit UTF-8. Try both before giving up; latin-1
# never fails, so it is the guaranteed terminator.
_DECODE_CHAIN = ("utf-8", "gbk", "latin-1")


def _decode(raw: bytes) -> tuple[str, str]:
    """Decode process output, returning ``(text, encoding_used)``."""
    for encoding in _DECODE_CHAIN:
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace"), "latin-1 (with replacements)"


def _process_group_kwargs() -> dict[str, Any]:
    """Popen kwargs that make the child killable as a whole tree."""
    if sys.platform == "win32":
        # A job-like grouping so taskkill /T can find the descendants.
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _kill_process_tree(proc: subprocess.Popen[bytes]) -> None:
    """Terminate a process and everything it spawned.

    Killing only the direct child leaves grandchildren running and still holding
    the inherited stdout pipe, which makes the timeout ineffective.
    """
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=10,
            )
            return
        except (OSError, subprocess.TimeoutExpired):
            pass  # Fall through to the direct kill below.
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return
        except (OSError, AttributeError):
            pass

    with contextlib.suppress(OSError):
        proc.kill()


class ShellProvider(LocalProvider):
    """Arbitrary shell command execution, behind a guard rail."""

    name = "shell"

    tools: list[Tool] = [
        Tool(
            name="run_bash",
            description=(
                "Execute a shell command and return stdout, stderr, and the exit "
                "code. Runs in the local system shell (cmd on Windows).\n"
                "\n"
                "Prefer the dedicated tools where one fits — read_file, write_file, "
                "edit_file, glob, grep — since they enforce the path whitelist and "
                "return structured results.\n"
                "\n"
                "A small set of irreversible commands (whole-disk operations, "
                "recursive deletion of a drive root, shutdown, piping a download "
                "into a shell) is refused outright."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute."},
                    "cwd": {"type": "string", "description": "Working directory. Default: first allowed path."},
                    "timeout": {"type": "integer", "description": "Timeout in seconds. Default 30.", "default": 30},
                },
                "required": ["command"],
            },
        ),
    ]

    def __init__(self, ctx: ProviderContext) -> None:
        super().__init__(ctx)
        self.command_guard = CommandGuard(
            enabled=ctx.config.command_guard_enabled,
            extra_patterns=ctx.config.denied_command_patterns,
        )

    # ------------------------------------------------------------------ #
    #  Tool: run_bash
    # ------------------------------------------------------------------ #

    def _run_bash(
        self,
        command: str,
        cwd: str | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Execute a shell command and return stdout, stderr, exit_code."""
        try:
            self.command_guard.check(command)
        except CommandBlocked as e:
            # Logged at warning level because this is the signal that the remote
            # agent tried something destructive — worth noticing in the log.
            logger.warning("Blocked command: %s", command)
            return err(str(e), "CommandBlocked", command=command)

        effective_timeout = timeout or self.config.bash_timeout
        effective_timeout = min(effective_timeout, self.config.bash_timeout * 2)

        work_dir = self._default_root
        if cwd:
            try:
                work_dir = self.guard.check(cwd)
            except PathGuardError as e:
                return err(str(e), "PathGuardError")

        try:
            proc = subprocess.Popen(  # noqa: S602 — arbitrary execution is this tool's purpose
                command,
                shell=True,
                cwd=str(work_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Bytes, not text: text mode decodes with the locale encoding and
                # raises or mangles whenever the command's actual encoding differs.
                env=dict(os.environ),
                **_process_group_kwargs(),
            )
        except OSError as e:
            return err(f"Failed to execute command: {e}", "ExecError")

        timed_out = False
        try:
            raw_out, raw_err = proc.communicate(timeout=effective_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # subprocess.run() would only kill the shell here. Under shell=True
            # the real work runs in a grandchild that inherited the stdout pipe,
            # so communicate() blocks until *that* finishes: a 1s timeout on a
            # 5s command returns after 5s, and a runaway command holds a worker
            # thread indefinitely. Killing the whole tree is what makes the
            # timeout an actual bound.
            _kill_process_tree(proc)
            try:
                raw_out, raw_err = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                raw_out, raw_err = b"", b""

        if timed_out:
            partial_out, _ = _decode(raw_out or b"")
            return err(
                f"Command timed out after {effective_timeout}s and its process "
                f"tree was killed.",
                "TimeoutError",
                command=command,
                cwd=str(work_dir),
                partial_stdout=partial_out[:BASH_OUTPUT_CAP],
            )

        stdout, out_encoding = _decode(raw_out or b"")
        stderr, _ = _decode(raw_err or b"")

        stdout_truncated = len(stdout) > BASH_OUTPUT_CAP
        if stdout_truncated:
            stdout = stdout[:BASH_OUTPUT_CAP] + f"\n...<truncated, {len(stdout)} chars total>"
        stderr_truncated = len(stderr) > BASH_OUTPUT_CAP
        if stderr_truncated:
            stderr = stderr[:BASH_OUTPUT_CAP] + f"\n...<truncated, {len(stderr)} chars total>"

        return ok(
            command=command,
            cwd=str(work_dir),
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            output_encoding=out_encoding,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )
