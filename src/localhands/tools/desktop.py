"""Desktop interaction: open a file with its default app, or interrupt a human.

Every other provider in this daemon assumes the only reader is the connected
agent.  These two tools exist because the agent is working on somebody's actual
machine, where "the report is ready" is worthless if nobody is looking at the
transcript.  They are the daemon's only channel to the person sitting there.

Both are best-effort and non-blocking by construction: a tool that pops a modal
dialog and then waits for it would hold the MCP request — and with it the
agent — hostage until a human happened to click OK.
"""

from __future__ import annotations

import ctypes  # windll is touched only under a sys.platform guard
import logging
import os
import subprocess
import sys
import threading
from typing import Any

from mcp.types import Tool

from ..security import PathGuardError
from .base import LocalProvider, err, ok

try:
    import winsound
except ImportError:  # non-Windows — notify still works, just silently
    winsound = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Long strings make MessageBoxW unreadable rather than failing, so they are
# trimmed here instead of rejected — a truncated alert still gets attention.
MAX_TITLE_CHARS = 120
MAX_MESSAGE_CHARS = 2000

# MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST — the last two
# matter because the dialog is raised by a background service the user is not
# looking at, and would otherwise open behind whatever they are doing.
_MB_FLAGS = 0x00000000 | 0x00000040 | 0x00010000 | 0x00040000


class DesktopProvider(LocalProvider):
    """Tools that act on the local desktop session: open files, raise alerts."""

    name = "desktop"

    tools: list[Tool] = [
    Tool(
        name="open_path",
        description=(
            "Open a file or folder on the LOCAL machine with whatever "
            "application the OS associates with it — a PDF in the PDF reader, "
            "a folder in the file manager, an .xlsx in Excel.\n"
            "\n"
            "This launches a GUI application on the user's desktop and puts a "
            "window in front of them, so use it when a human is meant to look "
            "at the result, not as a way to inspect a file yourself (use "
            "read_file or prepare_download for that).\n"
            "\n"
            "Returns as soon as the handler is launched; it does not wait for "
            "the application to start or for the user to close it. The path "
            "must exist and be inside an allowed directory."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File or folder to open with the OS default handler.",
                },
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="notify",
        description=(
            "Show a desktop alert on the LOCAL machine to get the user's "
            "attention. Use it when a long task finishes, when you need a "
            "decision before continuing, or when something failed in a way the "
            "user should know about now rather than whenever they next read "
            "the transcript.\n"
            "\n"
            "The dialog is displayed asynchronously: this returns immediately, "
            "and the alert stays on screen until the user dismisses it. It is "
            "therefore fire-and-forget — it cannot report back whether the user "
            "saw or acknowledged it.\n"
            "\n"
            "Keep the title short and put the detail in the message; "
            "over-long text is truncated rather than rejected."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": f"Alert title, one short line (truncated past {MAX_TITLE_CHARS} chars).",
                },
                "message": {
                    "type": "string",
                    "description": f"Alert body (truncated past {MAX_MESSAGE_CHARS} chars).",
                },
                "sound": {
                    "type": "boolean",
                    "description": "Play the system notification sound. Default true.",
                    "default": True,
                },
            },
            "required": ["title", "message"],
        },
    ),
    ]

    # ------------------------------------------------------------------ #
    #  Tool: open_path
    # ------------------------------------------------------------------ #

    def _open_path(self, path: str) -> dict[str, Any]:
        """Open a file or folder with the operating system's default handler."""
        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        if not resolved.exists():
            return err(f"Path not found: {resolved}", "FileNotFound")

        target = str(resolved)
        try:
            if sys.platform == "win32":
                handler = "os.startfile"
                os.startfile(target)  # noqa: S606 — launching the user's default app is the point
            else:
                # Kept portable so the module imports and behaves sanely if the
                # daemon is ever run somewhere other than this Windows box.
                handler = "open" if sys.platform == "darwin" else "xdg-open"
                subprocess.Popen(  # noqa: S603 — fixed argv, path is PathGuard-checked
                    [handler, target],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except FileNotFoundError:
            return err(f"No desktop handler available ({handler} not found).", "HandlerNotFound")
        except OSError as e:
            return err(f"Failed to open {target}: {e}", "OpenError")

        logger.info("Opened %s with %s", target, handler)
        return ok(
            path=target,
            kind="directory" if resolved.is_dir() else "file",
            handler=handler,
            note="Launched a GUI application on the user's desktop; not waited for.",
        )

    # ------------------------------------------------------------------ #
    #  Tool: notify
    # ------------------------------------------------------------------ #

    def _notify(self, title: str, message: str, sound: bool = True) -> dict[str, Any]:
        """Raise a desktop alert and return without waiting for it to be dismissed."""
        clean_title, title_cut = _clip(str(title), MAX_TITLE_CHARS)
        clean_message, message_cut = _clip(str(message), MAX_MESSAGE_CHARS)

        if sys.platform == "win32":
            if sound and winsound is not None:
                try:
                    winsound.MessageBeep(winsound.MB_ICONASTERISK)
                except RuntimeError:  # no audio device, or session has no sound
                    logger.debug("MessageBeep failed", exc_info=True)

            # MessageBoxW blocks until the user clicks OK. On a daemon thread it
            # blocks nothing that matters: the tool returns now, and an
            # unanswered dialog cannot keep the process alive at shutdown.
            thread = threading.Thread(
                target=_show_message_box,
                args=(clean_title, clean_message),
                name="desktop-notify",
                daemon=True,
            )
            thread.start()
            mechanism = "MessageBoxW"
        else:
            result = _notify_posix(clean_title, clean_message)
            if result is not None:
                return result
            mechanism = "notify-send" if sys.platform.startswith("linux") else "osascript"

        return ok(
            title=clean_title,
            message=clean_message,
            mechanism=mechanism,
            sound=bool(sound) and sys.platform == "win32" and winsound is not None,
            truncated=title_cut or message_cut,
            note=(
                "The alert is being displayed asynchronously and stays up until "
                "the user dismisses it; this call did not wait for that."
            ),
        )


# ====================================================================== #
#  Module-level helpers
# ====================================================================== #

def _show_message_box(title: str, message: str) -> None:
    """Body of the notification thread — blocks until the user clicks OK."""
    try:
        ctypes.windll.user32.MessageBoxW(None, message, title, _MB_FLAGS)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — an orphan thread must not take the daemon with it
        logger.exception("Desktop notification failed to display")


def _notify_posix(title: str, message: str) -> dict[str, Any] | None:
    """Best-effort notification off Windows. Returns an error payload or ``None``."""
    if sys.platform == "darwin":
        script = f'display notification {_applescript(message)} with title {_applescript(title)}'
        argv = ["osascript", "-e", script]
    elif sys.platform.startswith("linux"):
        argv = ["notify-send", "--", title, message]
    else:
        return err(f"No notification mechanism for platform {sys.platform!r}.", "UnsupportedPlatform")

    try:
        subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return err(f"Notification helper {argv[0]!r} is not installed.", "HandlerNotFound")
    except OSError as e:
        return err(f"Failed to raise notification: {e}", "NotifyError")
    return None


def _applescript(text: str) -> str:
    """Quote a string for embedding in an AppleScript literal."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _clip(text: str, limit: int) -> tuple[str, bool]:
    """Trim text to ``limit`` characters, reporting whether anything was cut."""
    if len(text) <= limit:
        return text, False
    return text[: limit - 1] + "…", True
