"""Binary transfer endpoints for the LocalHands daemon.

Why this exists
---------------
MCP moves tool arguments and results as text inside the model's context.  That
is fine for source files, but ruinous for binary payloads:

* **Model → local** (e.g. saving a generated image).  The model has to *emit*
  the base64 as a tool argument, so every byte becomes an **output** token.
  A 500 KB image is roughly 680 000 base64 characters — hundreds of thousands
  of output tokens, and tens of seconds of generation.  Unusable.
* **Local → model** (e.g. reading a screenshot).  The bytes arrive as a tool
  **result**.  If the client decodes MCP ``ImageContent`` into a real image the
  cost is only the image's inherent vision tokens, but clients that spool tool
  results to a JSON file and read them back as text pay full text price.

This module sidesteps both by never routing bytes through the model at all.
A tool call mints a one-time ticket and returns a plain URL; the agent moves the
file with ``curl`` in its own sandbox.  The only thing that enters the context is
a short URL, so transfer cost is a few dozen tokens regardless of file size.

The channel is deliberately format-agnostic — it carries PDFs, archives and
spreadsheets just as well as images, which is what makes ``read_file``'s
text-only limitation survivable.

Security model
--------------
These endpoints are *not* behind the bearer-token middleware, because the URL is
handed to a remote sandbox and would leak the long-lived token into that
sandbox's shell history.  The ticket in the path is the sole credential: 32
random bytes, bound to one file and one direction, valid once, for minutes.
Both minting and redemption re-check the path against ``PathGuard``.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import os
import time
from pathlib import Path
from typing import Any, Callable

from .config import Config
from .security import (
    OperationLogger,
    PathGuard,
    PathGuardError,
    TransferTicketError,
    TransferTicketStore,
)

logger = logging.getLogger(__name__)

# Chunk size for streaming file bodies in both directions.
CHUNK_SIZE = 64 * 1024

DOWNLOAD_PREFIX = "/download/"
UPLOAD_PREFIX = "/upload/"


class TransferEndpoints:
    """Raw-ASGI handlers for ``GET /download/<ticket>`` and ``PUT /upload/<ticket>``."""

    def __init__(
        self,
        config: Config,
        path_guard: PathGuard,
        tickets: TransferTicketStore,
        op_logger: OperationLogger,
    ) -> None:
        self.config = config
        self.guard = path_guard
        self.tickets = tickets
        self.logger = op_logger

    # ------------------------------------------------------------------ #
    #  Routing helper
    # ------------------------------------------------------------------ #

    @staticmethod
    def match(path: str, method: str) -> tuple[str, str] | None:
        """Return ``(kind, ticket_id)`` if the request targets a transfer endpoint."""
        if path.startswith(DOWNLOAD_PREFIX) and method == "GET":
            return "download", path[len(DOWNLOAD_PREFIX):]
        if path.startswith(UPLOAD_PREFIX) and method in ("PUT", "POST"):
            return "upload", path[len(UPLOAD_PREFIX):]
        return None

    async def handle(
        self,
        kind: str,
        ticket_id: str,
        scope: dict[str, Any],
        receive: Callable,
        send: Callable,
    ) -> None:
        """Dispatch to the download or upload handler, converting errors to HTTP."""
        start = time.monotonic()
        try:
            ticket = self.tickets.redeem(ticket_id, kind)
        except TransferTicketError as exc:
            # 403 rather than 404: the path shape was right, the credential was not.
            self.logger.log(
                tool=f"http_{kind}",
                arguments={"ticket": _mask(ticket_id)},
                status="error",
                duration_ms=(time.monotonic() - start) * 1000,
                error=str(exc),
            )
            await _send_json(send, 403, {"error": str(exc)})
            return

        # Re-validate at redemption time: the whitelist may have changed, or a
        # symlink may have been swapped in since the ticket was minted.
        try:
            resolved = self.guard.check(str(ticket.path))
        except PathGuardError as exc:
            await _send_json(send, 403, {"error": str(exc)})
            return

        try:
            if kind == "download":
                await self._download(resolved, send, start)
            else:
                await self._upload(resolved, ticket.max_bytes, receive, send, start)
        except Exception as exc:  # noqa: BLE001 — never leak a traceback to the wire
            logger.exception("Transfer %s failed for %s", kind, resolved)
            self.logger.log(
                tool=f"http_{kind}",
                arguments={"path": str(resolved)},
                status="error",
                duration_ms=(time.monotonic() - start) * 1000,
                error=str(exc),
            )
            await _send_json(send, 500, {"error": f"{type(exc).__name__}: {exc}"})

    # ------------------------------------------------------------------ #
    #  GET /download/<ticket>
    # ------------------------------------------------------------------ #

    async def _download(self, path: Path, send: Callable, start: float) -> None:
        """Stream a local file to the caller as raw bytes."""
        if not path.exists():
            await _send_json(send, 404, {"error": f"File not found: {path}"})
            return
        if not path.is_file():
            await _send_json(send, 400, {"error": f"Not a regular file: {path}"})
            return

        size = path.stat().st_size
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", mime.encode()),
                (b"content-length", str(size).encode()),
                # Latin-1 header safety: non-ASCII names go in the RFC 5987 form.
                (b"content-disposition", _content_disposition(path.name)),
                (b"cache-control", b"no-store"),
            ],
        })

        sent = 0
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                sent += len(chunk)
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

        self.logger.log(
            tool="http_download",
            arguments={"path": str(path)},
            status="success",
            duration_ms=(time.monotonic() - start) * 1000,
            result_summary=f"{sent} bytes, {mime}",
        )
        logger.info("Downloaded %s (%d bytes)", path, sent)

    # ------------------------------------------------------------------ #
    #  PUT | POST /upload/<ticket>
    # ------------------------------------------------------------------ #

    async def _upload(
        self,
        path: Path,
        max_bytes: int | None,
        receive: Callable,
        send: Callable,
        start: float,
    ) -> None:
        """Receive a raw request body and write it to a local file.

        Written to a sibling ``.part`` file and renamed on completion, so a
        dropped connection can never leave a truncated file at the target path.
        """
        limit = max_bytes if max_bytes is not None else self.config.upload_max_bytes
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".part")

        received = 0
        try:
            with tmp.open("wb") as fh:
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        raise ConnectionError("Client disconnected mid-upload")
                    if message["type"] != "http.request":
                        continue

                    chunk = message.get("body", b"")
                    if chunk:
                        received += len(chunk)
                        if received > limit:
                            raise ValueError(
                                f"Upload exceeds limit of {limit:,} bytes "
                                f"(received at least {received:,})"
                            )
                        fh.write(chunk)

                    if not message.get("more_body", False):
                        break
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

        existed = path.exists()
        os.replace(tmp, path)

        self.logger.log(
            tool="http_upload",
            arguments={"path": str(path)},
            status="success",
            duration_ms=(time.monotonic() - start) * 1000,
            result_summary=f"{received} bytes, {'overwritten' if existed else 'created'}",
        )
        logger.info("Uploaded %s (%d bytes)", path, received)

        await _send_json(send, 200, {
            "status": "success",
            "path": str(path),
            "bytes_written": received,
            "action": "overwritten" if existed else "created",
        })


# ====================================================================== #
#  Helpers
# ====================================================================== #

def _content_disposition(filename: str) -> bytes:
    """Build a Content-Disposition header that survives non-ASCII filenames.

    HTTP headers are latin-1; Chinese filenames would raise on encode.  The
    RFC 5987 ``filename*`` form carries the real name, with an ASCII-safe
    ``filename`` fallback for clients that ignore it.
    """
    from urllib.parse import quote

    ascii_name = filename.encode("ascii", "replace").decode("ascii").replace('"', "_")
    return (
        f'attachment; filename="{ascii_name}"; '
        f"filename*=UTF-8''{quote(filename, safe='')}"
    ).encode("latin-1")


async def _send_json(send: Callable, status: int, payload: dict[str, Any]) -> None:
    """Send a small JSON response over raw ASGI."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})


def _mask(ticket_id: str) -> str:
    """Show only enough of a ticket to correlate log lines."""
    return ticket_id[:8] + "..." if len(ticket_id) > 8 else ticket_id
