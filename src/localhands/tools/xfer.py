"""Binary transfer tools: mint one-time URLs for /download and /upload."""

from __future__ import annotations

import logging
import mimetypes
from typing import Any

from mcp.types import Tool

from ..security import PathGuardError
from .base import LocalProvider

logger = logging.getLogger(__name__)


class TransferProvider(LocalProvider):
    """Binary transfer tools: mint one-time URLs for /download and /upload."""

    # ngrok's free tier serves an HTML interstitial (ERR_NGROK_6024) to requests
    # that look like a browser. A default curl user-agent is not affected, but a
    # client that sends a browser-ish UA would silently download that HTML page
    # instead of the file. This header opts out unconditionally; other tunnel
    # providers ignore an unknown header, so it is safe to always suggest.
    _TUNNEL_HEADER = 'ngrok-skip-browser-warning: true'

    name = "transfer"

    tools: list[Tool] = [
    Tool(
        name="prepare_download",
        description=(
            "Get a temporary URL for fetching a LOCAL file as raw bytes. Use "
            "this for ANY binary file — images, PDFs, archives, spreadsheets — "
            "and for large text files.\n"
            "\n"
            "Call this, then run the exact command returned in the 'curl' field "
            "inside your own environment. Use that command verbatim — it carries "
            "a header needed to bypass the tunnel's browser check.\n"
            "The bytes travel over plain HTTP and never enter your context, so "
            "transfer costs nothing regardless of file size. Read the fetched "
            "file with your own tools afterwards (for an image, that means your "
            "normal image-viewing path).\n"
            "\n"
            "The URL works exactly ONCE and expires within minutes. Call this "
            "again to get a fresh one."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path of the local file to make downloadable."},
                "ttl_seconds": {
                    "type": "integer",
                    "description": "How long the URL stays valid. Default 300.",
                    "default": 300,
                },
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="prepare_upload",
        description=(
            "Get a temporary URL for writing a file TO the local machine as raw "
            "bytes. Use this to deliver any binary you produced — a generated "
            "image, a rendered PDF, an archive.\n"
            "\n"
            "Call this, then push the file with the command returned in the "
            "'curl' field, substituting your local filename. Use it verbatim "
            "otherwise — it carries a header needed to bypass the tunnel's "
            "browser check.\n"
            "\n"
            "ALWAYS prefer this over embedding base64 in a tool argument. Base64 "
            "in an argument has to be generated token by token: a 500 KB image "
            "becomes ~680,000 characters, costing hundreds of thousands of "
            "output tokens and tens of seconds. This URL costs nothing.\n"
            "\n"
            "The URL works exactly ONCE and expires within minutes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "dest_path": {"type": "string", "description": "Where the uploaded bytes should be written locally."},
                "ttl_seconds": {
                    "type": "integer",
                    "description": "How long the URL stays valid. Default 300.",
                    "default": 300,
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Reject uploads larger than this. Defaults to the server limit.",
                },
            },
            "required": ["dest_path"],
        },
    ),
    ]


    def _transfer_url(self, kind: str, ticket_id: str) -> str:
        """Build the URL the remote agent should curl.

        Falls back to a relative path when ``public_base_url`` is unset — the
        daemon has no reliable way to learn its own public origin (it sits
        behind a tunnel), so this has to be configured.
        """
        relative = f"/{kind}/{ticket_id}"
        base = self.config.public_base_url
        return f"{base}{relative}" if base else relative


    def _prepare_download(self, path: str, ttl_seconds: int = 300) -> dict[str, Any]:
        """Mint a one-time URL that serves a local file as raw bytes."""
        if self.tickets is None:
            return {
                "status": "error",
                "error": "Transfer channel is not available on this server.",
                "error_type": "TransferUnavailable",
            }
        try:
            resolved = self.guard.check(path)
        except PathGuardError as e:
            return {"status": "error", "error": str(e), "error_type": "PathGuardError"}

        if not resolved.exists():
            return {"status": "error", "error": f"File not found: {resolved}", "error_type": "FileNotFound"}
        if not resolved.is_file():
            return {"status": "error", "error": f"Not a regular file: {resolved}", "error_type": "NotAFile"}

        ttl = max(1, min(int(ttl_seconds), 3600))
        ticket_id, ticket = self.tickets.mint("download", resolved, ttl=ttl)
        size = resolved.stat().st_size
        mime = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
        url = self._transfer_url("download", ticket_id)

        result = {
            "status": "success",
            "url": url,
            "path": str(resolved),
            "filename": resolved.name,
            "size_bytes": size,
            "mime_type": mime,
            "expires_in_seconds": ttl,
            "single_use": True,
            "curl": f'curl -sSL -H "{self._TUNNEL_HEADER}" -o "{resolved.name}" "{url}"',
        }
        if not self.config.public_base_url:
            result["warning"] = (
                "public_base_url is not configured, so 'url' is only a path. "
                "Prefix it with the daemon's public origin."
            )
        return result


    def _prepare_upload(
        self,
        dest_path: str,
        ttl_seconds: int = 300,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        """Mint a one-time URL that writes raw request bytes to a local file."""
        if self.tickets is None:
            return {
                "status": "error",
                "error": "Transfer channel is not available on this server.",
                "error_type": "TransferUnavailable",
            }
        try:
            resolved = self.guard.check(dest_path)
        except PathGuardError as e:
            return {"status": "error", "error": str(e), "error_type": "PathGuardError"}

        if resolved.exists() and resolved.is_dir():
            return {
                "status": "error",
                "error": f"Destination is a directory: {resolved}",
                "error_type": "NotAFile",
            }

        ttl = max(1, min(int(ttl_seconds), 3600))
        limit = self.config.upload_max_bytes
        if max_bytes is not None:
            limit = max(1, min(int(max_bytes), self.config.upload_max_bytes))

        ticket_id, ticket = self.tickets.mint("upload", resolved, ttl=ttl, max_bytes=limit)
        url = self._transfer_url("upload", ticket_id)

        result = {
            "status": "success",
            "url": url,
            "dest_path": str(resolved),
            "max_bytes": limit,
            "expires_in_seconds": ttl,
            "single_use": True,
            "will_overwrite": resolved.exists(),
            "curl": f'curl -sSL -H "{self._TUNNEL_HEADER}" --upload-file "<your-local-file>" "{url}"',
        }
        if not self.config.public_base_url:
            result["warning"] = (
                "public_base_url is not configured, so 'url' is only a path. "
                "Prefix it with the daemon's public origin."
            )
        return result

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

