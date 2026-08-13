"""Outbound HTTP fetch: the daemon pulls a URL and writes it to local disk.

This is the mirror image of ``prepare_upload`` in :mod:`tools.xfer`.  There the
*agent* pushes bytes at the daemon; here the daemon fetches them itself, so a
public URL becomes a local file without a single byte passing through the
model's context.

Security note
-------------
The URL is chosen by a remote agent, which makes a naive implementation an SSRF
probe: ``http://127.0.0.1:8765/``, ``http://192.168.1.1/`` and friends are all
reachable from this process but not from the agent.  Every URL — including each
redirect hop — is therefore vetted for scheme, host, and *resolved address*
before a request is made.  Only hosts listed explicitly in
``download_allowed_hosts`` are exempt from the address check, on the grounds
that whoever wrote them into the config meant them.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from mcp.types import Tool

from ..security import PathGuardError
from .base import LocalProvider, err, ok

logger = logging.getLogger(__name__)

# Matches transfer.py so both directions move bytes in the same units.
CHUNK_SIZE = 64 * 1024

DEFAULT_MAX_BYTES = 52_428_800  # 50 MB
DEFAULT_TIMEOUT = 60.0
DEFAULT_SCHEMES = ["https", "http"]
MAX_REDIRECTS = 5

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class _DownloadTooLarge(Exception):
    """Raised internally when the body outgrows the ceiling mid-stream."""


class NetProvider(LocalProvider):
    """Network fetch tools: pull a remote URL straight onto local disk."""

    name = "net"

    # Identify the daemon rather than impersonating a browser; some hosts serve
    # different content to an unknown client, and a truthful UA makes the
    # traffic explicable in someone else's access log.
    _USER_AGENT = "localhands/1.0"

    tools: list[Tool] = [
    Tool(
        name="download_file",
        description=(
            "Fetch a URL and save it to a file on the LOCAL machine. The "
            "daemon does the fetching — the bytes never enter your context, so "
            "the transfer costs nothing regardless of file size.\n"
            "\n"
            "Use this whenever you have a public URL and want the file to land "
            "locally: an installer, a dataset, a PDF, a repository tarball. It "
            "is the opposite direction from prepare_upload, which is for bytes "
            "you produced yourself and must push to the daemon.\n"
            "\n"
            "The destination must be inside an allowed directory, and an "
            "existing file is left untouched unless overwrite is true. A failed "
            "or interrupted download never leaves a truncated file behind.\n"
            "\n"
            "Only public addresses are reachable: URLs resolving to loopback, "
            "link-local, or private ranges are refused (error_type "
            "'BlockedAddress') unless the host is whitelisted in the server "
            "config. Downloads are capped at a server-configured size."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "HTTP(S) URL to fetch. Redirects are followed and re-checked.",
                },
                "dest_path": {
                    "type": "string",
                    "description": "Local path to write the file to. Parent directories are created.",
                },
                "overwrite": {
                    "type": "boolean",
                    "description": "Replace dest_path if it already exists. Default false.",
                    "default": False,
                },
                "timeout": {
                    "type": "integer",
                    "description": "Per-operation timeout in seconds. Defaults to the server setting (60).",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": (
                        "Refuse anything larger than this. May only lower the "
                        "server limit, never raise it."
                    ),
                },
            },
            "required": ["url", "dest_path"],
        },
    ),
    ]

    # ------------------------------------------------------------------ #
    #  Tool: download_file
    # ------------------------------------------------------------------ #

    def _download_file(
        self,
        url: str,
        dest_path: str,
        overwrite: bool = False,
        timeout: int | None = None,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        """Stream a remote URL to a local file, enforcing size and address limits."""
        started = time.monotonic()

        limit = int(getattr(self.config, "download_max_bytes", DEFAULT_MAX_BYTES))
        if max_bytes is not None:
            # A caller may tighten the ceiling; letting it raise the ceiling
            # would make the server-side limit decorative.
            limit = max(1, min(int(max_bytes), limit))

        configured_timeout = float(getattr(self.config, "download_timeout", DEFAULT_TIMEOUT))
        effective_timeout = float(timeout) if timeout else configured_timeout
        effective_timeout = max(1.0, min(effective_timeout, 3600.0))

        try:
            resolved = self.guard.check(dest_path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")

        if resolved.is_dir():
            return err(f"Destination is a directory: {resolved}", "NotAFile")
        if resolved.exists() and not overwrite:
            return err(
                f"File already exists: {resolved}. Pass overwrite=true to replace it.",
                "FileExists",
            )

        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return err(f"Failed to create destination directory: {e}", "WriteError")

        # Same trick as the upload endpoint: build the file next to its target
        # and rename it in, so a dropped connection cannot leave a half-file at
        # a path something else may already be watching.
        tmp = resolved.with_name(resolved.name + ".part")

        current = url
        written = 0
        content_type = ""
        final_url = url

        try:
            with httpx.Client(follow_redirects=False, timeout=effective_timeout) as client:
                for _ in range(MAX_REDIRECTS + 1):
                    blocked = self._vet_url(current)
                    if blocked is not None:
                        return blocked

                    headers = {"User-Agent": self._USER_AGENT}
                    with client.stream("GET", current, headers=headers) as response:
                        if response.is_redirect:
                            # Redirects are followed by hand rather than by
                            # httpx: an automatic follow would fetch the next
                            # hop before this code could look at where it points.
                            current = urljoin(current, response.headers["location"])
                            continue
                        if 300 <= response.status_code < 400:
                            return err(
                                f"HTTP {response.status_code} with no Location header.",
                                "HttpError",
                                status_code=response.status_code,
                                url=current,
                            )
                        if response.status_code >= 400:
                            return err(
                                f"HTTP {response.status_code} fetching {current}",
                                "HttpError",
                                status_code=response.status_code,
                                url=current,
                            )

                        declared = _content_length(response)
                        if declared is not None and declared > limit:
                            return err(
                                f"Remote file is {declared:,} bytes, over the "
                                f"{limit:,} byte limit.",
                                "ContentTooLarge",
                                content_length=declared,
                                max_bytes=limit,
                            )

                        written = _write_stream(response, tmp, limit)
                        content_type = response.headers.get("content-type", "")
                        final_url = str(response.url)
                        break
                else:
                    return err(
                        f"Exceeded {MAX_REDIRECTS} redirects starting from {url}",
                        "TooManyRedirects",
                    )
        except _DownloadTooLarge as e:
            tmp.unlink(missing_ok=True)
            return err(str(e), "ContentTooLarge", max_bytes=limit)
        except httpx.TimeoutException:
            tmp.unlink(missing_ok=True)
            return err(
                f"Download timed out after {effective_timeout:g}s.",
                "TimeoutError",
                url=current,
            )
        except httpx.HTTPError as e:
            tmp.unlink(missing_ok=True)
            return err(f"Request failed: {type(e).__name__}: {e}", "NetworkError", url=current)
        except OSError as e:
            tmp.unlink(missing_ok=True)
            return err(f"Failed to write {tmp}: {e}", "WriteError")

        existed = resolved.exists()
        try:
            os.replace(tmp, resolved)
        except OSError as e:
            tmp.unlink(missing_ok=True)
            return err(f"Failed to move downloaded file into place: {e}", "WriteError")

        elapsed = time.monotonic() - started
        logger.info("Downloaded %s -> %s (%d bytes)", final_url, resolved, written)

        return ok(
            dest_path=str(resolved),
            bytes_written=written,
            content_type=content_type or "application/octet-stream",
            final_url=final_url,
            host=urlsplit(final_url).hostname or "",
            elapsed_seconds=round(elapsed, 3),
            action="overwritten" if existed else "created",
        )

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _vet_url(self, url: str) -> dict[str, Any] | None:
        """Return an error payload if this URL must not be fetched, else ``None``.

        Called for the caller's URL *and* for every redirect hop, because a
        public URL that 302s to ``http://127.0.0.1:8765/`` is exactly how an
        SSRF probe reaches a service that only trusts localhost.
        """
        parts = urlsplit(url)

        scheme = (parts.scheme or "").lower()
        allowed_schemes = [
            str(s).lower()
            for s in getattr(self.config, "download_allowed_schemes", DEFAULT_SCHEMES)
        ]
        if scheme not in allowed_schemes:
            return err(
                f"URL scheme {scheme or '(none)'!r} is not allowed "
                f"(allowed: {', '.join(allowed_schemes) or 'none'}).",
                "BlockedScheme",
                url=url,
            )

        try:
            host = parts.hostname
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError as e:
            return err(f"Malformed URL {url!r}: {e}", "InvalidUrl", url=url)
        if not host:
            return err(f"URL has no host: {url!r}", "InvalidUrl", url=url)

        allowed_hosts = [str(h) for h in (getattr(self.config, "download_allowed_hosts", []) or [])]
        whitelisted = _host_matches(host, allowed_hosts)
        if allowed_hosts and not whitelisted:
            return err(
                f"Host {host!r} is not in the server's download_allowed_hosts list.",
                "BlockedHost",
                host=host,
            )

        # A host someone deliberately wrote into the config is allowed to be
        # internal — that is usually the whole reason it was listed.
        if whitelisted:
            return None

        try:
            addresses = _resolve(host, port)
        except (OSError, ValueError) as e:
            return err(f"Cannot resolve host {host!r}: {e}", "DnsError", host=host)
        if not addresses:
            return err(f"Host {host!r} resolved to no addresses.", "DnsError", host=host)

        # Every answer must be public: a host with one public and one loopback
        # record would otherwise be a coin flip at connect time. Note this still
        # trusts DNS to answer the same way when httpx resolves it again a
        # moment later; closing that race needs connection-level address
        # pinning, which httpx does not expose.
        for ip in addresses:
            if _is_blocked(ip):
                return err(
                    f"Host {host!r} resolves to non-public address {ip} "
                    "(loopback, link-local, or private range).",
                    "BlockedAddress",
                    host=host,
                    address=str(ip),
                )
        return None


# ====================================================================== #
#  Module-level helpers
# ====================================================================== #

def _write_stream(response: httpx.Response, tmp: Path, limit: int) -> int:
    """Copy a streamed response body into ``tmp``, stopping past ``limit``."""
    written = 0
    with tmp.open("wb") as fh:
        for chunk in response.iter_bytes(CHUNK_SIZE):
            written += len(chunk)
            if written > limit:
                # Content-Length is a claim, not a fact: it can be absent on a
                # chunked response and wrong on a hostile one, so the ceiling
                # has to hold against the bytes actually arriving.
                raise _DownloadTooLarge(
                    f"Download exceeds limit of {limit:,} bytes "
                    f"(received at least {written:,})"
                )
            fh.write(chunk)
    return written


def _content_length(response: httpx.Response) -> int | None:
    """Read Content-Length, ignoring absent or malformed values."""
    raw = response.headers.get("content-length")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _resolve(host: str, port: int) -> list[IpAddress]:
    """Resolve a hostname to every address it currently answers with."""
    addresses: list[IpAddress] = []
    for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        raw = str(info[4][0]).split("%", 1)[0]  # drop any IPv6 zone index
        addresses.append(ipaddress.ip_address(raw))
    return addresses


def _is_blocked(ip: IpAddress) -> bool:
    """True for any address the daemon must not fetch from on an agent's say-so."""
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    # ::ffff:127.0.0.1 is loopback wearing a v6 costume, and answers False to
    # every check above on older Python versions.
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped is not None and _is_blocked(mapped)


def _host_matches(host: str, patterns: list[str]) -> bool:
    """Match a hostname against allowlist entries.

    A leading dot means "this domain and its subdomains": ``.example.com``
    matches ``example.com`` and ``api.example.com``, but not the lookalike
    ``notexample.com``.
    """
    candidate = host.lower().rstrip(".")
    for raw in patterns:
        entry = raw.strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("."):
            if candidate == entry[1:] or candidate.endswith(entry):
                return True
        elif candidate == entry:
            return True
    return False
