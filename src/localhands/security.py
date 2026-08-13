"""Security layers for the LocalHands daemon.

Implements the daemon's defence in depth:
  1. BearerAuthMiddleware   — ASGI middleware verifying the Authorization header
                              or ?token= query parameter, with session-based
                              auth for the two-step MCP SSE flow.
  2. RateLimitMiddleware     — ASGI middleware enforcing a per-minute token bucket.
  3. PathGuard               — Path whitelist checker (prevents directory traversal).
  4. CommandGuard            — Deny list for irreversible shell commands.
  5. TransferTicketStore     — One-time, single-file credentials for /download
                              and /upload, so the main token never leaves this
                              machine.
  6. OperationLogger         — JSONL audit log of every tool invocation.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from .config import Config

logger = logging.getLogger(__name__)

# Type alias for ASGI scope (kept minimal — we only read a few keys).
Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


# ====================================================================== #
#  1. Bearer Token Authentication (ASGI middleware)
# ====================================================================== #

class BearerAuthMiddleware:
    """ASGI middleware that authenticates MCP requests.

    Supports two authentication methods (tried in order):

    1. ``Authorization: Bearer <token>`` header (original, backward-compatible).
    2. ``?token=<token>`` query parameter — enables URL-only clients such as
       Aily ``aily-mcp install-remote`` which cannot send custom headers.

    **Session-based auth for the two-step SSE flow**

    The MCP SSE transport works in two steps:

    1. Client connects ``GET /sse?token=xxx`` — after token validation the
       ``SseServerTransport`` generates a ``session_id`` and broadcasts an
       ``endpoint`` event carrying the POST URL ``/messages/?session_id=<id>``.
    2. Client sends JSON-RPC requests to ``POST /messages/?session_id=<id>`` —
       this request carries **no token**, only the ``session_id``.

    To bridge the gap, ``GET /sse`` that authenticates via the query-param
    token registers the resulting ``session_id`` in an in-memory set.  Subsequent
    ``POST /messages/?session_id=<id>`` requests are admitted if the
    ``session_id`` is in that set, with no token required.  Sessions are
    removed when the SSE connection closes.

    All token comparisons use ``secrets.compare_digest`` (constant-time).
    ``GET /health`` is always public (no token required).
    """

    def __init__(
        self,
        app: Any,
        token: str,
        allow_query_token: bool = True,
    ) -> None:
        self._app = app
        self._token = token.encode("utf-8")
        self._allow_query_token = allow_query_token
        # session_ids authenticated via GET /sse — admitted on POST /messages.
        self._authenticated_sessions: set[str] = set()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")
        query_params = _parse_query_params(scope.get("query_string", b""))

        # /health is always public (used by monitoring / tunnel health checks).
        if path == "/health" and method == "GET":
            await self._app(scope, receive, send)
            return

        # Binary transfer endpoints authenticate with the single-use ticket in
        # their own path, so the bearer token is deliberately not required here.
        # Requiring it would force the token into the remote sandbox's shell
        # history; an unknown ticket is rejected with 403 downstream, and the
        # rate limiter still wraps this middleware.
        if path.startswith("/download/") or path.startswith("/upload/"):
            await self._app(scope, receive, send)
            return

        # POST /messages — check session-based auth first (no token needed
        # if the session was authenticated during the SSE handshake).
        if method == "POST" and path.startswith("/messages"):
            session_id = query_params.get("session_id")
            if session_id and session_id in self._authenticated_sessions:
                await self._app(scope, receive, send)
                return
            # No valid session — fall through to token-based auth below.

        # --- Token-based authentication (Bearer header or ?token=) ---

        # 1. Bearer header (backward-compatible).
        auth_header = _get_header(scope, b"authorization")
        if auth_header:
            auth_str = auth_header.decode("utf-8", errors="replace")
            if not auth_str.startswith("Bearer "):
                await _send_json_error(
                    send, 401,
                    "Invalid auth scheme — expected 'Bearer <token>'",
                )
                return
            provided = auth_str[7:].strip().encode("utf-8")
            if not secrets.compare_digest(provided, self._token):
                await _send_json_error(send, 403, "Invalid bearer token")
                return
            # Bearer auth passed.
            # Route SSE through session-tracking handler so anti-buffering
            # headers are injected (same as query-param auth path).
            if method == "GET" and path == "/sse":
                await self._serve_sse_with_session_tracking(scope, receive, send)
                return
            await self._app(scope, receive, send)
            return

        # 2. Query-parameter token fallback (for URL-only clients like Aily).
        if not self._allow_query_token:
            await _send_json_error(
                send, 401,
                "Missing Authorization header (query-param token is disabled)",
            )
            return

        token_param = query_params.get("token")
        if token_param is None:
            await _send_json_error(
                send, 401,
                "Missing token — provide 'Authorization: Bearer <token>' header "
                "or '?token=<token>' query parameter",
            )
            return

        provided = token_param.encode("utf-8")
        if not secrets.compare_digest(provided, self._token):
            await _send_json_error(send, 403, "Invalid token")
            return

        # Query-param token auth passed.
        # GET /sse — capture session_id so POST /messages can authenticate.
        if method == "GET" and path == "/sse":
            await self._serve_sse_with_session_tracking(scope, receive, send)
            return

        await self._app(scope, receive, send)

    async def _serve_sse_with_session_tracking(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Handle GET /sse with session_id capture and cleanup.

        Wraps ``send`` to intercept the SSE ``endpoint`` event and extract the
        ``session_id``.  The session is registered so that subsequent
        ``POST /messages/?session_id=<id>`` requests pass without a token.
        On disconnect the session is removed.
        """
        captured: dict[str, str | None] = {"session_id": None}

        async def _tracking_send(message: dict[str, Any]) -> None:
            # Inject anti-buffering headers on SSE response start to prevent
            # Cloudflare Tunnel / reverse-proxy buffering that blocks the
            # initial 'endpoint' event from reaching the client.
            if message.get("type") == "http.response.start":
                message = _inject_sse_no_buffer_headers(message)

            if (
                message.get("type") == "http.response.body"
                and captured["session_id"] is None
            ):
                body = message.get("body", b"")
                if body:
                    sid = _extract_session_id(body)
                    if sid:
                        captured["session_id"] = sid
                        self._authenticated_sessions.add(sid)
                        logger.info("Registered authenticated SSE session: %s", sid)
            await send(message)

        try:
            await self._app(scope, receive, _tracking_send)
        finally:
            sid = captured["session_id"]
            if sid:
                self._authenticated_sessions.discard(sid)
                logger.info("Removed SSE session on disconnect: %s", sid)


# ====================================================================== #
#  2. Rate Limiting (ASGI middleware, token-bucket)
# ====================================================================== #

class RateLimitMiddleware:
    """Token-bucket rate limiter as pure-ASGI middleware.

    Args:
        app:       The wrapped ASGI application.
        capacity:  Maximum tokens in the bucket (= burst capacity).
        refill_per_sec:  How many tokens are added per second.
    """

    def __init__(
        self,
        app: Any,
        capacity: int = 60,
        refill_per_sec: float = 1.0,
    ) -> None:
        self._app = app
        self._capacity = float(capacity)
        self._refill_per_sec = refill_per_sec
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        logger.info("Rate limiter: capacity=%d, refill=%.1f/s", capacity, refill_per_sec)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        if not self._consume():
            client_ip = _get_client_ip(scope)
            logger.warning("Rate limit exceeded for client %s", client_ip)
            await _send_json_error(
                send, 429, "Rate limit exceeded — please slow down",
                extra_headers=[(b"retry-after", b"1")],
            )
            return

        await self._app(scope, receive, send)

    def _consume(self) -> bool:
        """Attempt to consume one token.  Refills based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_per_sec)
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


# ====================================================================== #
#  3. PathGuard — whitelist enforcement with traversal protection
# ====================================================================== #

class PathGuardError(Exception):
    """Raised when a path is outside the whitelist."""


class PathGuard:
    """Validates that a given path stays within the configured allowed directories.

    Uses ``Path.resolve()`` to canonicalise the path (resolving symlinks,
    ``..`` segments, etc.) and then checks that the resolved path is inside
    at least one allowed root.
    """

    def __init__(self, config: Config) -> None:
        self._roots: list[Path] = config.resolved_allowed_paths
        if not self._roots:
            raise ValueError("PathGuard requires at least one allowed path.")

    def check(self, raw_path: str) -> Path:
        """Validate and return the resolved Path.

        Raises:
            PathGuardError: If the resolved path is outside all allowed roots.
        """
        candidate = Path(raw_path).expanduser()
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise PathGuardError(f"Cannot resolve path {raw_path!r}: {exc}") from exc

        for root in self._roots:
            try:
                resolved.relative_to(root)
                return resolved  # inside this root — allowed
            except ValueError:
                continue

        # Not inside any allowed root.
        raise PathGuardError(
            f"Path {resolved} is outside all allowed directories: "
            f"{[str(r) for r in self._roots]}"
        )

    def is_allowed(self, raw_path: str) -> bool:
        """Return True if the path passes the whitelist check."""
        try:
            self.check(raw_path)
            return True
        except PathGuardError:
            return False


# ====================================================================== #
#  4. CommandGuard — refuse irreversible shell commands
# ====================================================================== #

class CommandBlocked(Exception):
    """Raised when a shell command matches a deny pattern."""


# Commands whose damage cannot be undone by a follow-up command. The list is
# deliberately short: this is a guard rail against a remote model doing
# something catastrophic on a bad inference, not a sandbox. Anything that only
# breaks the working tree is left alone, because refusing ordinary work would
# push the agent toward creative workarounds that are harder to audit.
DEFAULT_DENIED_COMMANDS: tuple[str, ...] = (
    # Recursive deletion of a drive root, a user profile, or an unbounded glob.
    r"\brm\s+(-[a-zA-Z]*\s+)*-?[a-zA-Z]*[rR][a-zA-Z]*f?\s+(/|~|/\*|\$HOME|[A-Za-z]:[\\/]?)\s*$",
    r"\brm\s+-[rRf]+\s+[A-Za-z]:[\\/]\s*$",
    r"\b(del|erase)\s+.*/[sS]\b.*\s[A-Za-z]:[\\/]?(\*|\s|$)",
    r"\brd\s+.*/[sS]\b.*\s[A-Za-z]:[\\/]?\s*$",
    r"Remove-Item\s+.*-Recurse.*\s+['\"]?[A-Za-z]:[\\/]?['\"]?\s*$",
    # Whole-disk operations.
    r"\bformat\s+[A-Za-z]:",
    r"\bdiskpart\b",
    r"\bmkfs(\.\w+)?\b",
    r"\bdd\s+.*\bof=/dev/",
    # Machine state the user did not ask an agent to change.
    r"\bshutdown\s+/[rs]\b",
    r"\bRestart-Computer\b",
    r"\bStop-Computer\b",
    # Registry hives.
    r"\breg\s+delete\s+HK(LM|EY_LOCAL_MACHINE)\b",
    # Fetch-and-execute: the fetched script is unreviewable, so the audit log
    # would record a harmless-looking curl while arbitrary code ran.
    r"\|\s*(sudo\s+)?(ba)?sh\b",
    r"\|\s*(iex|Invoke-Expression)\b",
    r"(curl|wget|Invoke-WebRequest)\b.*\|\s*\w*(sh|bash|iex|python)\b",
)


class CommandGuard:
    """Blocks shell commands matching a deny list.

    This is not an adversarial security boundary — anything with shell access
    can trivially obfuscate its way past a regex, and ``run_bash`` is arbitrary
    code execution by design. What it does buy is protection against the failure
    mode that actually happens: a cloud model, acting on a misread instruction or
    a prompt injection in a document it read, emitting one irreversible command.
    """

    def __init__(self, enabled: bool = True, extra_patterns: list[str] | None = None) -> None:
        self.enabled = enabled
        patterns = list(DEFAULT_DENIED_COMMANDS) + list(extra_patterns or [])
        self._patterns: list[re.Pattern[str]] = []
        for raw in patterns:
            try:
                self._patterns.append(re.compile(raw, re.IGNORECASE))
            except re.error as exc:
                # A bad user-supplied regex must not stop the daemon starting.
                logger.warning("Ignoring invalid denied_command_pattern %r: %s", raw, exc)
        logger.info(
            "Command guard: %s (%d patterns)",
            "enabled" if enabled else "DISABLED",
            len(self._patterns),
        )

    def check(self, command: str) -> None:
        """Raise ``CommandBlocked`` if the command matches a deny pattern."""
        if not self.enabled:
            return
        for pattern in self._patterns:
            if pattern.search(command):
                raise CommandBlocked(
                    f"Command blocked by the daemon's guard rail (matched "
                    f"{pattern.pattern!r}). This command is irreversible. If you "
                    f"genuinely need it, ask the human operator to run it."
                )

    def is_allowed(self, command: str) -> bool:
        """Return True if the command passes."""
        try:
            self.check(command)
            return True
        except CommandBlocked:
            return False


# ====================================================================== #
#  5. TransferTicketStore — one-time credentials for binary transfer
# ====================================================================== #

class TransferTicketError(Exception):
    """Raised when a transfer ticket is unknown, expired, or already used."""


@dataclass
class TransferTicket:
    """A single-use authorisation to move one file over HTTP."""

    kind: str  # "download" (daemon -> client) or "upload" (client -> daemon)
    path: Path
    expires_at: float
    max_bytes: int | None = None


class TransferTicketStore:
    """Mints and redeems one-time tickets for the /download and /upload endpoints.

    Why tickets instead of the main auth token: the cloud agent fetches these
    URLs with ``curl`` inside its own sandbox, so whatever credential is in the
    URL lands in that sandbox's shell history and logs.  Putting the long-lived
    ``auth_token`` there would leak the key to the entire server.  A ticket is
    instead scoped to exactly one file, one direction, one use, and a few
    minutes — a leaked ticket is worth almost nothing by the time anyone reads
    the log.

    Tickets are held in memory only: a daemon restart invalidates all of them,
    which is the desired behaviour.
    """

    def __init__(self, ttl: int = 300, max_outstanding: int = 256) -> None:
        self._ttl = ttl
        self._max_outstanding = max_outstanding
        self._tickets: dict[str, TransferTicket] = {}
        self._lock = threading.Lock()

    def mint(
        self,
        kind: str,
        path: Path,
        ttl: int | None = None,
        max_bytes: int | None = None,
    ) -> tuple[str, TransferTicket]:
        """Create a ticket and return ``(ticket_id, ticket)``."""
        if kind not in ("download", "upload"):
            raise ValueError(f"Unknown transfer kind: {kind!r}")

        ticket_id = secrets.token_urlsafe(32)
        ticket = TransferTicket(
            kind=kind,
            path=path,
            expires_at=time.time() + (ttl if ttl is not None else self._ttl),
            max_bytes=max_bytes,
        )
        with self._lock:
            self._purge_expired_locked()
            # Bound memory even if a caller mints tickets it never redeems.
            if len(self._tickets) >= self._max_outstanding:
                oldest = min(self._tickets, key=lambda k: self._tickets[k].expires_at)
                del self._tickets[oldest]
            self._tickets[ticket_id] = ticket
        logger.info("Minted %s ticket for %s (ttl=%ss)", kind, path, ttl or self._ttl)
        return ticket_id, ticket

    def redeem(self, ticket_id: str, kind: str) -> TransferTicket:
        """Consume a ticket, or raise ``TransferTicketError``.

        The ticket is removed before any I/O happens, so a request that fails
        halfway cannot be replayed.
        """
        with self._lock:
            self._purge_expired_locked()
            ticket = self._tickets.get(ticket_id)

            if ticket is None:
                raise TransferTicketError("Unknown, expired, or already-used transfer ticket")
            # Validate before consuming, all under the same lock. Popping first
            # would burn the ticket on a wrong-kind request, so the legitimate
            # redemption that follows would fail too — while still holding the
            # lock keeps the check-then-consume atomic against a concurrent
            # replay.
            if ticket.kind != kind:
                raise TransferTicketError(f"Ticket is for {ticket.kind!r}, not {kind!r}")
            if ticket.expires_at < time.time():
                del self._tickets[ticket_id]
                raise TransferTicketError("Transfer ticket has expired")

            del self._tickets[ticket_id]

        return ticket

    def _purge_expired_locked(self) -> None:
        """Drop expired tickets.  Caller must hold ``self._lock``."""
        now = time.time()
        expired = [k for k, t in self._tickets.items() if t.expires_at < now]
        for k in expired:
            del self._tickets[k]


# ====================================================================== #
#  6. OperationLogger — JSONL audit trail
# ====================================================================== #

class OperationLogger:
    """Appends structured operation records to a JSONL log file.

    Each record contains: timestamp, tool name, arguments (sanitised),
    status (success/error/blocked), duration_ms, and an optional error message.

    Writes are flushed immediately to survive crashes.

    The log rotates once it grows past ``max_bytes``: the current file is moved
    to ``<name>.1`` (replacing any previous ``.1``) and a fresh file is started.
    A single generation is kept deliberately — this is an operational audit
    trail, not an archive, and an unbounded log was what let the previous file
    accumulate into noise.  ``max_bytes=0`` disables rotation.
    """

    def __init__(self, log_file: str, max_bytes: int = 5_242_880) -> None:
        self._log_path = Path(log_file).expanduser()
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_bytes
        logger.info(
            "Operation log: %s (rotate at %s)",
            self._log_path,
            f"{max_bytes:,} bytes" if max_bytes else "never",
        )

    def _rotate_if_needed(self) -> None:
        """Move the current log aside if it has grown past ``max_bytes``."""
        if self._max_bytes <= 0:
            return
        try:
            if self._log_path.stat().st_size < self._max_bytes:
                return
        except OSError:
            return  # Missing file — nothing to rotate.

        backup = self._log_path.with_name(self._log_path.name + ".1")
        try:
            backup.unlink(missing_ok=True)
            self._log_path.rename(backup)
            logger.info("Rotated operation log to %s", backup)
        except OSError as exc:
            # Rotation is best-effort; never let it block an audit write.
            logger.warning("Failed to rotate operation log: %s", exc)

    def log(
        self,
        tool: str,
        arguments: dict[str, Any],
        status: str,
        duration_ms: float,
        error: str | None = None,
        result_summary: str | None = None,
    ) -> None:
        """Append a single operation record."""
        record: dict[str, Any] = {
            "timestamp": _utc_iso(),
            "tool": tool,
            "arguments": _sanitise_args(arguments),
            "status": status,
            "duration_ms": round(duration_ms, 2),
        }
        if error:
            record["error"] = error
        if result_summary:
            record["result_summary"] = result_summary

        line = json.dumps(record, ensure_ascii=False, default=str)
        self._rotate_if_needed()
        try:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            logger.error("Failed to write operation log: %s", exc)


# ====================================================================== #
#  Helpers (header extraction, query parsing, JSON errors, timestamps)
# ====================================================================== #

def _parse_query_params(query_string: bytes | str) -> dict[str, str]:
    """Parse an ASGI ``query_string`` into a ``{key: value}`` dict.

    Only the first value for each key is kept (MCP only uses single-value
    params such as ``token`` and ``session_id``).
    """
    if not query_string:
        return {}
    if isinstance(query_string, bytes):
        query_string = query_string.decode("utf-8", errors="replace")
    parsed = parse_qs(query_string, keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


def _extract_session_id(body: bytes) -> str | None:
    """Extract ``session_id`` from an SSE ``endpoint`` event body.

    The MCP SSE transport broadcasts an event like::

        event: endpoint
        data: /messages/?session_id=<session_id>

    We look for ``session_id=`` in any line and grab the value up to the
    next ``&`` or end-of-line.
    """
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return None
    for line in text.split("\n"):
        if "session_id=" in line:
            idx = line.index("session_id=") + len("session_id=")
            after = line[idx:]
            sid = after.split("&", 1)[0].strip()
            if sid:
                return sid
    return None


def _get_header(scope: Scope, name: bytes) -> bytes | None:
    """Extract a header value from the raw ASGI scope headers list."""
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value
    return None


def _get_client_ip(scope: Scope) -> str:
    """Best-effort extraction of the client IP from the ASGI scope."""
    client = scope.get("client")
    if client and isinstance(client, (list, tuple)) and len(client) >= 1:
        return str(client[0])
    return "unknown"


async def _send_json_error(
    send: Send,
    status_code: int,
    message: str,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    """Send a JSON error response without buffering (safe for non-SSE contexts)."""
    body = json.dumps({"error": message}).encode("utf-8")
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status_code, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _inject_sse_no_buffer_headers(message: dict[str, Any]) -> dict[str, Any]:
    """Add headers to prevent reverse-proxy buffering of SSE responses.

    Cloudflare Tunnel (and other reverse proxies) may buffer SSE response
    bodies, preventing the initial ``endpoint`` event from reaching the
    client within the connection timeout.  Adding ``X-Accel-Buffering: no``
    and enhancing ``Cache-Control`` tells proxies to forward each chunk
    immediately.
    """
    headers = list(message.get("headers", []))

    # Only inject for SSE responses (text/event-stream content type).
    is_sse = any(
        k.lower() == b"content-type" and b"text/event-stream" in v.lower()
        for k, v in headers
    )
    if not is_sse:
        return message

    existing_keys = {k.lower() for k, _ in headers}

    # X-Accel-Buffering: no — critical for nginx / Cloudflare edge buffering.
    if b"x-accel-buffering" not in existing_keys:
        headers.append((b"x-accel-buffering", b"no"))

    # Upgrade Cache-Control to include no-store and no-transform.
    if b"cache-control" in existing_keys:
        headers = [(k, v) for k, v in headers if k.lower() != b"cache-control"]
    headers.append((b"cache-control", b"no-cache, no-store, no-transform"))

    logger.debug("Injected SSE anti-buffering headers (X-Accel-Buffering, Cache-Control)")
    return {**message, "headers": headers}


def _utc_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _sanitise_args(arguments: dict[str, Any]) -> dict[str, Any]:
    """Truncate long argument values to keep the log readable."""
    MAX_VAL_LEN = 500
    result: dict[str, Any] = {}
    for key, value in arguments.items():
        if isinstance(value, str) and len(value) > MAX_VAL_LEN:
            result[key] = value[:MAX_VAL_LEN] + f"...<truncated, {len(value)} chars total>"
        elif isinstance(value, (list, dict)):
            s = json.dumps(value, ensure_ascii=False, default=str)
            if len(s) > MAX_VAL_LEN:
                result[key] = s[:MAX_VAL_LEN] + "...<truncated>"
            else:
                result[key] = value
        else:
            result[key] = value
    return result
