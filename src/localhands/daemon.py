#!/usr/bin/env python3
"""LocalHands daemon — the MCP server a cloud agent connects to.

    Cloud agent  →  MCP over /mcp or /sse  →  tunnel  →  this daemon  →  machine

Tools are declared by providers under ``tools/``; see ``tools/__init__.py`` for
the registry. Bytes never travel through the model's context — ``/download`` and
``/upload`` move them over plain HTTP instead (see ``transfer.py``).

Defence in depth, outermost first: rate limit, bearer token, path whitelist,
command guard, audit log. ``run_bash`` is arbitrary code execution by design, so
the auth token is equivalent to a shell password on this machine.

Usage:
    python -m localhands --config config.yaml
    python -m localhands --config config.yaml --check      # validate only
    python -m localhands --config config.yaml --no-tunnel  # skip the tunnel

Import-safe: importing this module will NOT start the server — all side
effects are guarded by ``if __name__ == "__main__"``.
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import sys
from pathlib import Path
from typing import Any

import uvicorn

from .config import Config, ConfigError
from .security import (
    BearerAuthMiddleware,
    OperationLogger,
    PathGuard,
    RateLimitMiddleware,
    TransferTicketStore,
)
from .tools import TOOL_DEFINITIONS, ToolHandler
from .transfer import TransferEndpoints
from .tunnel import TunnelError, TunnelManager

logger = logging.getLogger("localhands")

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

from . import SERVER_NAME, __version__ as SERVER_VERSION

DEFAULT_CONFIG_PATH = "config.yaml"


# --------------------------------------------------------------------------- #
#  MCP Server + Starlette App Factory
# --------------------------------------------------------------------------- #

def create_mcp_server(
    config: Config,
    path_guard: PathGuard,
    op_logger: OperationLogger,
    tickets: TransferTicketStore,
):
    """Create an MCP Server instance with tools registered.

    Returns:
        ``(server, handler)`` — the handler is returned as well because the tool
        list it actually serves depends on what the machine turns out to have,
        so /health and the startup banner must ask it rather than guess.

    Note on the SDK 2.x shape: handlers are constructor arguments rather than
    decorators, they receive ``(request_context, params)``, and return values are
    no longer auto-wrapped — each handler builds its own Result object.
    """
    from mcp.server.lowlevel import Server
    from mcp.types import CallToolRequestParams, CallToolResult, ListToolsResult

    handler = ToolHandler(config, path_guard, op_logger, tickets)

    async def _list_tools(ctx: Any, params: Any) -> ListToolsResult:
        """Return the list of available tool schemas."""
        return ListToolsResult(tools=await handler.list_tools())

    async def _call_tool(ctx: Any, params: CallToolRequestParams) -> CallToolResult:
        """Dispatch a tool call and return its content blocks."""
        return await handler.call_tool(params.name, params.arguments or {})

    server = Server(
        SERVER_NAME,
        version=SERVER_VERSION,  # 1.x reported the SDK's version here instead
        # Guidance that applies to the whole server rather than to one tool.
        # Clients generally fold this into the system prompt, which reaches the
        # model before it picks a tool — unlike a description, which it only
        # reads once it is already looking at that tool.
        instructions=handler.instructions,
        on_list_tools=_list_tools,
        on_call_tool=_call_tool,
    )
    return server, handler


def create_app(config: Config) -> Any:
    """Create the ASGI application with SSE routes and middleware.

    The app exposes:
        GET  /sse          — SSE connection endpoint (raw ASGI, no root_path pollution)
        POST /messages/    — MCP message endpoint (raw ASGI)
        GET  /health       — health check (Starlette Route)
        GET  /             — server info (Starlette Route)

    Middleware stack (outermost → innermost):
        RateLimitMiddleware  →  BearerAuthMiddleware  →  ASGI router

    Note: SSE and POST endpoints use a custom ASGI router (not Starlette's
    Mount) to avoid root_path prefix pollution — Mount("/sse") would cause
    the SseServerTransport to advertise /sse/messages/ as the POST URL.
    """
    import contextlib

    from mcp.server.sse import SseServerTransport
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    # SSE keepalive — prevents idle-connection drops through ngrok/proxies
    # (root cause of intermittent protocol error 210204).
    _enable_sse_keepalive(config.sse_ping_interval)

    # Shared state
    path_guard = PathGuard(config)
    op_logger = OperationLogger(config.log_file, max_bytes=config.log_max_bytes)
    tickets = TransferTicketStore(ttl=config.transfer_ticket_ttl)
    transfer = TransferEndpoints(config, path_guard, tickets, op_logger)
    server, handler = create_mcp_server(config, path_guard, op_logger, tickets)

    # SSE transport — the POST endpoint path sent to clients.
    sse = SseServerTransport("/messages/")

    # ------------------------------------------------------------------ #
    #  Streamable HTTP transport
    # ------------------------------------------------------------------ #
    # Runs alongside SSE rather than replacing it: clients already registered
    # against /sse keep working while new ones can be pointed at /mcp.
    #
    # It also sidesteps the failure that SSE keeps hitting here. SSE needs one
    # connection held open indefinitely, and an idle one gets dropped somewhere
    # in the tunnel; the client then reuses a dead pooled session and the call
    # stalls (protocol error 210204, currently mitigated by a keepalive ping).
    # Streamable HTTP uses short request-scoped exchanges, so there is no idle
    # connection to lose.
    http_manager: StreamableHTTPSessionManager | None = None
    if "streamable_http" in config.transports:
        # DNS-rebinding protection defaults to the local Host header, which this
        # daemon never sees: requests arrive through a tunnel bearing the public
        # hostname. Allow that hostname explicitly instead of switching the
        # check off.
        allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
        allowed_origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
        if config.public_base_url:
            public_host = config.public_base_url.split("://", 1)[-1].rstrip("/")
            allowed_hosts.append(public_host)
            allowed_origins.append(config.public_base_url)

        http_manager = StreamableHTTPSessionManager(
            app=server,
            json_response=False,
            stateless=False,
            max_request_body_size=config.max_request_body_size,
            security_settings=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=allowed_hosts,
                allowed_origins=allowed_origins,
            ),
        )

    # ------------------------------------------------------------------ #
    #  Starlette app for health and root endpoints only
    # ------------------------------------------------------------------ #
    async def health_endpoint(request):
        """Health check — returns 200 with server status."""
        # Asked of the live handler, not a static list: some tools are withheld
        # depending on what this machine has, so a hard-coded list would lie.
        tool_names = [t.name for t in handler.served_tools]
        return JSONResponse({
            "status": "ok",
            "server": SERVER_NAME,
            "version": SERVER_VERSION,
            "tool_count": len(tool_names),
            "tools": tool_names,
            "dlp_handling": handler.dlp_active,
        })

    async def root_endpoint(request):
        """Root endpoint — basic server info."""
        return JSONResponse({
            "server": SERVER_NAME,
            "version": SERVER_VERSION,
            "transports": config.transports,
            "endpoints": {
                "streamable_http": "GET|POST|DELETE /mcp" if "streamable_http" in config.transports else None,
                "sse": "GET /sse" if "sse" in config.transports else None,
                "messages": "POST /messages/" if "sse" in config.transports else None,
                "health": "GET /health",
                "download": "GET /download/{ticket}",
                "upload": "PUT|POST /upload/{ticket}",
            },
            "allowed_paths": [str(p) for p in config.resolved_allowed_paths],
        })

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        """Own the Streamable HTTP session manager's task group.

        ``StreamableHTTPSessionManager.run()`` must be active for the whole
        server lifetime — it supervises the per-session tasks. Binding it to the
        ASGI lifespan means sessions are torn down cleanly on shutdown instead of
        being abandoned.
        """
        if http_manager is None:
            yield
            return
        async with http_manager.run():
            logger.info("Streamable HTTP transport ready at /mcp")
            yield

    starlette_app = Starlette(
        routes=[
            Route("/health", endpoint=health_endpoint, methods=["GET"]),
            Route("/", endpoint=root_endpoint, methods=["GET"]),
        ],
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------ #
    #  Custom ASGI router — handles SSE + POST, delegates rest to Starlette
    # ------------------------------------------------------------------ #
    async def asgi_router(scope: dict, receive, send) -> None:
        """Route requests: SSE/POST handled inline, everything else → Starlette."""
        if scope["type"] == "http":
            path = scope.get("path", "")
            method = scope.get("method", "")

            # Streamable HTTP endpoint — one path for all three verbs.
            if path == "/mcp" or path.startswith("/mcp/"):
                if http_manager is None:
                    await _send_plain(send, 404, "Streamable HTTP transport is disabled")
                    return
                await http_manager.handle_request(scope, receive, send)
                return

            # SSE endpoint — establish connection and run MCP server.
            if path == "/sse" and method == "GET":
                if "sse" not in config.transports:
                    await _send_plain(send, 404, "SSE transport is disabled")
                    return
                async with sse.connect_sse(scope, receive, send) as (read_stream, write_stream):
                    await server.run(
                        read_stream,
                        write_stream,
                        server.create_initialization_options(),
                    )
                return

            # POST endpoint — handle MCP JSON-RPC messages.
            if path.startswith("/messages") and method == "POST":
                await sse.handle_post_message(scope, receive, send)
                return

            # Binary transfer endpoints — authenticated by the one-time ticket
            # in the path, not by the bearer token (see transfer.py).
            hit = TransferEndpoints.match(path, method)
            if hit is not None:
                kind, ticket_id = hit
                await transfer.handle(kind, ticket_id, scope, receive, send)
                return

        # Delegate to Starlette for health, root, and 404s.
        await starlette_app(scope, receive, send)

    # Apply middleware (outermost last — it wraps everything)
    app = BearerAuthMiddleware(
        asgi_router,
        token=config.auth_token,
        allow_query_token=config.allow_query_token,
    )
    app = RateLimitMiddleware(
        app,
        capacity=config.rate_limit,
        refill_per_sec=config.rate_limit / 60.0,
    )

    return app


# --------------------------------------------------------------------------- #
#  SSE Keepalive (fix for intermittent protocol error 210204)
# --------------------------------------------------------------------------- #

def _enable_sse_keepalive(ping_interval: int) -> None:
    """Patch the MCP SDK SSE response to emit periodic keepalive pings.

    Root cause of 210204: the MCP SDK builds sse_starlette.EventSourceResponse
    without ``ping`` (sse_starlette defaults to None = no heartbeat). With no
    traffic between calls, intermediaries (ngrok, reverse proxies, NAT) silently
    close the idle SSE connection. The Aily MCP hub reuses the now-dead pooled
    session, the response never arrives, and the hub surfaces protocol error
    210204. Retrying establishes a fresh session and succeeds — the classic
    first-call-after-idle flake.

    Fix: force every SSE response to send a keepalive comment every
    ``ping_interval`` seconds. Keeps the connection alive through ngrok/proxies
    and lets the server detect a dead client fast (ping write fails -> response
    ends -> session cleaned up -> hub gets a clean 404 instead of a silent
    stall). Idempotent; ``ping_interval <= 0`` leaves behaviour unchanged.
    """
    if ping_interval <= 0:
        logger.info("SSE keepalive disabled (sse_ping_interval=0).")
        return

    import mcp.server.sse as _sse_mod

    if getattr(_sse_mod, "_localhands_keepalive_patched", False):
        return

    _OrigESR = _sse_mod.EventSourceResponse

    class _KeepaliveESR(_OrigESR):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            if kwargs.get("ping") is None:
                kwargs["ping"] = ping_interval
            super().__init__(*args, **kwargs)

    _sse_mod.EventSourceResponse = _KeepaliveESR  # type: ignore[assignment]
    _sse_mod._localhands_keepalive_patched = True  # type: ignore[attr-defined]
    logger.info("SSE keepalive enabled: ping every %ds (fix for 210204).", ping_interval)


# --------------------------------------------------------------------------- #
#  Startup Self-Check
# --------------------------------------------------------------------------- #

def run_self_check(config: Config) -> bool:
    """Verify dependencies, port availability, and path existence.

    Returns True if all checks pass (warnings are non-fatal).
    Exits the process on hard failures.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # 1. Check Python version ≥ 3.10
    if sys.version_info < (3, 10):
        errors.append(f"Python 3.10+ required, got {sys.version_info.major}.{sys.version_info.minor}")

    # 2. Check required Python packages
    required_packages = [
        ("mcp", "mcp"),
        ("starlette", "starlette"),
        ("uvicorn", "uvicorn"),
        ("yaml", "pyyaml"),
        ("pathspec", "pathspec"),
    ]
    for import_name, pip_name in required_packages:
        try:
            __import__(import_name)
        except ImportError:
            errors.append(f"Missing Python package: {pip_name} (pip install {pip_name})")

    # 3. Check auth token strength
    if len(config.auth_token) < 16:
        warnings.append(f"auth_token is short ({len(config.auth_token)} chars) — recommend ≥32 chars")

    # 4. Check allowed paths
    path_warnings = config.validate_paths()
    warnings.extend(path_warnings)
    if not config.resolved_allowed_paths:
        errors.append("No allowed paths configured — at least one directory is required.")

    # 5. Check port availability
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((config.host, config.port))
    except OSError as e:
        errors.append(f"Port {config.port} on {config.host} is not available: {e}")
    finally:
        if sock:
            sock.close()

    # 6. Check the tunnel binary exists before we promise to launch it
    if config.tunnel.enabled:
        try:
            TunnelManager(config.tunnel, config.port).build_argv()
        except TunnelError as e:
            errors.append(f"Tunnel is enabled but not runnable: {e}")

    # 7. Check log file writability
    log_dir = Path(config.log_file).expanduser().parent
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        test_file = Path(config.log_file).expanduser()
        test_file.touch()
    except OSError as e:
        warnings.append(f"Log file may not be writable: {e}")

    # --- Report ---
    print("\n" + "=" * 60)
    print(f"  {SERVER_NAME} v{SERVER_VERSION} — Self-Check")
    print("=" * 60)

    if warnings:
        print("\n⚠️  Warnings (non-fatal):")
        for w in warnings:
            print(f"   • {w}")

    if errors:
        print("\n❌ Errors (must fix before starting):")
        for e in errors:
            print(f"   • {e}")
        print("\n" + "=" * 60 + "\n")
        return False

    print("\n✅ All checks passed.")
    print(f"   Port:       {config.host}:{config.port}")
    print(f"   Tools:      {len(TOOL_DEFINITIONS)} declared "
          f"({', '.join(t.name for t in TOOL_DEFINITIONS)})")
    print(f"   DLP mode:   {config.dlp_mode}"
          f"{' (some tools are withheld when no encryption is found)' if config.dlp_mode == 'auto' else ''}")
    print(f"   Transports: {', '.join(config.transports)}")
    print(f"   Public URL: {config.public_base_url or '(not configured — transfer tools return relative paths)'}")
    if config.tunnel.enabled:
        print(f"   Tunnel:     {config.tunnel.provider}"
              f"{' -> ' + config.tunnel.domain if config.tunnel.domain else ''}")
    else:
        print("   Tunnel:     disabled (start one yourself, or set tunnel.enabled)")
    print(f"   Rate limit:  {config.rate_limit} req/min")
    print(f"   Max read:   {config.max_file_size:,} bytes")
    print(f"   Bash timeout: {config.bash_timeout}s")
    print(f"   Log file:   {config.log_file}")
    print(f"   Allowed paths:")
    for p in config.resolved_allowed_paths:
        print(f"     • {p}")
    print("\n" + "=" * 60 + "\n")

    return True


# --------------------------------------------------------------------------- #
#  Console Encoding
# --------------------------------------------------------------------------- #

async def _send_plain(send: Any, status: int, message: str) -> None:
    """Send a minimal JSON error over raw ASGI."""
    import json as _json

    body = _json.dumps({"error": message}).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})


def force_utf8_io() -> None:
    """Force stdout/stderr to UTF-8 so non-ASCII output can never kill the process.

    On Windows, a redirected stdout (``Start-Process -RedirectStandardOutput``,
    ``> file``, a service wrapper) is opened with the *locale* encoding — GBK on
    a Chinese system.  The self-check banner contains ``⚠️``/``✅``/``❌``, which
    GBK cannot encode, so ``print()`` raised ``UnicodeEncodeError`` and the
    daemon died before it ever bound the port.  ``scripts/restart.ps1`` still
    reported success because it only checked that the process had been spawned.

    Reconfiguring with ``errors="replace"`` also guarantees that no future
    non-ASCII log line (Chinese paths, tool output) can crash the daemon.

    ``line_buffering`` is forced on for the same reason: a redirected stream is
    block-buffered, so the runtime log trails reality by up to 8 KB and looks
    empty exactly when you are trying to diagnose a startup failure.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(  # type: ignore[union-attr]
                encoding="utf-8", errors="replace", line_buffering=True
            )
        except (AttributeError, OSError, ValueError):
            # Stream is not a reconfigurable TextIOWrapper (already wrapped,
            # or detached).  Nothing to do — best effort only.
            pass


# --------------------------------------------------------------------------- #
#  Logging Setup
# --------------------------------------------------------------------------- #

def setup_logging(config: Config, verbose: bool = False) -> None:
    """Configure logging with both console and file output."""
    level = logging.DEBUG if verbose else logging.INFO

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root_logger.addHandler(console)

    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("mcp").setLevel(logging.INFO)


# --------------------------------------------------------------------------- #
#  Main Entry Point
# --------------------------------------------------------------------------- #

def main() -> None:
    """Parse arguments, run self-check, and start the server."""
    # Must run before any print()/logging — see force_utf8_io() docstring.
    force_utf8_io()

    parser = argparse.ArgumentParser(
        description=f"{SERVER_NAME} — local MCP server for cloud-to-local file bridging.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            f"  python {Path(__file__).name} --config {DEFAULT_CONFIG_PATH}\n"
            f"  python {Path(__file__).name} --config {DEFAULT_CONFIG_PATH} --check\n"
        ),
    )
    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to YAML config file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run self-check only, then exit (do not start server).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )
    tunnel_group = parser.add_mutually_exclusive_group()
    tunnel_group.add_argument(
        "--tunnel",
        dest="tunnel",
        action="store_true",
        default=None,
        help="Start the public tunnel alongside the daemon (overrides tunnel.enabled).",
    )
    tunnel_group.add_argument(
        "--no-tunnel",
        dest="tunnel",
        action="store_false",
        help="Do not start the tunnel, even if tunnel.enabled is true.",
    )
    args = parser.parse_args()

    # Load configuration
    try:
        config = Config.from_yaml(args.config)
    except ConfigError as e:
        print(f"❌ Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    setup_logging(config, verbose=args.verbose)

    # Self-check
    if not run_self_check(config):
        logger.error("Self-check failed. Fix the errors above and try again.")
        sys.exit(1)

    if args.check:
        logger.info("Self-check passed (--check mode, not starting server).")
        sys.exit(0)

    # --- Tunnel -------------------------------------------------------- #
    # Started before the app is built so a discovered public URL can fill in
    # public_base_url, which the transfer tools need to hand out absolute URLs.
    want_tunnel = config.tunnel.enabled if args.tunnel is None else args.tunnel
    tunnel: TunnelManager | None = None
    if want_tunnel:
        tunnel = TunnelManager(config.tunnel, config.port)
        try:
            public_url = tunnel.start()
        except TunnelError as exc:
            logger.error("Tunnel failed to start: %s", exc)
            logger.error("Fix the tunnel, or run with --no-tunnel to skip it.")
            sys.exit(1)

        if public_url and not config.public_base_url:
            config.public_base_url = public_url
            logger.info("public_base_url auto-detected from tunnel: %s", public_url)
        elif public_url and public_url.rstrip("/") != config.public_base_url:
            logger.warning(
                "Tunnel reports %s but public_base_url is configured as %s — "
                "transfer URLs will use the configured value.",
                public_url, config.public_base_url,
            )

    # Create and run the app
    logger.info("Starting %s v%s on %s:%d ...", SERVER_NAME, SERVER_VERSION, config.host, config.port)
    for transport in config.transports:
        endpoint = "/mcp" if transport == "streamable_http" else "/sse"
        logger.info("Transport %-16s http://%s:%d%s", transport, config.host, config.port, endpoint)
    logger.info("Health check: http://%s:%d/health", config.host, config.port)
    if config.public_base_url:
        for transport in config.transports:
            endpoint = "/mcp" if transport == "streamable_http" else "/sse"
            logger.info("Public URL (%s): %s%s?token=<auth_token>",
                        transport, config.public_base_url, endpoint)

    app = create_app(config)
    try:
        uvicorn.run(
            app,
            host=config.host,
            port=config.port,
            log_level="info" if not args.verbose else "debug",
        )
    finally:
        # The tunnel is a child of this process; never leave it orphaned.
        if tunnel is not None:
            tunnel.stop()


if __name__ == "__main__":
    main()
