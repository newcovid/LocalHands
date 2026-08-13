"""Shared fixtures for the LocalHands test suite.

Everything here is built in-process from ``tmp_path``.  No test starts the
daemon, opens a socket, or launches a tunnel, and the real
``config.yaml`` is deliberately never read — a suite that depended on
the operator's live whitelist would pass or fail for reasons unrelated to the
code under test, and a live daemon may already own port 8765.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Sequence

import pytest

from localhands.config import Config
from localhands.security import OperationLogger, PathGuard, TransferTicketStore
from localhands.tools import ToolHandler

# Long enough that Config does not emit its "token is short" warning,
# so a genuine warning in a test run means something.
TEST_TOKEN = "t" * 32

# Never 8765: the operator's real daemon owns that port. Nothing in this suite
# binds a socket, but a stray port number in a config is an invitation.
TEST_PORT = 18765


# ====================================================================== #
#  Configuration, guard, logger, dispatcher
# ====================================================================== #

@pytest.fixture
def allowed_root(tmp_path: Path) -> Path:
    """The single whitelisted directory every tool is allowed to touch."""
    root = tmp_path / "allowed"
    root.mkdir()
    return root


@pytest.fixture
def outside_root(tmp_path: Path) -> Path:
    """A directory that is *not* whitelisted, holding bait for escape attempts."""
    root = tmp_path / "outside"
    root.mkdir()
    (root / "secret.txt").write_text("classified\n", encoding="utf-8")
    return root


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    """Audit log location.  The parent is intentionally absent — OperationLogger
    is expected to create it."""
    return tmp_path / "logs" / "ops.log"


@pytest.fixture
def make_config(
    allowed_root: Path,
    log_path: Path,
) -> Callable[..., Config]:
    """Factory for a valid config, with per-test overrides by keyword."""

    def _make(**overrides: Any) -> Config:
        data: dict[str, Any] = {
            "auth_token": TEST_TOKEN,
            "allowed_paths": [str(allowed_root)],
            "log_file": str(log_path),
            "port": TEST_PORT,
            "bash_timeout": 5,
            # Small enough that the truncation paths are reachable without
            # writing megabytes to disk.
            "max_file_size": 65_536,
            "public_base_url": "https://bridge.example",
        }
        data.update(overrides)
        return Config.from_dict(data)

    return _make


@pytest.fixture
def config(make_config: Callable[..., Config]) -> Config:
    """A valid config whose only allowed path is ``allowed_root``."""
    return make_config()


@pytest.fixture
def guard(config: Config) -> PathGuard:
    """PathGuard bound to the temporary whitelist."""
    return PathGuard(config)


@pytest.fixture
def op_logger(log_path: Path) -> OperationLogger:
    """Audit logger with rotation off, so tool tests see every record."""
    return OperationLogger(str(log_path), max_bytes=0)


@pytest.fixture
def tickets() -> TransferTicketStore:
    """Ticket store with a short cap, so eviction is cheap to provoke."""
    return TransferTicketStore(ttl=60, max_outstanding=32)


@pytest.fixture
def handler(
    config: Config,
    guard: PathGuard,
    op_logger: OperationLogger,
    tickets: TransferTicketStore,
) -> ToolHandler:
    """The real dispatcher, wired exactly as the daemon wires it."""
    return ToolHandler(config, guard, op_logger, tickets)


@pytest.fixture
def call_tool(
    handler: ToolHandler,
) -> Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]:
    """Call a tool through the dispatcher and return its decoded JSON payload.

    Every tool answers with a single ``TextContent`` block holding a JSON
    object; unwrapping it here keeps the assertions in the tests about
    behaviour rather than about the MCP envelope.
    """

    async def _call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = await handler.call_tool(name, arguments)
        assert result.content, f"{name} returned no content block"
        payload = json.loads(result.content[0].text)
        assert isinstance(payload, dict)
        return payload

    return _call


# ====================================================================== #
#  Filesystem helpers
# ====================================================================== #

@pytest.fixture
def write_lines() -> Callable[[Path, Sequence[str]], Path]:
    """Write text with LF endings, bypassing Windows newline translation.

    ``Path.write_text`` would turn every ``\\n`` into ``\\r\\n`` here, which
    silently changes byte counts and makes line-oriented assertions lie.
    """

    def _write(path: Path, lines: Sequence[str]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes("".join(f"{line}\n" for line in lines).encode("utf-8"))
        return path

    return _write


@pytest.fixture
def make_symlink() -> Callable[[Path, Path], Path]:
    """Create a symlink, or skip the test if Windows refuses without privileges.

    Symlink creation needs Developer Mode or an elevated shell on Windows, and
    the whole point of the tests that use this is the escape attempt — a
    fabricated substitute would not exercise ``Path.resolve``.
    """

    def _link(link: Path, target: Path) -> Path:
        try:
            link.symlink_to(target, target_is_directory=target.is_dir())
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"platform refuses symlink creation: {exc}")
        return link

    return _link


# ====================================================================== #
#  In-process ASGI driver (no socket, no server)
# ====================================================================== #

@dataclass
class AsgiResult:
    """What an ASGI app sent back, flattened for assertions."""

    status: int = 0
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        """Return a header value as text, or None if absent (case-insensitive)."""
        wanted = name.lower().encode()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value.decode("latin-1")
        return None

    def json(self) -> Any:
        """Decode the response body as JSON."""
        return json.loads(self.body.decode("utf-8"))


@pytest.fixture
def http_scope() -> Callable[..., dict[str, Any]]:
    """Build a minimal ASGI HTTP scope."""

    def _scope(
        path: str = "/",
        method: str = "GET",
        query: str = "",
        headers: Sequence[tuple[bytes, bytes]] | None = None,
    ) -> dict[str, Any]:
        return {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "path": path,
            "query_string": query.encode("utf-8"),
            "headers": list(headers or []),
            "client": ("127.0.0.1", 51234),
        }

    return _scope


@pytest.fixture
def run_asgi() -> Callable[..., Awaitable[AsgiResult]]:
    """Drive an ASGI callable in-process and collect its response.

    This replaces the whole server stack: the app under test cannot tell the
    difference, and nothing binds a port.
    """

    async def _run(
        app: Callable[..., Awaitable[None]],
        scope: dict[str, Any],
        body: bytes | Sequence[bytes] = b"",
    ) -> AsgiResult:
        chunks: list[bytes] = [body] if isinstance(body, bytes) else list(body)
        result = AsgiResult()

        async def receive() -> dict[str, Any]:
            if chunks:
                chunk = chunks.pop(0)
                return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}
            # An exhausted client is a disconnect, which is what the upload
            # handler must cope with rather than hanging.
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                result.status = message["status"]
                result.headers = list(message.get("headers", []))
            elif message["type"] == "http.response.body":
                result.body += message.get("body", b"")

        await app(scope, receive, send)
        return result

    return _run


@pytest.fixture
def downstream_app() -> Any:
    """A stand-in for the wrapped MCP app, recording whether it was reached.

    Middleware tests care about exactly one thing: did the request get past the
    guard.  ``scopes`` answers that without needing the real server.
    """

    class _Recorder:
        def __init__(self) -> None:
            self.scopes: list[dict[str, Any]] = []

        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            self.scopes.append(scope)
            body = b'{"reached": true}'
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})

        @property
        def reached(self) -> bool:
            return bool(self.scopes)

    return _Recorder()
