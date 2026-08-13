"""Shared plumbing for tool providers.

A *provider* is a group of related tools that share an implementation concern —
file editing, search, shell, binary transfer.  ``ToolHandler`` owns a list of
them and routes each incoming call to whichever provider declared that tool.

The point of the indirection is extensibility.  Everything a provider must
supply is in :class:`ToolProvider`: a name, a list of schemas, and an async
``call``.  A future provider that proxies an *upstream* MCP server — anything
speaking stdio or HTTP — implements the same three members and registers
alongside the local ones; the dispatcher, the audit log, and the error handling
do not change to accommodate it.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from mcp.types import Tool

from ..config import Config
from ..security import OperationLogger, PathGuard, PathGuardError, TransferTicketStore

logger = logging.getLogger(__name__)

# Result caps, shared so no single tool can flood the model's context.
MAX_GREP_RESULTS = 200
MAX_GLOB_RESULTS = 500
MAX_TREE_ENTRIES = 2000
BASH_OUTPUT_CAP = 512 * 1024  # bytes per stream


class UnknownToolError(Exception):
    """Raised when a call names a tool no provider declares."""


@dataclass
class ProviderContext:
    """Everything a provider needs from the daemon, passed in once at startup."""

    config: Config
    guard: PathGuard
    op_logger: OperationLogger
    tickets: TransferTicketStore | None = None
    # Resolved once at startup rather than per call: whether this machine
    # actually has transparent encryption. Providers use it to withhold tools
    # and guidance that would be dead weight on a clean machine.
    dlp_active: bool = False

    @property
    def default_root(self) -> Path:
        """Directory used when a tool's ``path`` argument is omitted."""
        roots = self.config.resolved_allowed_paths
        return roots[0] if roots else Path.cwd()


@runtime_checkable
class ToolProvider(Protocol):
    """The contract every tool group implements."""

    name: str

    def list_tools(self) -> list[Tool]:
        """Return the schemas this provider serves."""
        ...

    async def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        """Execute one tool.  Returns a JSON-serialisable dict, or a
        ``CallToolResult`` to bypass the default serialisation."""
        ...


class LocalProvider:
    """Base class for providers implemented in this process.

    Subclasses declare ``name`` and ``tools``, then implement one method per
    tool named ``_<tool_name>``.  Synchronous methods are run on a worker thread
    so a slow filesystem or subprocess never stalls the event loop; a method
    written as ``async def`` is awaited directly.

    Attribute names deliberately mirror what the tool bodies already used
    (``self.config``, ``self.guard``, ``self.logger``) so implementations read
    the same whether or not they have been split into their own module.
    """

    name: str = "local"
    tools: list[Tool] = []

    # Tools that are only worth advertising when this machine actually has a
    # transparent-encryption driver. On a clean machine such a tool can only
    # ever return zero, so advertising it spends context and invites calls that
    # cannot tell the agent anything.
    requires_dlp: frozenset[str] = frozenset()

    def __init__(self, ctx: ProviderContext) -> None:
        self.ctx = ctx
        self.config = ctx.config
        self.guard = ctx.guard
        self.logger = ctx.op_logger
        self.tickets = ctx.tickets
        self.dlp_active = ctx.dlp_active
        self._default_root = ctx.default_root

    def list_tools(self) -> list[Tool]:
        if self.dlp_active or not self.requires_dlp:
            return self.tools
        return [t for t in self.tools if t.name not in self.requires_dlp]

    async def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        method = getattr(self, f"_{tool}", None)
        if method is None:
            raise UnknownToolError(f"{self.name} provider has no handler for {tool!r}")
        if inspect.iscoroutinefunction(method):
            return await method(**arguments)
        return await asyncio.to_thread(method, **arguments)

    # ------------------------------------------------------------------ #
    #  Helpers shared across providers
    # ------------------------------------------------------------------ #

    def _resolve_root(self, path: str | None) -> Path | dict[str, Any]:
        """Resolve a root directory argument, defaulting to the first allowed path.

        Returns an error dict rather than raising, because every caller forwards
        it straight back as the tool result.
        """
        if path is None:
            return self._default_root
        try:
            return self.guard.check(path)
        except PathGuardError as e:
            return err(str(e), "PathGuardError")


# ====================================================================== #
#  Result helpers
# ====================================================================== #

def ok(**fields: Any) -> dict[str, Any]:
    """Build a success payload."""
    return {"status": "success", **fields}


def err(message: str, error_type: str, **fields: Any) -> dict[str, Any]:
    """Build an error payload.

    ``error_type`` is a stable machine-readable tag; the connected agent keys
    its recovery behaviour off it, so prefer reusing an existing tag over
    inventing a near-synonym.
    """
    return {"status": "error", "error": message, "error_type": error_type, **fields}
