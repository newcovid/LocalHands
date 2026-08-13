"""Tool registry and dispatcher for LocalHands.

``ToolHandler`` is the single entry point the MCP server talks to.  It owns the
provider list, builds a name→provider routing table once at startup, and wraps
every call with the same audit logging and error containment.

Adding tools means adding a provider (see ``base.ToolProvider``), not touching
the dispatcher.

Every tool returns a JSON-serialised dict inside a TextContent block:
  • {"status": "success", …fields…}
  • {"status": "error", "error": "…", "error_type": "…"}

Binary payloads never pass through here — they move over the /download and
/upload endpoints — so a result stays small no matter how large the file it
describes.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from mcp.types import CallToolResult, TextContent, Tool

from ..config import Config
from ..security import OperationLogger, PathGuard, TransferTicketStore

from . import instructions as _instructions
from .base import LocalProvider, ProviderContext, ToolProvider, UnknownToolError
from .encryption import DEFAULT_MARKERS, parse_markers, probe_for_encryption
from .policy import annotate
from .desktop import DesktopProvider
from .files import FileProvider
from .media import MediaProvider
from .net import NetProvider
from .search import SearchProvider
from .shell import ShellProvider
from .xfer import TransferProvider

logger = logging.getLogger(__name__)

# Providers instantiated for every daemon, in the order their tools are
# advertised. A future UpstreamMcpProvider joins this list without any other
# change to the dispatcher.
PROVIDER_CLASSES: list[type[LocalProvider]] = [
    FileProvider,
    SearchProvider,
    ShellProvider,
    TransferProvider,
    MediaProvider,
    NetProvider,
    DesktopProvider,
]

# Every tool a provider *declares*. Some are withheld at runtime depending on
# what the machine turns out to have, so ask a live ToolHandler for the served
# set — this is the upper bound, useful for documentation and tests.
TOOL_DEFINITIONS: list[Tool] = [tool for cls in PROVIDER_CLASSES for tool in cls.tools]

# How much of a result is echoed into the audit log.
LOG_SUMMARY_CHARS = 200


class ToolHandler:
    """Routes MCP tool calls to providers and records every one of them."""

    def __init__(
        self,
        config: Config,
        path_guard: PathGuard,
        op_logger: OperationLogger,
        tickets: TransferTicketStore | None = None,
    ) -> None:
        dlp_active = self._resolve_dlp(config)
        ctx = ProviderContext(
            config=config,
            guard=path_guard,
            op_logger=op_logger,
            tickets=tickets,
            dlp_active=dlp_active,
        )
        self.dlp_active = dlp_active
        self.instructions = _instructions.build(dlp_active)
        self.config = config
        self.op_logger = op_logger
        self.providers: list[ToolProvider] = [cls(ctx) for cls in PROVIDER_CLASSES]

        self._route: dict[str, ToolProvider] = {}
        for provider in self.providers:
            for tool in provider.list_tools():
                if tool.name in self._route:
                    raise ValueError(
                        f"Tool {tool.name!r} declared by both "
                        f"{self._route[tool.name].name!r} and {provider.name!r}"
                    )
                self._route[tool.name] = provider

        logger.info(
            "Registered %d tools from %d providers: %s (DLP handling %s)",
            len(self._route),
            len(self.providers),
            ", ".join(p.name for p in self.providers),
            "on" if dlp_active else "off",
        )

    @staticmethod
    def _resolve_dlp(config: Config) -> bool:
        """Decide whether this machine has transparent encryption.

        'auto' samples real files rather than enumerating filter drivers: a
        marker in an actual file is direct evidence, needs no elevation, and
        does not require knowing which vendor's product is installed.
        """
        mode = getattr(config, "dlp_mode", "auto")
        if mode == "on":
            return True
        if mode == "off":
            return False
        markers = parse_markers(config.encrypted_file_markers) or DEFAULT_MARKERS
        return probe_for_encryption(config.resolved_allowed_paths, markers)

    @property
    def served_tools(self) -> list[Tool]:
        """The tools actually advertised, after runtime filtering and annotation."""
        return [
            annotate(tool)
            for provider in self.providers
            for tool in provider.list_tools()
        ]

    # ------------------------------------------------------------------ #
    #  MCP handler entry points
    # ------------------------------------------------------------------ #

    async def list_tools(self) -> list[Tool]:
        """Return every advertised tool schema, in provider order."""
        return self.served_tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        """Dispatch a tool call, audit it, and wrap the payload for the protocol.

        ``is_error`` is deliberately left False even for failed tools.  Every
        result already carries ``{"status": "error", "error_type": ...}`` in its
        JSON body, which is what the connected agent reads; flipping the
        protocol-level flag would change how the client surfaces failures, and
        that is a behavioural decision rather than a dispatch concern.
        """
        start = time.monotonic()
        status = "error"
        error_msg: str | None = None

        try:
            provider = self._route.get(name)
            if provider is None:
                result: dict[str, Any] = {
                    "status": "error",
                    "error": f"Unknown tool: {name}",
                    "error_type": "UnknownTool",
                }
            else:
                result = await provider.call(name, arguments)

            status = result.get("status", "error")
            error_msg = None if status == "success" else result.get("error", "Unknown error")
            result_text = json.dumps(result, ensure_ascii=False, default=str)

        except UnknownToolError as exc:
            error_msg, status = str(exc), "error"
            result_text = json.dumps(
                {"status": "error", "error": error_msg, "error_type": "UnknownTool"},
                ensure_ascii=False,
            )
        except TypeError as exc:
            # Almost always a bad argument set from the model (missing required
            # field, unexpected key). Report it as such instead of as a crash.
            logger.warning("Bad arguments for tool '%s': %s", name, exc)
            error_msg, status = f"Invalid arguments: {exc}", "error"
            result_text = json.dumps(
                {"status": "error", "error": error_msg, "error_type": "InvalidArguments"},
                ensure_ascii=False,
            )
        except Exception as exc:  # noqa: BLE001 — a tool must never kill the server
            logger.exception("Unhandled error in tool '%s'", name)
            error_msg, status = str(exc), "error"
            result_text = json.dumps(
                {"status": "error", "error": error_msg, "error_type": type(exc).__name__},
                ensure_ascii=False,
            )

        self.op_logger.log(
            tool=name,
            arguments=arguments,
            status=status,
            duration_ms=(time.monotonic() - start) * 1000,
            error=error_msg,
            result_summary=(
                result_text[:LOG_SUMMARY_CHARS] + "..."
                if len(result_text) > LOG_SUMMARY_CHARS
                else result_text
            ),
        )
        return CallToolResult(content=[TextContent(type="text", text=result_text)])


__all__ = [
    "PROVIDER_CLASSES",
    "TOOL_DEFINITIONS",
    "LocalProvider",
    "ProviderContext",
    "ToolHandler",
    "ToolProvider",
]
