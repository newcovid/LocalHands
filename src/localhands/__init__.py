"""LocalHands — a local MCP server that a cloud agent drives.

The reasoning runs somewhere else; this provides the hands. A cloud agent
connects over a tunnel and gets scoped, audited access to one real machine:
its files, its shell, its screen.
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "newcovid"

SERVER_NAME = "localhands"

__all__ = ["SERVER_NAME", "__author__", "__version__"]
