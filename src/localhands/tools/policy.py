"""Per-tool behavioural metadata, kept in one table rather than 23 constructors.

Two things live here.

**Standard MCP annotations.** ``ToolAnnotations`` carries ``readOnlyHint``,
``destructiveHint``, ``idempotentHint`` and ``openWorldHint``. Clients use them
to decide what to confirm with a human and what to retry on their own, so
getting them right is worth more than the descriptions in some clients and
nothing at all in others.

**Whether a call is visible to the person at the machine.** This server drives a
real workstation, and a handful of tools put a window in front of whoever is
sitting there or read what is already on their screen. That distinction is not
in the MCP spec, so it travels in ``_meta`` and — because a client may ignore
``_meta`` entirely — is also stated in the description of each affected tool.

Keeping the table separate from the tool definitions means the answer to "what
can this server do to my machine without asking" is one screen of text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Namespace for the non-standard hints, per the MCP convention for _meta keys.
META_PREFIX = "localhands.dev/"


@dataclass(frozen=True)
class ToolPolicy:
    """How a tool behaves, beyond what its schema says."""

    title: str

    # --- Standard MCP hints ---
    read_only: bool = False
    """Leaves the user's data untouched. Staging copies under %TEMP% do not
    count: nothing the user would miss changes."""

    destructive: bool = False
    """A call can overwrite or remove data that already existed."""

    idempotent: bool = False
    """Calling twice with the same arguments changes nothing the first call did
    not already change."""

    open_world: bool = False
    """Reaches something outside this machine, or opens a door for something
    outside to reach in."""

    # --- Local, non-standard ---
    user_visible: bool = False
    """Puts something on the screen of whoever is at the machine."""

    reads_screen: bool = False
    """Captures the user's screen, including windows unrelated to the task."""


P = ToolPolicy

POLICIES: dict[str, ToolPolicy] = {
    # ---- Reading: safe, repeatable, invisible ----
    "read_file":        P("Read file", read_only=True, idempotent=True),
    "read_many_files":  P("Read several files", read_only=True, idempotent=True),
    "glob":             P("Find files by name", read_only=True, idempotent=True),
    "grep":             P("Search file contents", read_only=True, idempotent=True),
    "list_directory":   P("List directory", read_only=True, idempotent=True),
    "get_project_tree": P("Show directory tree", read_only=True, idempotent=True),
    "scan_encrypted":   P("Find unreadable files", read_only=True, idempotent=True),
    "image_info":       P("Inspect image", read_only=True, idempotent=True),

    # ---- Writing: changes the user's files ----
    # write_file replaces a whole file, so an imprecise call loses content the
    # caller never read. edit_file and multi_edit only touch the span they
    # matched, but a second identical call fails rather than repeating cleanly.
    "write_file":       P("Write file", destructive=True, idempotent=True),
    "edit_file":        P("Edit file"),
    "multi_edit":       P("Edit file (multiple)"),

    # ---- Relocation and deletion ----
    # overwrite=true deletes whatever is at the destination first, including a
    # whole directory tree, which is why copy is marked destructive too.
    "move_path":        P("Move or rename", destructive=True),
    "copy_path":        P("Copy", destructive=True),
    "delete_path":      P("Delete", destructive=True),

    # ---- Shell ----
    "run_bash":         P("Run shell command", destructive=True),

    # ---- Transfer: opens an HTTP door for the caller ----
    # prepare_upload authorises a write that has not happened yet, so it is not
    # read-only even though the call itself writes nothing.
    "prepare_download": P("Share a local file", read_only=True, open_world=True),
    "prepare_upload":   P("Receive a file", destructive=True, open_world=True),
    "download_file":    P("Download a URL", destructive=True, open_world=True),

    # ---- Images ----
    # read_image and screenshot only write a staging copy under %TEMP%.
    "read_image":       P("View a local image", read_only=True, open_world=True),
    "process_image":    P("Crop or resize an image", destructive=True),
    "screenshot":       P("Capture the screen", read_only=True, open_world=True,
                          reads_screen=True),

    # ---- Things the person at the machine will notice ----
    "open_path":        P("Open on the desktop", user_visible=True),
    "notify":           P("Alert the user", user_visible=True),
}


def annotate(tool: Any) -> Any:  # noqa: ANN401 — mcp.types.Tool, imported lazily
    """Return a copy of ``tool`` carrying its policy as annotations and _meta.

    A copy rather than a mutation: the ``Tool`` objects are class attributes
    shared by every provider instance, so writing to one would leak across
    daemons in the same process — which the test suite does routinely.
    """
    from mcp.types import ToolAnnotations

    policy = POLICIES.get(tool.name)
    if policy is None:
        return tool

    meta = dict(tool.meta or {})
    if policy.user_visible:
        meta[META_PREFIX + "userVisible"] = True
    if policy.reads_screen:
        meta[META_PREFIX + "readsScreen"] = True

    return tool.model_copy(update={
        "title": policy.title,
        "annotations": ToolAnnotations(
            title=policy.title,
            read_only_hint=policy.read_only,
            destructive_hint=policy.destructive,
            idempotent_hint=policy.idempotent,
            open_world_hint=policy.open_world,
        ),
        "meta": meta or None,
    })
