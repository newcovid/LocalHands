"""The server-level guidance sent to a client in the initialize response.

MCP lets a server return an ``instructions`` string alongside its capabilities,
and clients generally fold it into the system prompt. That is the right home for
anything that is true of the whole server rather than of one tool: repeating it
in every tool description costs context on each turn and still only reaches the
model once it has already decided which tool to call.

What stays in the tool descriptions is the operational half — *what command to
run*. Only the rationale moves here. A client that ignores ``instructions``
therefore still gets working tools; it just loses the explanation.
"""

from __future__ import annotations

BASE = """\
This server runs on a person's real workstation. Files you change are their real
files, and windows you open appear on their real screen.

MOVING BYTES
Never put file bytes into a tool argument, and never ask for them in a result.
Base64 in an argument is emitted token by token: a 500 KB image becomes roughly
680,000 characters, costing hundreds of thousands of output tokens and tens of
seconds. Use the transfer tools instead — prepare_download to fetch a local
file, prepare_upload to deliver one you produced, download_file to have the
daemon pull a public URL straight to disk. Each returns a ready-to-run command
in its 'curl' field; run that command verbatim, because it carries a header the
tunnel requires. Those URLs work exactly once and expire within minutes.

TOOLS THE USER CAN SEE
Most tools are silent background operations. Three are not, and interrupt
whoever is sitting at the machine:
  notify      puts a dialog on their desktop that stays until they dismiss it
  open_path   launches an application and brings its window to the foreground
  screenshot  captures whatever is on screen right now, including windows that
              have nothing to do with the task
Use these only when a human is meant to look at something. To inspect a file
yourself, use read_file or prepare_download — those interrupt no one.

SCOPE AND SAFETY
File access is confined to a configured whitelist; a path outside it fails with
PathGuardError rather than being silently redirected elsewhere. delete_path
moves things to a recycle bin and returns trash_path unless permanent=true. A
short list of irreversible shell commands is refused outright. When a tool
refuses, it is reporting a real boundary — reaching the same result another way
is not the intent.

SPENDING FEWER TURNS
Every tool call is a full round trip. Prefer read_many_files over a run of
read_file calls, and multi_edit over a run of edit_file calls on one file.
For search, start with grep in files_with_matches mode and only switch to
content once you know which files matter."""

DLP = """\

THIS MACHINE ENCRYPTS SOME FILES
A transparent-encryption (DLP) driver is active here. Files written by protected
applications — office suites, CAD and engineering tools, and similar — reach this
daemon as ciphertext, and reading one returns a FileEncrypted error rather than
its contents.

Copying such a file does not decrypt it: the ciphertext is the file's content, so
the copy is encrypted too, wherever it lands. Retrying, or reading it with a
different tool, will not help either. The only route to readable bytes is to
re-export the file from the application that owns it, saving into the staging
directory named in the error — that path is excluded from the driver.

Run scan_encrypted over a directory before planning work across its documents,
so you learn which files are readable in one call instead of discovering it one
failure at a time."""


def build(dlp_active: bool) -> str:
    """Assemble the instructions for this machine's actual configuration.

    The DLP section is withheld on a machine that has none. Most machines do,
    and describing ciphertext the agent will never encounter is both wasted
    context and an invitation to call a tool that can only return zero.
    """
    return BASE + (DLP if dlp_active else "")
