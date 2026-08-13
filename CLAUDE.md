# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

LocalHands is a local MCP **server**: a cloud agent (Feishu Aily / Kimi K3 / any MCP client)
connects over a tunnel and drives this workstation through 23 tools. The reasoning is remote;
this process is the hands. Read `README.md` for the product-level rationale — this file covers
what you need to change the code.

## Commands

The project virtualenv holds the pinned `mcp` 2.x; a bare `python` may have the wrong one.

```powershell
.venv\Scripts\python.exe -m pip install -e ".[dev]"

.venv\Scripts\python.exe -m pytest tests/ -q                      # 222 tests, no daemon/network/tunnel
.venv\Scripts\python.exe -m pytest tests/test_tools.py::TestEditFile -q          # one class
.venv\Scripts\python.exe -m pytest tests/test_tools.py -k "encrypted" -q         # by name

.venv\Scripts\python.exe -m localhands --config config.yaml --check   # validate config, don't serve
.venv\Scripts\python.exe -m localhands --config config.yaml           # serve (+ tunnel if enabled)
.venv\Scripts\python.exe -m localhands --config config.yaml --no-tunnel -v

ruff check .        # config lives in pyproject.toml; ruff is not a declared dev dep
```

`scripts\restart.ps1` kills whatever holds the port, sweeps orphaned `ngrok`/`cloudflared`,
relaunches detached, then **polls `/health` until it answers** before reporting success. Use it
rather than restarting by hand — it is the only path that verifies the daemon actually serves.
Status and log tails land in `var/logs/restart.txt`.

`config.yaml` is gitignored (it carries the auth token and machine paths); `config.example.yaml`
is the documented template and the file to update when adding a config key.

## Architecture

### Request path

```
tunnel → RateLimitMiddleware → BearerAuthMiddleware → asgi_router
                                                        ├─ /mcp          → StreamableHTTPSessionManager
                                                        ├─ /sse, /messages/ → SseServerTransport
                                                        ├─ /download/<t>, /upload/<t> → TransferEndpoints
                                                        └─ everything else → Starlette (/health, /)
```

`create_app()` in `daemon.py` wires this. The SSE and streamable-HTTP routes are handled by a
hand-rolled ASGI router rather than Starlette `Mount`, because `Mount("/sse")` makes the transport
advertise `/sse/messages/` as the POST URL. Both transports run at once so already-registered
clients keep working.

Two auth carve-outs, both deliberate: `/health` is public, and `/download` / `/upload` skip the
bearer check because their one-time ticket *is* the credential (putting the long-lived token in a
URL would leak it into the remote sandbox's shell history).

### Tools: provider pattern

`tools/__init__.py` holds `ToolHandler` — the single object the MCP server talks to. It builds a
`name → provider` route table once at startup, then wraps every call with audit logging and
blanket error containment (a tool must never kill the server).

To add a tool:

1. Subclass `LocalProvider` (`tools/base.py`): set `name`, add a `Tool(...)` to `tools`, and
   implement a method named `_<tool_name>`. Sync methods are dispatched through
   `asyncio.to_thread`; `async def` methods are awaited directly.
2. Register the class in `PROVIDER_CLASSES`.
3. **Add an entry to `POLICIES` in `tools/policy.py`** — a tool missing from that table ships with
   no MCP annotations at all. That one table is the answer to "what can this server do to my
   machine without asking".

The dispatcher, audit log, and error handling need no changes. The same seam is how an upstream
MCP server would be proxied: implement the three members of the `ToolProvider` protocol, namespace
the names, apply `PathGuard` to path arguments, register alongside the local providers.

### Invariants worth not breaking

- **Every tool returns a dict via `ok(...)` / `err(...)`** from `tools/base.py`, serialised into a
  single `TextContent` block. `error_type` is a stable machine-readable tag the connected agent
  keys its recovery on — reuse an existing tag rather than coining a synonym.
- **`is_error` on `CallToolResult` stays `False` even for failed tools.** The JSON body already
  carries `status`/`error_type`; flipping the protocol flag changes how clients surface failures.
- **Bytes never travel through a tool result or argument.** `prepare_download` / `prepare_upload`
  mint a one-time ticket and return a ready-to-run `curl` command carrying the
  `ngrok-skip-browser-warning` header. Anything that needs to move a file goes through
  `transfer.py`, not through the model's context.
- **Any path from the model goes through `PathGuard.check()`**, which fully resolves symlinks and
  `..` before the prefix test. Transfer tickets re-check at redemption as well as at minting.
- **`Tool` objects are class attributes shared across provider instances.** `policy.annotate()`
  returns `model_copy(...)`; never mutate a `Tool` in place — the test suite builds several
  handlers in one process.
- Result caps (`MAX_GREP_RESULTS`, `MAX_GLOB_RESULTS`, `MAX_TREE_ENTRIES`, `BASH_OUTPUT_CAP`) live
  in `tools/base.py` so no single tool can flood the model's context.

### Runtime-conditional tool surface

The advertised tool list is **not** static. `ToolHandler._resolve_dlp()` samples the whitelisted
directories for transparent-encryption magic bytes at startup (`dlp_mode: auto | on | off`), and
providers withhold anything listed in their `requires_dlp` set when the machine turns out to be
clean. `MediaProvider.list_tools()` additionally drops `screenshot` when
`screenshot_enabled: false`. `tools/instructions.py` likewise appends its DLP section only when
relevant. So
`/health` and the startup banner ask the live handler for `served_tools`; `TOOL_DEFINITIONS` is
the declared upper bound, useful for tests and docs only.

Server-level guidance (what applies to the whole server, not one tool) belongs in
`tools/instructions.py`, which reaches the model via the initialize response and usually the
system prompt. Per-tool operational detail stays in the tool description.

### mcp 2.x, not 1.x

The floor `mcp>=2.0` in `pyproject.toml` is load-bearing, not hygiene. 2.x is a rewrite: the
low-level `Server` takes `on_list_tools` / `on_call_tool` constructor arguments instead of
decorators, handlers receive `(request_context, params)`, results are not auto-wrapped
(each handler builds its own `*Result`), and model fields are snake_case. Don't relax it without
revisiting `create_mcp_server()` and every `Tool` definition.

`_enable_sse_keepalive()` monkey-patches `mcp.server.sse.EventSourceResponse` to force a ping
interval — the SDK passes none, so idle SSE connections get dropped by the tunnel and the client
reuses a dead session (protocol error 210204). Streamable HTTP has no such problem.

## Testing conventions

Fixtures in `tests/conftest.py` build everything from `tmp_path`. Nothing binds a socket, starts
a daemon, or launches a tunnel, and the real `config.yaml` is never read — the operator's live
whitelist must not decide whether tests pass. Test port is 18765, never 8765.

- `call_tool` drives the **real dispatcher** and returns the decoded JSON payload, so assertions
  are about behaviour rather than the MCP envelope. Prefer it over calling provider methods.
- `run_asgi` + `http_scope` drive middleware and transfer endpoints in-process.
- Use the `write_lines` fixture for test files: `Path.write_text` translates `\n` to `\r\n` on
  Windows, which silently breaks byte counts and line-oriented assertions.
- `filterwarnings = ["error::DeprecationWarning"]` — a DeprecationWarning fails the run.
- `asyncio_mode = "auto"`; no `@pytest.mark.asyncio` needed.

## Windows specifics

Development and deployment target Windows. `force_utf8_io()` runs before any output in `main()`
because a redirected stdout opens with the locale encoding (GBK here) and the self-check banner's
emoji would kill the daemon before it bound the port. `run_bash` uses `shell=True` with a process
group so `taskkill /T` can reach descendants — a plain `subprocess.run` timeout only kills the
shell and then blocks on the grandchild's inherited pipe. `_decode_text` tries GBK after UTF-8
because legacy Chinese encodings are common in the files this daemon reads.
