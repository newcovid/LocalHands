<div align="center">

# LocalHands

**The reasoning runs somewhere else. This provides the hands.**

A local MCP server that lets a cloud AI agent operate one real machine — read and edit
files, run commands, capture the screen, move binaries in and out — over a tunnel,
behind a path whitelist, a command guard, and an audit log.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-2.x-000000)](https://modelcontextprotocol.io/)
[![Tests](https://img.shields.io/badge/tests-222%20passing-4c1)](#running-the-tests)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)](#requirements)

**English** · [简体中文](README.zh-CN.md)

</div>

---

## Table of contents

- [What it is](#what-it-is)
- [Why it exists](#why-it-exists)
- [Quick start](#quick-start)
- [Connecting a client](#connecting-a-client)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [Tool reference](#tool-reference)
- [How it works](#how-it-works)
- [Security model](#security-model)
- [Working with transparent encryption (DLP)](#working-with-transparent-encryption-dlp)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## What it is

Most AI integrations put a local agent in charge and give it cloud tools. LocalHands
inverts that. The reasoning runs on a cloud platform — Feishu Aily, Kimi, Claude, or any
MCP client — and this daemon is the pair of hands it borrows on your workstation.

```
   cloud agent  ──►  MCP over HTTPS  ──►  tunnel  ──►  LocalHands  ──►  your machine
                                                        │
                              rate limit → bearer token → path whitelist
                                       → command guard → audit log
```

Twenty-three tools, one config file, no telemetry, no external service beyond the tunnel
you choose.

## Why it exists

`claude mcp serve` already exposes a local machine over MCP, and for many people it is
enough. LocalHands was built after measuring three things that got in the way:

| | `claude mcp serve` | LocalHands |
|---|---|---|
| Tool schemas on every turn | 30 tools, ~70 000 characters (~20 k tokens) | 23 tools, scoped to driving a workstation |
| Authentication | none | bearer token, constant-time compared |
| Filesystem scope | unrestricted | whitelist, symlinks resolved before the check |
| Audit trail | none | JSONL, one line per call, rotated |
| Binary payloads | through the model's context | out-of-band HTTP, one-time URLs |

The token figure matters more than it looks: that context is spent on **every single
turn**, and most of it is irrelevant to operating a machine (`Workflow` alone is 19 378
characters).

---

## Quick start

Five minutes, from nothing to a cloud agent holding your files.

### Requirements

- **Python 3.10+**
- **Windows 10/11** (primary target) or **Linux** — the desktop tools and process handling
  are Windows-tuned; everything else is portable
- A tunnel binary if you want the daemon to publish itself: [`ngrok`](https://ngrok.com/download)
  or [`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
- *Optional:* [ripgrep](https://github.com/BurntSushi/ripgrep) on `PATH` — `grep` uses it
  automatically and falls back to a pure-Python matcher without it

### 1. Install

```powershell
git clone https://github.com/newcovid/LocalHands.git
cd LocalHands

python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
```

<details>
<summary>Linux / macOS</summary>

```bash
git clone https://github.com/newcovid/LocalHands.git
cd LocalHands

python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

Substitute `.venv/bin/python` for `.venv\Scripts\python.exe` in every command below.
</details>

### 2. Configure

```powershell
copy config.example.yaml config.yaml
```

Two settings are mandatory. Everything else has a working default.

```yaml
# Generate one with:
#   python -c "import secrets; print(secrets.token_urlsafe(32))"
auth_token: "paste-a-long-random-token-here"

# Every file tool is confined to these directories.
allowed_paths:
  - "C:/Users/you/projects"
  - "%TEMP%"
```

> [!IMPORTANT]
> `run_bash` is arbitrary code execution by design, so `auth_token` is equivalent to a
> shell password on this machine. Generate it randomly, keep it out of version control
> (`config.yaml` is gitignored), and rotate it if it ever leaks.

`%TEMP%` is worth whitelisting: image staging and DLP re-exports land there.

### 3. Verify before serving

```powershell
.venv\Scripts\python.exe -m localhands --config config.yaml --check
```

This validates the config, checks every dependency, confirms the port is free, confirms
the tunnel binary is runnable, and prints exactly what would be served — then exits
without starting anything.

```
============================================================
  localhands v1.0.0 — Self-Check
============================================================

✅ All checks passed.
   Port:       127.0.0.1:8765
   Tools:      23 declared (read_file, write_file, edit_file, ...)
   DLP mode:   auto (some tools are withheld when no encryption is found)
   Transports: sse, streamable_http
   ...
```

### 4. Run

```powershell
.venv\Scripts\python.exe -m localhands --config config.yaml
```

Installed as a package, `localhands --config config.yaml` works too.

| Flag | Effect |
|---|---|
| `--config`, `-c` | Path to the YAML config (default `config.yaml`) |
| `--check` | Validate and report, then exit without serving |
| `--verbose`, `-v` | DEBUG-level logging |
| `--tunnel` / `--no-tunnel` | Override `tunnel.enabled` for this run |

Confirm it is alive:

```powershell
curl http://127.0.0.1:8765/health
```

```json
{"status":"ok","server":"localhands","version":"1.0.0","tool_count":22,"tools":["read_file", "..."],"dlp_handling":false}
```

### 5. Publish it

The daemon binds to loopback. Something has to put it on the internet for the cloud agent
to reach.

**Let the daemon manage the tunnel** (recommended — one process, one lifecycle):

```yaml
tunnel:
  enabled: true
  provider: ngrok          # ngrok | cloudflared | custom
  executable: ""           # empty = look on PATH
  domain: ""               # a reserved domain, if your plan has one
```

Now `python -m localhands --config config.yaml` starts both, the tunnel dies with the
daemon, and `public_base_url` is filled in automatically from the tunnel's own API — which
the transfer tools need in order to hand out absolute URLs.

**Or run your own tunnel** and tell the daemon where it lives:

```yaml
tunnel:
  enabled: false
public_base_url: "https://your-domain.example"
```

---

## Connecting a client

Register this URL with your MCP client:

```
https://<your-domain>/mcp?token=<auth_token>
```

| Endpoint | Method | Purpose |
|---|---|---|
| `/mcp` | `GET` `POST` `DELETE` | Streamable HTTP transport — **prefer this** |
| `/sse` | `GET` | Legacy HTTP+SSE transport |
| `/messages/` | `POST` | JSON-RPC channel paired with `/sse` |
| `/health` | `GET` | Liveness and the live tool list — **public, no token** |
| `/` | `GET` | Server info, transports, whitelist |
| `/download/{ticket}` | `GET` | One-time byte pull (ticket is the credential) |
| `/upload/{ticket}` | `PUT` `POST` | One-time byte push (ticket is the credential) |

Both transports run at once, so a client already registered against `/sse` keeps working
while new ones are pointed at `/mcp`. Prefer Streamable HTTP for anything new: SSE holds
one connection open indefinitely, tunnels drop idle connections, and the client then
reuses a dead session and stalls. (A keepalive ping, `sse_ping_interval`, mitigates this
for clients that can only speak SSE.)

Authentication accepts either form:

```
Authorization: Bearer <auth_token>     # preferred
?token=<auth_token>                    # for clients that can only be given a URL
```

Set `allow_query_token: false` to require the header.

---

## Deployment

### Windows — restart and verify

```powershell
powershell -ExecutionPolicy Bypass -File scripts\restart.ps1
```

`scripts/restart.ps1` reads the port out of `config.yaml`, kills whatever is listening on
it, sweeps up orphaned `ngrok`/`cloudflared` processes, relaunches the daemon detached —
and then **polls `/health` until it actually answers** before reporting success. It does
not assume the process it spawned survived startup.

Exit code `0` means healthy. On failure it writes the reason and the tail of both logs to
`var/logs/restart.txt`.

### Windows — start at logon

Task Scheduler, in one line:

```powershell
schtasks /Create /TN LocalHands /SC ONLOGON /RL HIGHEST /F `
  /TR "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\path\to\LocalHands\scripts\restart.ps1"
```

### Linux — systemd

```ini
# /etc/systemd/system/localhands.service
[Unit]
Description=LocalHands MCP daemon
After=network-online.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/opt/localhands
ExecStart=/opt/localhands/.venv/bin/python -m localhands --config config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now localhands
```

### Runtime state

Everything the daemon writes lives under `var/`, which is gitignored:

```
var/logs/ops.log       JSONL audit record — one line per tool call, rotated at log_max_bytes
var/logs/runtime.log   stdout of the daemon, truncated per restart
var/logs/tunnel.log    tunnel child process output
var/logs/restart.txt   result of the last restart.ps1 run
var/trash/             recycle bin for delete_path, in timestamped folders
```

Reviewing what an agent actually did is one command:

```powershell
Get-Content var\logs\ops.log -Tail 20 | ConvertFrom-Json | Format-Table timestamp, tool, status
```

---

## Configuration

`config.example.yaml` is the annotated template — copy it and edit. Every key below is
optional except the two named in [Quick start](#2-configure).

<details open>
<summary><b>Authentication and scope</b></summary>

| Key | Default | Meaning |
|---|---|---|
| `auth_token` | *(required)* | Bearer credential for every MCP call. Treat as a shell password. |
| `allowed_paths` | *(required)* | Directories the file tools may touch. Env vars are expanded (`%TEMP%`, `$HOME`). |
| `allow_query_token` | `true` | Accept `?token=` as well as the `Authorization` header. |
| `host` | `127.0.0.1` | Bind address. Keep it on loopback and put a tunnel in front. |
| `port` | `8765` | TCP port. |

</details>

<details>
<summary><b>Transports and limits</b></summary>

| Key | Default | Meaning |
|---|---|---|
| `transports` | `["sse", "streamable_http"]` | Which MCP transports to serve. Both may run at once. |
| `max_request_body_size` | `4194304` | Streamable HTTP body cap (4 MiB). |
| `sse_ping_interval` | `15` | SSE keepalive seconds; `0` disables. |
| `max_file_size` | `1048576` | Largest response a single `read_file` returns. |
| `bash_timeout` | `30` | Default `run_bash` timeout; a call may request up to 2×. |
| `rate_limit` | `60` | Requests per minute, and the burst capacity. |

</details>

<details>
<summary><b>Binary transfer channel</b></summary>

| Key | Default | Meaning |
|---|---|---|
| `public_base_url` | `""` | Public origin the agent can reach. Auto-filled from a managed ngrok tunnel. |
| `transfer_ticket_ttl` | `300` | Seconds a one-time transfer ticket stays valid. |
| `upload_max_bytes` | `104857600` | Largest accepted upload body (100 MB). |

</details>

<details>
<summary><b>Outbound downloads (<code>download_file</code>)</b></summary>

| Key | Default | Meaning |
|---|---|---|
| `download_allowed_schemes` | `["https","http"]` | Permitted URL schemes. |
| `download_allowed_hosts` | `[]` | Empty means any public host. Listing a host also exempts it from the private-address check. |
| `download_max_bytes` | `52428800` | Size cap (50 MB). |
| `download_timeout` | `60` | Per-request timeout in seconds. |

Loopback, link-local and private addresses are refused whatever the list says — without
that check a remote agent could use this tool to probe your LAN. Every redirect hop is
re-vetted (max 5).

</details>

<details>
<summary><b>Safety rails</b></summary>

| Key | Default | Meaning |
|---|---|---|
| `command_guard_enabled` | `true` | Refuse a short list of irreversible shell commands. |
| `denied_command_patterns` | `[]` | Extra deny regexes, appended to the built-ins. |
| `trash_dir` | `./var/trash` | Where `delete_path` moves things. Empty makes deletes permanent. |
| `screenshot_enabled` | `true` | `false` withholds the `screenshot` tool entirely. |
| `log_file` | `./var/logs/ops.log` | JSONL audit log. |
| `log_max_bytes` | `5242880` | Rotate to `<log_file>.1` past this size; `0` disables. |

</details>

<details>
<summary><b>Images, search, DLP, tunnel</b></summary>

| Key | Default | Meaning |
|---|---|---|
| `image_max_edge` | `1568` | Longest edge before downscaling; vision cost scales with resolution. |
| `image_jpeg_quality` | `85` | Initial JPEG quality. |
| `max_image_bytes` | `1572864` | Re-encode until the result fits. |
| `ripgrep_path` | `""` | Explicit `rg` binary. Empty probes `PATH`, then vendored copies, then falls back to Python. |
| `dlp_mode` | `auto` | `auto` samples the whitelist for ciphertext; `on`/`off` decide without sampling. |
| `encrypted_file_markers` | `[]` | Hex magic-byte prefixes. Empty uses the built-in defaults. |
| `staging_dir` | `""` | Where protected apps should export plaintext. Empty = `%TEMP%/localhands_staging`. |
| `tunnel.*` | see template | Provider, executable, domain, extra args, proxy stripping, startup timeout. |

</details>

---

## Tool reference

Twenty-three tools are **declared**; the number actually advertised depends on the machine
(see [Runtime-conditional tools](#the-tool-list-is-not-static)). 👁 marks the three the
person at the keyboard will notice — everything else is silent.

<details open>
<summary><b>Files</b> — 8 tools</summary>

| Tool | Notes |
|---|---|
| `read_file` | Line numbers by default; `offset`/`limit` pagination; refuses binaries and DLP ciphertext |
| `read_many_files` | Batch read — one round trip instead of N; each path reports its own error |
| `write_file` | Replaces whole content, creates parent directories |
| `edit_file` | Exact-string replace, **unique match required** by default |
| `multi_edit` | Several edits to one file, applied atomically and in order |
| `move_path` / `copy_path` | Whitelist-checked on both ends; `copy_path` recurses |
| `delete_path` | **Recycle bin by default**, returns `trash_path`; `permanent=true` really deletes |

</details>

<details open>
<summary><b>Search</b> — 5 tools</summary>

| Tool | Notes |
|---|---|
| `glob` | `*`, `?`, `**`; sorted newest-first |
| `grep` | ripgrep when available; `content` / `files_with_matches` / `count` modes |
| `list_directory` | Name, type, size, mtime in both epoch and ISO-8601 |
| `get_project_tree` | Honours `.gitignore`, skips build and cache directories |
| `scan_encrypted` | Which files the DLP driver has made unreadable — *only served when DLP is detected* |

</details>

<details open>
<summary><b>Shell, transfer, media, net, desktop</b> — 10 tools</summary>

| | Tool | Notes |
|---|---|---|
| **Shell** | `run_bash` | stdout, stderr, exit code; guard rail on irreversible commands; process-tree kill on timeout |
| **Transfer** | `prepare_download` | One-time URL to pull a local file as raw bytes |
| | `prepare_upload` | One-time URL to push bytes onto this machine |
| **Media** | `read_image` | Downscales, then returns a URL — never pixels |
| | `process_image` | Crop, resize, convert; writes to `dest_path`, transfers nothing |
| | `image_info` | Format, mode, dimensions, alpha, EXIF orientation — no copy, no transfer |
| 👁 | `screenshot` | Captures whatever is on screen right now |
| **Net** | `download_file` | The daemon fetches the URL itself; bytes never enter the context |
| **Desktop** 👁 | `open_path` | Opens a file or folder in its associated application |
| 👁 | `notify` | Puts a dialog on the user's screen |

</details>

Every tool also carries MCP `annotations` (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) plus two local `_meta` hints, `userVisible` and
`readsScreen`. They live in one table — [`tools/policy.py`](src/localhands/tools/policy.py)
— so "what can this server do to my machine without asking" is one screen of text.

---

## How it works

### Binary payloads never travel through the model's context

This is the design decision that shapes everything else.

MCP moves tool arguments and results as text, which is ruinous for bytes:

- **Model → local.** The model has to *emit* base64 as a tool argument, so every byte is
  an **output** token. A 500 KB image is ~680 000 characters: hundreds of thousands of
  output tokens and tens of seconds of generation.
- **Local → model.** The bytes arrive as a tool **result**. A client that decodes MCP
  `ImageContent` into a real image pays only vision tokens, but a client that spools
  results to a file and reads them back as text pays full text price. That behaviour is
  client-specific and cannot be assumed.

So `prepare_download` and `prepare_upload` mint a **one-time URL** and return a ready-to-run
`curl` command. The agent moves the file in its own environment; only a short URL enters
the context. `read_image` returns a ~760-character payload for an image of any size.

The channel is format-agnostic, which is the larger win: PDFs, archives and spreadsheets
travel the same way, so `read_file` being text-only stops mattering.

### One-time tickets, not the main token

The URL is handed to a remote sandbox that fetches it with `curl`, so whatever credential
it carries lands in that sandbox's shell history. A ticket is 32 random bytes scoped to
**one file, one direction, one use, a few minutes**. The long-lived `auth_token` never
leaves this machine. Both minting and redemption re-check the path against the whitelist.

### The tool list is not static

At startup the daemon samples the whitelisted directories for a transparent-encryption
driver's ciphertext marker. On a clean machine it finds nothing, `scan_encrypted` is never
advertised, and the DLP guidance never reaches the agent — describing ciphertext it will
never meet would just spend context. `screenshot_enabled: false` removes screen capture
the same way. `/health` reports what is *actually* served.

### Server-level instructions

Beyond the per-tool schemas, the server sends an `instructions` block in its initialize
response — clients generally fold it into the system prompt, which reaches the model
*before* it picks a tool. It covers what applies to the whole server: that bytes move over
HTTP rather than through the context, that file access is whitelisted, and which three
tools the person at the machine will actually notice.

---

## Security model

Five layers, in request order:

1. **Rate limit** — token bucket, outermost, applied before anything is parsed.
2. **Bearer token** — header or `?token=`, constant-time compared. `/health` is public;
   `/download` and `/upload` authenticate with their own one-time ticket instead, so the
   long-lived token is never put in a URL.
3. **Path whitelist** — every path is fully resolved (symlinks, junctions, `..`) *before*
   the prefix check, so a symlink pointing outside is rejected rather than followed.
4. **Command guard** — a deny list for irreversible shell commands: whole-disk operations,
   recursive deletion of a drive root, shutdown, registry hive deletion, and piping a
   download straight into a shell.
5. **Audit log** — JSONL, one line per invocation, with rotation.

> [!WARNING]
> **Be clear about what this is not.** `run_bash` is arbitrary code execution by design,
> so the auth token is equivalent to a shell password on this machine. The command guard is
> a rail against a model acting on a misread or injected instruction — **not** a boundary
> against an adversary. Anything with shell access can obfuscate past a regex. For a hard
> boundary, run the daemon in a VM or container.

---

## Working with transparent encryption (DLP)

**Skip this unless your machine has one.** With `dlp_mode: auto` (the default) the daemon
samples the whitelisted directories at startup, biased toward the document and image
formats such policies actually protect. Finding nothing, it withholds the whole subject.
Force the decision either way with `dlp_mode: on | off`.

Corporate endpoints often run a transparent-encryption filter driver. Files written by
*protected* applications are handed to this daemon as **ciphertext**, which `read_file`
would otherwise return as several kilobytes of mojibake — and the model would then reason
about noise, confidently and at full token price.

Two measured facts determine what actually helps:

- **Copying never decrypts.** `shutil.copyfile`, `cmd copy` and `Copy-Item` all produce a
  still-encrypted copy, in `%TEMP%` or anywhere else. The ciphertext *is* the content;
  location is irrelevant.
- **`%TEMP%` is typically excluded on write.** A protected application doing "Save As"
  into `%TEMP%` writes plaintext, because the driver skips that path.

So the daemon detects the condition by magic bytes and returns a `FileEncrypted` error
naming the one remedy that works: re-export from the owning application into `staging_dir`.
Run `scan_encrypted` first to learn what is readable in one call, instead of discovering it
one failure at a time.

---

## Development

### Project layout

```
pyproject.toml            Packaging, pytest and ruff configuration
config.example.yaml       Documented template; copy to config.yaml
scripts/restart.ps1       Restart and verify (Windows)
src/localhands/
  daemon.py               Entry point, ASGI routing, transports, tunnel lifecycle
  config.py               Typed configuration with validation
  security.py             Auth, rate limit, PathGuard, CommandGuard, tickets, audit log
  transfer.py             /download and /upload byte streaming
  tunnel.py               Tunnel supervision (ngrok / cloudflared / custom)
  tools/
    base.py               ToolProvider protocol, LocalProvider, ok()/err()
    __init__.py           Registry and dispatcher
    policy.py             Per-tool annotations: read-only, destructive, user-visible
    instructions.py       Server-level guidance sent in the initialize response
    encryption.py         DLP detection and probing
    files.py  search.py  shell.py  xfer.py  media.py  net.py  desktop.py
tests/                    pytest suite; no daemon, network, or tunnel required
var/                      Runtime state — logs, recycle bin (gitignored)
```

### Running the tests

```powershell
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest tests/ -q
```

222 tests, none of which need a running daemon, a network, or a tunnel. Everything is built
in-process from `tmp_path`, and the real `config.yaml` is deliberately never read.

```powershell
.venv\Scripts\python.exe -m pytest tests/test_tools.py::TestEditFile -q   # one class
.venv\Scripts\python.exe -m pytest tests/ -k "encrypted" -q               # by name
```

Lint rules are configured in `pyproject.toml` (ruff is not a declared dependency — install it
separately). The tree is clean; please keep it that way:

```powershell
ruff check .
```

### Adding a tool

Subclass `LocalProvider`, declare `name` and `tools`, and implement one method per tool
named `_<tool_name>`. Register the class in `PROVIDER_CLASSES`, and add an entry to
`POLICIES` in `tools/policy.py` so it ships with correct annotations. The dispatcher, audit
logging and error containment need no changes.

Synchronous methods are run on a worker thread automatically, so a slow filesystem never
stalls the event loop; `async def` methods are awaited directly.

The same seam is how an **upstream MCP server** gets proxied: implement `ToolProvider` over
a stdio or HTTP client, namespace the tool names, apply `PathGuard` to path arguments, and
register it alongside the local providers.

### A note on the `mcp` dependency

The floor `mcp>=2.0` is load-bearing, not hygiene. 2.x is a rewrite of the 1.x API, not a
compatible bump: the low-level `Server` takes `on_*` handlers instead of decorators,
results are no longer auto-wrapped, and model fields are snake_case.

---

## Troubleshooting

<details>
<summary><b>The daemon says it started, but nothing answers</b></summary>

Use `scripts/restart.ps1` rather than launching it by hand — it polls `/health` and reports
honestly. If it fails, `var/logs/restart.txt` holds the reason plus the tail of both logs.

A common cause on Windows: a redirected stdout opens with the locale encoding, and non-ASCII
log output kills the process before it binds the port. The daemon forces UTF-8 on stdout and
stderr at startup to prevent exactly this.
</details>

<details>
<summary><b>The client stalls on the first call after an idle period</b></summary>

That is the SSE failure mode: an idle connection is dropped somewhere in the tunnel, the
client reuses the dead pooled session, and the call never returns. Point the client at
`/mcp` (Streamable HTTP) instead — its exchanges are request-scoped, so there is no idle
connection to lose. If you must stay on SSE, keep `sse_ping_interval` above zero.
</details>

<details>
<summary><b>ngrok exits immediately with <code>ERR_NGROK_9009</code></b></summary>

ngrok's free tier refuses to start when `http_proxy`/`https_proxy` are set. Leave
`tunnel.strip_proxy_env: true` (the default) — it scrubs them from the tunnel child process
only, and your other tools keep their proxy settings.
</details>

<details>
<summary><b>A download saved an HTML page instead of the file</b></summary>

ngrok's free tier serves a browser interstitial (`ERR_NGROK_6024`) to requests that look
like a browser. The `curl` field returned by the transfer tools already carries the
`ngrok-skip-browser-warning` header — run that command verbatim rather than reconstructing
it.
</details>

<details>
<summary><b><code>read_file</code> returns <code>FileEncrypted</code></b></summary>

A transparent-encryption driver owns that file. Copying it will not help. See
[Working with transparent encryption](#working-with-transparent-encryption-dlp).
</details>

<details>
<summary><b>A path inside my project is rejected</b></summary>

`PathGuard` resolves symlinks and junctions before checking the prefix, so a link that
points outside `allowed_paths` is rejected even though its name looks fine. Add the real
target directory, or move the file.
</details>

---

## Contributing

Issues and pull requests are welcome at
[github.com/newcovid/LocalHands](https://github.com/newcovid/LocalHands).

Before opening a PR:

- `.venv\Scripts\python.exe -m pytest tests/ -q` passes
- `ruff check .` is clean
- New tools carry a `POLICIES` entry and a test that goes through the real dispatcher

Please do not include machine-specific paths, tokens, or tunnel domains in a patch —
`config.yaml` and `var/` are gitignored for that reason.

## License

[MIT](LICENSE) © newcovid
