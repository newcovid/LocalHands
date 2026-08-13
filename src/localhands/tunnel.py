"""Tunnel supervision for the LocalHands daemon.

The daemon binds to localhost, but the cloud agent that drives it lives on the
public internet, so a tunnel has to sit in front.  Running that tunnel as a
second manual terminal is easy to forget and easy to get wrong — the daemon
comes up, the tunnel does not, and the agent sees a dead URL.  This module folds
the tunnel into the daemon's own lifecycle: one command starts both, and the
tunnel dies with the daemon.

It also removes two footguns that cost real debugging time:

* **Proxy environment variables.**  ngrok's free tier refuses to start when
  ``http_proxy``/``https_proxy`` are set (``ERR_NGROK_9009``), which is why a
  shell with a proxy configured fails while a clean one works.  ``strip_proxy_env``
  scrubs them from the child's environment only, leaving the parent untouched.
* **Guessing the public origin.**  The transfer tools have to hand out absolute
  URLs, but the daemon cannot see its own public hostname.  For ngrok the real
  URL is read back from the local agent API and used to fill in
  ``public_base_url`` automatically when it was left blank.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Environment variables that make ngrok's free tier refuse to start.
PROXY_ENV_VARS = (
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
)

# Where the ngrok agent exposes its local inspection API.
NGROK_API = "http://127.0.0.1:4040/api/tunnels"

SUPPORTED_PROVIDERS = ("ngrok", "cloudflared", "custom")


class TunnelError(Exception):
    """Raised when the tunnel cannot be configured or started."""


@dataclass
class TunnelConfig:
    """Declarative description of the tunnel to run alongside the daemon."""

    enabled: bool = False
    provider: str = "ngrok"
    executable: str = ""          # Empty = auto-detect on PATH
    domain: str = ""              # Reserved domain, if the plan provides one
    command: list[str] = field(default_factory=list)  # provider: custom
    extra_args: list[str] = field(default_factory=list)
    strip_proxy_env: bool = True
    log_file: str = "./var/logs/tunnel.log"
    startup_timeout: int = 30

    @classmethod
    def from_dict(cls, data: Any) -> "TunnelConfig":
        """Build from the ``tunnel:`` block of the YAML config."""
        if not data:
            return cls()
        if not isinstance(data, dict):
            raise TunnelError("'tunnel' must be a mapping.")

        provider = str(data.get("provider", "ngrok")).strip().lower()
        if provider not in SUPPORTED_PROVIDERS:
            raise TunnelError(
                f"tunnel.provider must be one of {SUPPORTED_PROVIDERS}, got {provider!r}."
            )

        command = data.get("command") or []
        if command and not isinstance(command, list):
            raise TunnelError("tunnel.command must be a list of arguments.")
        if provider == "custom" and not command:
            raise TunnelError("tunnel.provider 'custom' requires tunnel.command.")

        extra_args = data.get("extra_args") or []
        if not isinstance(extra_args, list):
            raise TunnelError("tunnel.extra_args must be a list.")

        startup_timeout = int(data.get("startup_timeout", 30))
        if startup_timeout < 1:
            raise TunnelError("tunnel.startup_timeout must be >= 1.")

        return cls(
            enabled=bool(data.get("enabled", False)),
            provider=provider,
            executable=str(data.get("executable", "") or "").strip(),
            domain=str(data.get("domain", "") or "").strip(),
            command=[str(a) for a in command],
            extra_args=[str(a) for a in extra_args],
            strip_proxy_env=bool(data.get("strip_proxy_env", True)),
            log_file=str(data.get("log_file", "./var/logs/tunnel.log")),
            startup_timeout=startup_timeout,
        )


class TunnelManager:
    """Starts, inspects, and stops the tunnel process."""

    def __init__(self, config: TunnelConfig, port: int) -> None:
        self.config = config
        self.port = port
        self._proc: subprocess.Popen[bytes] | None = None
        self._log_handle: Any = None
        self.public_url: str = ""

    # ------------------------------------------------------------------ #
    #  Command construction
    # ------------------------------------------------------------------ #

    def _resolve_executable(self) -> str:
        """Find the tunnel binary, preferring an explicit config value."""
        if self.config.executable:
            candidate = Path(self.config.executable).expanduser()
            if candidate.is_file():
                return str(candidate)
            found = shutil.which(self.config.executable)
            if found:
                return found
            raise TunnelError(f"tunnel.executable not found: {self.config.executable}")

        name = "ngrok" if self.config.provider == "ngrok" else "cloudflared"
        found = shutil.which(name)
        if found:
            return found
        raise TunnelError(
            f"'{name}' is not on PATH. Install it, or set tunnel.executable "
            f"to its full path in the config."
        )

    def build_argv(self) -> list[str]:
        """Assemble the full command line for the configured provider."""
        if self.config.provider == "custom":
            return [a.replace("{port}", str(self.port)) for a in self.config.command]

        exe = self._resolve_executable()

        if self.config.provider == "ngrok":
            argv = [exe, "http"]
            if self.config.domain:
                argv.append(f"--domain={self.config.domain}")
            argv.extend(self.config.extra_args)
            argv.append(str(self.port))
            return argv

        # cloudflared
        argv = [exe, "tunnel", "--url", f"http://127.0.0.1:{self.port}"]
        argv.extend(self.config.extra_args)
        return argv

    def _child_env(self) -> dict[str, str]:
        """Environment for the tunnel process, with proxy vars optionally removed."""
        env = dict(os.environ)
        if self.config.strip_proxy_env:
            removed = [v for v in PROXY_ENV_VARS if env.pop(v, None) is not None]
            if removed:
                logger.info(
                    "Stripped proxy vars from tunnel environment: %s "
                    "(ngrok's free tier refuses to run behind a proxy)",
                    ", ".join(sorted(set(removed))),
                )
        return env

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> str:
        """Launch the tunnel and return its public URL (empty if undiscoverable).

        Raises:
            TunnelError: if the process cannot be launched or dies immediately.
        """
        argv = self.build_argv()
        log_path = Path(self.config.log_file).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info("Starting tunnel: %s", " ".join(argv))
        self._log_handle = log_path.open("wb")
        try:
            self._proc = subprocess.Popen(  # noqa: S603 — argv is config-derived, not shell
                argv,
                stdout=self._log_handle,
                stderr=subprocess.STDOUT,
                env=self._child_env(),
            )
        except OSError as exc:
            self._close_log()
            raise TunnelError(f"Failed to launch tunnel: {exc}") from exc

        url = self._await_ready(log_path)
        self.public_url = url
        return url

    def _await_ready(self, log_path: Path) -> str:
        """Wait for the tunnel to come up; return its public URL if we can learn it."""
        deadline = time.time() + self.config.startup_timeout

        while time.time() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                raise TunnelError(
                    f"Tunnel exited immediately with code {self._proc.returncode}. "
                    f"See {log_path} — {self._log_tail(log_path)}"
                )

            # Only ngrok exposes a local API to read the real URL back from.
            if self.config.provider == "ngrok":
                url = self._query_ngrok_url()
                if url:
                    logger.info("Tunnel is live: %s -> 127.0.0.1:%d", url, self.port)
                    return url
            else:
                # No inspection API: assume ready once it has stayed up briefly.
                time.sleep(2)
                if self._proc is not None and self._proc.poll() is None:
                    logger.info("Tunnel process is running (no URL discovery for %s).",
                                self.config.provider)
                    return ""
            time.sleep(0.5)

        # Still running but no URL — usable, just not introspectable.
        if self._proc is not None and self._proc.poll() is None:
            logger.warning(
                "Tunnel is running but its public URL could not be determined within %ds. "
                "Set public_base_url manually if transfer URLs come out wrong.",
                self.config.startup_timeout,
            )
            return ""
        raise TunnelError(f"Tunnel failed to start. {self._log_tail(log_path)}")

    @staticmethod
    def _query_ngrok_url() -> str:
        """Read the public URL from ngrok's local agent API.

        Built without proxies on purpose: the daemon's own environment may point
        at a proxy that cannot reach 127.0.0.1.
        """
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(NGROK_API, timeout=2) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
            return ""

        tunnels = payload.get("tunnels") or []
        # Prefer https when the agent reports both schemes for one endpoint.
        for tunnel in sorted(tunnels, key=lambda t: t.get("proto") != "https"):
            url = tunnel.get("public_url", "")
            if url.startswith("https://"):
                return url
        return tunnels[0].get("public_url", "") if tunnels else ""

    @staticmethod
    def _log_tail(log_path: Path, lines: int = 8) -> str:
        """Return the last few log lines, for error messages."""
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "(tunnel log unreadable)"
        tail = [ln for ln in text.strip().splitlines() if ln.strip()][-lines:]
        return " | ".join(tail) if tail else "(tunnel log empty)"

    def is_alive(self) -> bool:
        """True if the tunnel process is still running."""
        return self._proc is not None and self._proc.poll() is None

    def stop(self) -> None:
        """Terminate the tunnel, escalating to kill if it ignores the request."""
        if self._proc is None:
            return
        if self._proc.poll() is None:
            logger.info("Stopping tunnel (pid %d) ...", self._proc.pid)
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("Tunnel did not exit in time; killing it.")
                self._proc.kill()
                self._proc.wait(timeout=5)
        self._proc = None
        self._close_log()

    def _close_log(self) -> None:
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            finally:
                self._log_handle = None
