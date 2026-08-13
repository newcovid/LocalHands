"""Configuration for the LocalHands daemon.

Loads and validates YAML configuration, exposing a typed Config dataclass.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .tunnel import TunnelConfig, TunnelError

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when configuration is invalid or cannot be loaded."""


@dataclass
class Config:
    """Typed configuration for LocalHands.

    Attributes:
        auth_token:        Bearer token for authenticating MCP requests.
        allowed_paths:     Whitelisted directories that file tools may access.
        port:              TCP port for the SSE HTTP server.
        max_file_size:     Maximum bytes a single read_file call may return.
        bash_timeout:      Default timeout (seconds) for run_bash commands.
        rate_limit:        Maximum requests per minute (token-bucket capacity).
        log_file:          Path to the JSONL operation log.
        host:              Bind address for the HTTP server.
        allow_query_token: If True (default), accept ``?token=<token>`` query
                           parameter as an alternative to the Authorization
                           header — needed for clients like Aily
                           ``aily-mcp install-remote`` that can only send a URL.
    """

    auth_token: str = ""
    allowed_paths: list[str] = field(default_factory=list)
    port: int = 8765
    max_file_size: int = 1_048_576  # 1 MB
    bash_timeout: int = 30
    rate_limit: int = 60
    log_file: str = "./var/logs/ops.log"
    host: str = "127.0.0.1"
    allow_query_token: bool = True
    sse_ping_interval: int = 15  # SSE keepalive ping seconds (0 = disable); fixes 210204
    log_max_bytes: int = 5_242_880  # Rotate the audit log past this size (0 = never)

    # --- Binary transfer channel (/download, /upload) ---
    # Public origin the cloud agent can reach, e.g. the ngrok domain. Required
    # for transfer tools to hand out usable URLs; without it they return only
    # a relative path and the caller has to know the origin already.
    public_base_url: str = ""
    transfer_ticket_ttl: int = 300  # Seconds a one-time transfer ticket stays valid
    upload_max_bytes: int = 104_857_600  # Largest accepted upload body (100 MB)

    # --- MCP transports served concurrently ---
    # "sse" is the original HTTP+SSE transport (deprecated in the spec but still
    # what already-registered clients point at); "streamable_http" is the
    # current one. Both can run at once so a client can be migrated without a
    # flag day.
    transports: list[str] = field(default_factory=lambda: ["sse", "streamable_http"])
    max_request_body_size: int = 4_194_304  # Streamable HTTP body cap (4 MiB)

    # --- Search ---
    # Explicit ripgrep binary. Empty = probe PATH, then known vendored copies,
    # then fall back to the pure-Python matcher.
    ripgrep_path: str = ""

    # --- Shell command guard rail ---
    command_guard_enabled: bool = True
    # Extra deny regexes, appended to the built-in list in security.py.
    denied_command_patterns: list[str] = field(default_factory=list)

    # --- Destructive file operations ---
    # Where delete_path moves files instead of unlinking them. Empty disables
    # the recycle bin and makes deletes permanent.
    trash_dir: str = "./var/trash"

    # --- DLP / transparent-encryption handling ---
    # Whether this machine runs a transparent-encryption driver.
    #   auto - sample the allowed paths at startup and decide from evidence
    #   on   - assume it does, without sampling
    #   off  - assume it does not; the DLP tool and guidance are withheld
    # Most machines have none, and on those the whole subject is noise.
    dlp_mode: str = "auto"
    # Magic-byte prefixes (hex) that mark a file as encrypted by the local
    # DLP driver. Empty = use the built-in defaults.
    encrypted_file_markers: list[str] = field(default_factory=list)
    # Where protected applications should export plaintext. Empty = %TEMP%/localhands_staging.
    staging_dir: str = ""

    # --- Image handling ---
    image_max_edge: int = 1568
    image_jpeg_quality: int = 85
    max_image_bytes: int = 1_572_864
    screenshot_enabled: bool = True

    # --- Outbound download (download_file tool) ---
    download_allowed_schemes: list[str] = field(default_factory=lambda: ["https", "http"])
    download_allowed_hosts: list[str] = field(default_factory=list)
    download_max_bytes: int = 52_428_800
    download_timeout: int = 60

    # --- Public tunnel started and supervised by the daemon ---
    tunnel: TunnelConfig = field(default_factory=TunnelConfig)

    # ------------------------------------------------------------------ #
    #  Resolved properties (computed once, cached)
    # ------------------------------------------------------------------ #

    @property
    def resolved_allowed_paths(self) -> list[Path]:
        """Return allowed_paths as absolute, resolved Path objects.

        Environment variables are expanded first, so a config can portably say
        ``%TEMP%`` or ``$HOME`` instead of hard-coding a machine-specific path.
        This matters because %TEMP% is frequently redirected away from its
        default location under AppData, and a hard-coded path would miss it.

        Duplicates are dropped while preserving order, since expansion can make
        two different-looking entries resolve to the same directory.
        """
        seen: dict[Path, None] = {}
        for raw in self.allowed_paths:
            expanded = os.path.expandvars(raw)
            # A %VAR% that does not exist expands to itself; keeping it would
            # create a nonsense whitelist entry, so drop it instead.
            if "%" in expanded or expanded.startswith("$"):
                logger.warning("Skipping allowed_path with unresolved variable: %r", raw)
                continue
            seen.setdefault(Path(expanded).expanduser().resolve(), None)
        return list(seen)

    # ------------------------------------------------------------------ #
    #  Factory
    # ------------------------------------------------------------------ #

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        """Build a Config from a raw dict, applying defaults and validation."""
        if not isinstance(data, dict):
            raise ConfigError("Configuration root must be a mapping (dict).")

        # auth_token is required — no safe default exists.
        auth_token = data.get("auth_token", "")
        if not auth_token:
            raise ConfigError("'auth_token' is required and must be non-empty.")
        if len(auth_token) < 16:
            logger.warning(
                "auth_token is only %d chars — recommend ≥32 for security.",
                len(auth_token),
            )

        # allowed_paths: must be a non-empty list of existing directories.
        raw_paths = data.get("allowed_paths", [])
        if not isinstance(raw_paths, list) or not raw_paths:
            raise ConfigError("'allowed_paths' must be a non-empty list of directory paths.")
        allowed_paths: list[str] = []
        for p in raw_paths:
            if not isinstance(p, str) or not p.strip():
                raise ConfigError(f"Invalid path entry in allowed_paths: {p!r}")
            allowed_paths.append(p.strip())

        port = int(data.get("port", 8765))
        if not (1 <= port <= 65535):
            raise ConfigError(f"port must be in 1–65535, got {port}.")

        max_file_size = int(data.get("max_file_size", 1_048_576))
        if max_file_size < 1024:
            raise ConfigError(f"max_file_size must be ≥ 1024 bytes, got {max_file_size}.")

        bash_timeout = int(data.get("bash_timeout", 30))
        if bash_timeout < 1 or bash_timeout > 3600:
            raise ConfigError(f"bash_timeout must be 1–3600 seconds, got {bash_timeout}.")

        rate_limit = int(data.get("rate_limit", 60))
        if rate_limit < 1:
            raise ConfigError(f"rate_limit must be ≥ 1, got {rate_limit}.")

        allow_query_token = bool(data.get("allow_query_token", True))

        sse_ping_interval = int(data.get("sse_ping_interval", 15))
        if sse_ping_interval < 0:
            raise ConfigError(f"sse_ping_interval must be >= 0, got {sse_ping_interval}.")

        log_max_bytes = int(data.get("log_max_bytes", 5_242_880))
        if log_max_bytes < 0:
            raise ConfigError(f"log_max_bytes must be >= 0, got {log_max_bytes}.")

        public_base_url = str(data.get("public_base_url", "") or "").strip().rstrip("/")
        if public_base_url and not public_base_url.startswith(("http://", "https://")):
            raise ConfigError(
                f"public_base_url must start with http:// or https://, got {public_base_url!r}."
            )

        transfer_ticket_ttl = int(data.get("transfer_ticket_ttl", 300))
        if transfer_ticket_ttl < 1:
            raise ConfigError(f"transfer_ticket_ttl must be >= 1, got {transfer_ticket_ttl}.")

        upload_max_bytes = int(data.get("upload_max_bytes", 104_857_600))
        if upload_max_bytes < 1:
            raise ConfigError(f"upload_max_bytes must be >= 1, got {upload_max_bytes}.")

        try:
            tunnel = TunnelConfig.from_dict(data.get("tunnel"))
        except TunnelError as exc:
            raise ConfigError(str(exc)) from exc

        def _str_list(key: str, default: list[str]) -> list[str]:
            raw = data.get(key, default)
            if raw is None:
                return list(default)
            if not isinstance(raw, list):
                raise ConfigError(f"'{key}' must be a list of strings.")
            return [str(x) for x in raw]

        def _positive_int(key: str, default: int) -> int:
            value = int(data.get(key, default))
            if value < 1:
                raise ConfigError(f"'{key}' must be >= 1, got {value}.")
            return value

        dlp_mode = str(data.get("dlp_mode", "auto") or "auto").strip().lower()
        if dlp_mode not in ("auto", "on", "off"):
            raise ConfigError(f"dlp_mode must be 'auto', 'on' or 'off', got {dlp_mode!r}.")

        transports = _str_list("transports", ["sse", "streamable_http"])
        unknown = [t for t in transports if t not in ("sse", "streamable_http")]
        if unknown:
            raise ConfigError(
                f"Unknown transport(s) {unknown}; valid values are 'sse' and 'streamable_http'."
            )
        if not transports:
            raise ConfigError("'transports' must list at least one transport.")

        image_jpeg_quality = int(data.get("image_jpeg_quality", 85))
        if not (1 <= image_jpeg_quality <= 100):
            raise ConfigError(f"image_jpeg_quality must be 1-100, got {image_jpeg_quality}.")

        return cls(
            auth_token=auth_token,
            allowed_paths=allowed_paths,
            port=port,
            max_file_size=max_file_size,
            bash_timeout=bash_timeout,
            rate_limit=rate_limit,
            log_file=str(data.get("log_file", "./var/logs/ops.log")),
            host=str(data.get("host", "127.0.0.1")),
            allow_query_token=allow_query_token,
            sse_ping_interval=sse_ping_interval,
            log_max_bytes=log_max_bytes,
            public_base_url=public_base_url,
            transfer_ticket_ttl=transfer_ticket_ttl,
            upload_max_bytes=upload_max_bytes,
            transports=transports,
            max_request_body_size=_positive_int("max_request_body_size", 4_194_304),
            trash_dir=str(data.get("trash_dir", "./var/trash") or "").strip(),
            ripgrep_path=str(data.get("ripgrep_path", "") or "").strip(),
            command_guard_enabled=bool(data.get("command_guard_enabled", True)),
            denied_command_patterns=_str_list("denied_command_patterns", []),
            dlp_mode=dlp_mode,
            encrypted_file_markers=_str_list("encrypted_file_markers", []),
            staging_dir=str(data.get("staging_dir", "") or "").strip(),
            image_max_edge=_positive_int("image_max_edge", 1568),
            image_jpeg_quality=image_jpeg_quality,
            max_image_bytes=_positive_int("max_image_bytes", 1_572_864),
            screenshot_enabled=bool(data.get("screenshot_enabled", True)),
            download_allowed_schemes=_str_list("download_allowed_schemes", ["https", "http"]),
            download_allowed_hosts=_str_list("download_allowed_hosts", []),
            download_max_bytes=_positive_int("download_max_bytes", 52_428_800),
            download_timeout=_positive_int("download_timeout", 60),
            tunnel=tunnel,
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Config":
        """Load configuration from a YAML file."""
        yaml_path = Path(path).expanduser()
        if not yaml_path.is_file():
            raise ConfigError(f"Config file not found: {yaml_path}")
        try:
            with yaml_path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ConfigError(f"Failed to parse YAML in {yaml_path}: {exc}") from exc
        if data is None:
            raise ConfigError(f"Config file is empty: {yaml_path}")
        return cls.from_dict(data)

    # ------------------------------------------------------------------ #
    #  Self-check (called at startup)
    # ------------------------------------------------------------------ #

    def validate_paths(self) -> list[str]:
        """Verify every allowed_path exists and is a directory.

        Returns a list of warning messages for paths that don't exist yet
        (non-fatal — the directory may be created later).
        """
        warnings: list[str] = []
        for p in self.resolved_allowed_paths:
            if not p.exists():
                warnings.append(f"Allowed path does not exist: {p}")
            elif not p.is_dir():
                warnings.append(f"Allowed path is not a directory: {p}")
        return warnings
