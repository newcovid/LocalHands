"""Tests for the binary transfer channel: header encoding and the ASGI handlers.

The /download and /upload endpoints sit deliberately outside the bearer-token
middleware, so the ticket carried in the URL is the only thing standing between
a stranger and a file.  Everything here is driven through an in-process ASGI
call: no socket is opened and no tunnel is involved.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

from localhands.config import Config
from localhands.security import OperationLogger, PathGuard, TransferTicketStore
from localhands.transfer import TransferEndpoints, _content_disposition, _mask

CHINESE_NAME = "季度报告.pdf"


# ====================================================================== #
#  _content_disposition
# ====================================================================== #

class TestContentDisposition:
    """HTTP headers are latin-1; real-world filenames are not."""

    def test_chinese_filename_produces_a_latin1_safe_header(self) -> None:
        # Encoding the raw name would raise UnicodeEncodeError and turn a
        # working download into a 500 at the moment the response starts.
        header = _content_disposition(CHINESE_NAME)
        assert isinstance(header, bytes)
        header.decode("latin-1")  # would raise if any byte were out of range
        assert all(byte < 128 for byte in header), "header must stay pure ASCII"

    def test_chinese_filename_survives_in_the_rfc_5987_form(self) -> None:
        # The percent-encoded filename* is what a modern client actually uses,
        # so the real name has to be recoverable from it.
        header = _content_disposition(CHINESE_NAME).decode("latin-1")
        assert f"filename*=UTF-8''{quote(CHINESE_NAME, safe='')}" in header

    def test_ascii_fallback_is_present_for_clients_that_ignore_filename_star(
        self,
    ) -> None:
        header = _content_disposition(CHINESE_NAME).decode("latin-1")
        assert header.startswith("attachment; filename=")

    def test_ascii_filename_is_carried_through_unchanged(self) -> None:
        header = _content_disposition("report.pdf").decode("latin-1")
        assert 'filename="report.pdf"' in header

    def test_quote_in_a_filename_cannot_break_out_of_the_quoted_form(self) -> None:
        # A filename containing a double quote would otherwise let an attacker
        # who controls the name inject extra header parameters.
        header = _content_disposition('evil".txt').decode("latin-1")
        assert 'filename="evil_.txt"' in header
        assert header.count('"') == 2


def test_ticket_is_masked_in_log_lines() -> None:
    """The audit log has to be correlatable without republishing the credential."""
    ticket_id = "abcdefgh" + "z" * 40
    masked = _mask(ticket_id)
    assert masked == "abcdefgh..."
    assert ticket_id not in masked


# ====================================================================== #
#  Routing
# ====================================================================== #

class TestMatch:
    """Which requests belong to the transfer channel at all."""

    @pytest.mark.parametrize(
        ("path", "method", "expected"),
        [
            ("/download/abc", "GET", ("download", "abc")),
            ("/upload/abc", "PUT", ("upload", "abc")),
            ("/upload/abc", "POST", ("upload", "abc")),
        ],
    )
    def test_recognised_requests_yield_kind_and_ticket(
        self, path: str, method: str, expected: tuple[str, str]
    ) -> None:
        assert TransferEndpoints.match(path, method) == expected

    @pytest.mark.parametrize(
        ("path", "method"),
        [
            ("/download/abc", "PUT"),      # downloads are read-only
            ("/download/abc", "DELETE"),
            ("/upload/abc", "GET"),        # a GET must not trigger a write
            ("/sse", "GET"),
            ("/health", "GET"),
            ("/downloads/abc", "GET"),     # near-miss prefix
        ],
    )
    def test_other_requests_are_not_claimed(self, path: str, method: str) -> None:
        assert TransferEndpoints.match(path, method) is None


# ====================================================================== #
#  Endpoint fixtures
# ====================================================================== #

@pytest.fixture
def endpoints(
    config: Config,
    guard: PathGuard,
    tickets: TransferTicketStore,
    op_logger: OperationLogger,
) -> TransferEndpoints:
    """The transfer handlers, wired as the daemon wires them."""
    return TransferEndpoints(config, guard, tickets, op_logger)


@pytest.fixture
def transfer_app(endpoints: TransferEndpoints) -> Callable[..., Any]:
    """Adapt the handlers to a plain ASGI app so run_asgi can drive them.

    Routing goes through ``match`` rather than being hard-coded here, so the
    URL shape the daemon serves is what the tests exercise.
    """

    async def _app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        matched = TransferEndpoints.match(scope["path"], scope["method"])
        assert matched is not None, f"{scope['method']} {scope['path']} is not a transfer URL"
        kind, ticket_id = matched
        await endpoints.handle(kind, ticket_id, scope, receive, send)

    return _app


# ====================================================================== #
#  GET /download/<ticket>
# ====================================================================== #

class TestDownload:
    async def test_serves_the_file_bytes_with_a_matching_content_length(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        payload = b"\x89PNG\r\n\x1a\n binary payload \x00\xff"
        target = allowed_root / "image.png"
        target.write_bytes(payload)
        ticket_id, _ = tickets.mint("download", target)

        result = await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))

        assert result.status == 200
        assert result.body == payload
        assert result.header("content-length") == str(len(payload))
        assert result.header("content-type") == "image/png"
        # Nothing about a single-use URL should ever be cached by a proxy.
        assert result.header("cache-control") == "no-store"

    async def test_non_ascii_filename_reaches_the_header_intact(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        target = allowed_root / CHINESE_NAME
        target.write_bytes(b"%PDF-1.4\n")
        ticket_id, _ = tickets.mint("download", target)

        result = await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))
        assert result.status == 200
        assert quote(CHINESE_NAME, safe="") in (result.header("content-disposition") or "")

    async def test_a_replayed_url_is_refused(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        # The URL lands in the remote sandbox's shell history, so a second
        # fetch of the same URL is the expected attack, not an edge case.
        target = allowed_root / "once.txt"
        target.write_bytes(b"data")
        ticket_id, _ = tickets.mint("download", target)

        first = await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))
        second = await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))

        assert first.status == 200
        assert second.status == 403
        assert "error" in second.json()

    async def test_an_unknown_ticket_is_refused_with_403_not_404(
        self, transfer_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        # 404 would confirm which ticket shapes exist; 403 says only that the
        # credential was not accepted.
        result = await run_asgi(transfer_app, http_scope(path="/download/not-a-ticket"))
        assert result.status == 403

    async def test_an_upload_ticket_cannot_be_used_to_download(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        target = allowed_root / "inbound.bin"
        target.write_bytes(b"data")
        ticket_id, _ = tickets.mint("upload", target)

        result = await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))
        assert result.status == 403

    async def test_a_ticket_for_a_path_outside_the_whitelist_is_refused(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        outside_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        # Defence in depth: the tool that mints tickets already checks the
        # whitelist, but the endpoint re-checks at redemption because the
        # whitelist may have changed, or a symlink may have been swapped in,
        # between minting and use.
        ticket_id, _ = tickets.mint("download", outside_root / "secret.txt")

        result = await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))
        assert result.status == 403

    async def test_a_missing_file_is_reported_as_404(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        ticket_id, _ = tickets.mint("download", allowed_root / "vanished.bin")
        result = await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))
        assert result.status == 404

    async def test_a_directory_cannot_be_downloaded(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        ticket_id, _ = tickets.mint("download", allowed_root)
        result = await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))
        assert result.status == 400

    async def test_a_large_file_is_streamed_in_full(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        # Bigger than one 64 KB chunk, so the chunking loop actually iterates
        # and the final empty body message is exercised.
        payload = bytes(range(256)) * 1024  # 256 KB
        target = allowed_root / "big.bin"
        target.write_bytes(payload)
        ticket_id, _ = tickets.mint("download", target)

        result = await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))
        assert result.body == payload


# ====================================================================== #
#  PUT /upload/<ticket>
# ====================================================================== #

class TestUpload:
    async def test_writes_the_request_body_to_the_ticketed_path(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        target = allowed_root / "inbound" / "generated.png"
        ticket_id, _ = tickets.mint("upload", target)
        payload = b"\x89PNG\r\n\x1a\n generated bytes"

        result = await run_asgi(
            transfer_app,
            http_scope(path=f"/upload/{ticket_id}", method="PUT"),
            body=payload,
        )

        assert result.status == 200
        body = result.json()
        assert body["status"] == "success"
        assert body["bytes_written"] == len(payload)
        assert body["action"] == "created"
        # Parent directories are created, so the agent does not have to make a
        # separate call just to prepare the destination.
        assert target.read_bytes() == payload

    async def test_a_chunked_body_is_reassembled_in_order(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        target = allowed_root / "chunked.bin"
        ticket_id, _ = tickets.mint("upload", target)

        await run_asgi(
            transfer_app,
            http_scope(path=f"/upload/{ticket_id}", method="PUT"),
            body=[b"first-", b"second-", b"third"],
        )
        assert target.read_bytes() == b"first-second-third"

    async def test_overwriting_an_existing_file_is_reported(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        target = allowed_root / "existing.bin"
        target.write_bytes(b"old")
        ticket_id, _ = tickets.mint("upload", target)

        result = await run_asgi(
            transfer_app,
            http_scope(path=f"/upload/{ticket_id}", method="PUT"),
            body=b"new",
        )
        assert result.json()["action"] == "overwritten"
        assert target.read_bytes() == b"new"

    async def test_no_partial_file_is_left_behind_on_success(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        # The body is written to "<name>.part" and renamed, so a dropped
        # connection can never leave a truncated file at the target path.
        target = allowed_root / "atomic.bin"
        ticket_id, _ = tickets.mint("upload", target)

        await run_asgi(
            transfer_app,
            http_scope(path=f"/upload/{ticket_id}", method="PUT"),
            body=b"payload",
        )
        assert not target.with_name(target.name + ".part").exists()

    async def test_a_body_over_the_ticket_limit_is_refused(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        # The limit is enforced while streaming, so an oversized body is cut
        # off rather than buffered to disk first.
        target = allowed_root / "too_big.bin"
        ticket_id, _ = tickets.mint("upload", target, max_bytes=10)

        result = await run_asgi(
            transfer_app,
            http_scope(path=f"/upload/{ticket_id}", method="PUT"),
            body=b"x" * 5000,
        )

        assert result.status == 500
        assert not target.exists()
        # And the temporary file is cleaned up, not left as debris.
        assert not target.with_name(target.name + ".part").exists()

    async def test_a_ticket_is_burnt_even_when_the_upload_fails(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        # Redemption happens before any I/O, so a failed transfer cannot be
        # retried against the same URL — the agent must ask for a new ticket.
        target = allowed_root / "retry.bin"
        ticket_id, _ = tickets.mint("upload", target, max_bytes=10)

        await run_asgi(
            transfer_app,
            http_scope(path=f"/upload/{ticket_id}", method="PUT"),
            body=b"x" * 5000,
        )
        retry = await run_asgi(
            transfer_app,
            http_scope(path=f"/upload/{ticket_id}", method="PUT"),
            body=b"x",
        )
        assert retry.status == 403

    async def test_a_download_ticket_cannot_be_used_to_upload(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        # Otherwise a ticket handed out to read a file would also authorise
        # replacing it.
        target = allowed_root / "readonly.bin"
        target.write_bytes(b"original")
        ticket_id, _ = tickets.mint("download", target)

        result = await run_asgi(
            transfer_app,
            http_scope(path=f"/upload/{ticket_id}", method="PUT"),
            body=b"replaced",
        )
        assert result.status == 403
        assert target.read_bytes() == b"original"

    async def test_an_upload_to_a_path_outside_the_whitelist_is_refused(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        outside_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        target = outside_root / "planted.bin"
        ticket_id, _ = tickets.mint("upload", target)

        result = await run_asgi(
            transfer_app,
            http_scope(path=f"/upload/{ticket_id}", method="PUT"),
            body=b"payload",
        )
        assert result.status == 403
        assert not target.exists()


# ====================================================================== #
#  Tool → endpoint, end to end
# ====================================================================== #

class TestPrepareThenTransfer:
    """The URL a tool hands the agent has to be the URL the endpoint serves."""

    async def test_prepare_download_mints_a_url_that_actually_works(
        self,
        call_tool: Any,
        transfer_app: Any,
        config: Config,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        payload = "报告内容\n".encode()
        target = allowed_root / CHINESE_NAME
        target.write_bytes(payload)

        prepared = await call_tool("prepare_download", {"path": str(target)})
        assert prepared["status"] == "success"
        assert prepared["single_use"] is True
        assert prepared["url"].startswith(config.public_base_url)

        # Strip the configured origin to get the path an ASGI scope carries.
        path = prepared["url"][len(config.public_base_url):]
        result = await run_asgi(transfer_app, http_scope(path=path))
        assert result.status == 200
        assert result.body == payload

    async def test_prepare_upload_mints_a_url_that_actually_works(
        self,
        call_tool: Any,
        transfer_app: Any,
        config: Config,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        target = allowed_root / "delivered" / "output.bin"
        prepared = await call_tool("prepare_upload", {"dest_path": str(target)})
        assert prepared["will_overwrite"] is False

        path = prepared["url"][len(config.public_base_url):]
        result = await run_asgi(
            transfer_app, http_scope(path=path, method="PUT"), body=b"delivered bytes"
        )
        assert result.status == 200
        assert target.read_bytes() == b"delivered bytes"

    async def test_a_prepared_url_is_single_use_end_to_end(
        self,
        call_tool: Any,
        transfer_app: Any,
        config: Config,
        allowed_root: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        target = allowed_root / "once.bin"
        target.write_bytes(b"data")
        prepared = await call_tool("prepare_download", {"path": str(target)})
        path = prepared["url"][len(config.public_base_url):]

        assert (await run_asgi(transfer_app, http_scope(path=path))).status == 200
        assert (await run_asgi(transfer_app, http_scope(path=path))).status == 403

    async def test_transfer_activity_is_written_to_the_audit_log(
        self,
        transfer_app: Any,
        tickets: TransferTicketStore,
        allowed_root: Path,
        log_path: Path,
        http_scope: Any,
        run_asgi: Any,
    ) -> None:
        # These endpoints skip the bearer middleware, so the audit log is the
        # only record that the transfer happened at all.
        target = allowed_root / "audited.bin"
        target.write_bytes(b"data")
        ticket_id, _ = tickets.mint("download", target)
        await run_asgi(transfer_app, http_scope(path=f"/download/{ticket_id}"))

        records = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        assert records[-1]["tool"] == "http_download"
        assert records[-1]["status"] == "success"
