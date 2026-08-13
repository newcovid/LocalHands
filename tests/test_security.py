"""Tests for the security layer: path whitelist, transfer tickets, audit log,
and the two ASGI middlewares.

These are the parts of the daemon that decide what a remote model is allowed to
reach, so the assertions here are about refusals as much as about successes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import TEST_TOKEN
from localhands.config import Config
from localhands.security import (
    BearerAuthMiddleware,
    OperationLogger,
    PathGuard,
    PathGuardError,
    RateLimitMiddleware,
    TransferTicketError,
    TransferTicketStore,
)

# ====================================================================== #
#  PathGuard — the whitelist boundary
# ====================================================================== #

class TestPathGuardAccepts:
    """Paths that must be allowed through, or the daemon is useless."""

    def test_file_directly_inside_the_allowed_root_is_accepted(
        self, guard: PathGuard, allowed_root: Path
    ) -> None:
        target = allowed_root / "notes.txt"
        target.write_text("x", encoding="utf-8")
        assert guard.check(str(target)) == target.resolve()

    def test_deeply_nested_path_is_accepted(
        self, guard: PathGuard, allowed_root: Path
    ) -> None:
        target = allowed_root / "a" / "b" / "c" / "d.txt"
        target.parent.mkdir(parents=True)
        target.write_text("x", encoding="utf-8")
        assert guard.check(str(target)) == target.resolve()

    def test_the_allowed_root_itself_is_accepted(
        self, guard: PathGuard, allowed_root: Path
    ) -> None:
        # Tools such as glob and get_project_tree pass the root as their search
        # base, so rejecting it would break the default case.
        assert guard.check(str(allowed_root)) == allowed_root.resolve()

    def test_path_that_does_not_exist_yet_validates_by_location(
        self, guard: PathGuard, allowed_root: Path
    ) -> None:
        # write_file must be able to create a file, and prepare_upload must be
        # able to mint a ticket for one, so validation is about *where* the path
        # points and never about whether it exists.
        target = allowed_root / "not" / "created" / "yet.txt"
        assert not target.exists()
        assert guard.check(str(target)) == target.resolve()

    def test_dotdot_that_stays_inside_the_root_is_accepted(
        self, guard: PathGuard, allowed_root: Path
    ) -> None:
        (allowed_root / "sub").mkdir()
        wandering = allowed_root / "sub" / ".." / "target.txt"
        assert guard.check(str(wandering)) == (allowed_root / "target.txt").resolve()

    def test_symlink_pointing_back_inside_the_root_is_accepted(
        self,
        guard: PathGuard,
        allowed_root: Path,
        make_symlink: Callable[[Path, Path], Path],
    ) -> None:
        real = allowed_root / "real"
        real.mkdir()
        link = make_symlink(allowed_root / "alias", real)
        assert guard.check(str(link / "file.txt")) == (real / "file.txt").resolve()


class TestPathGuardRejects:
    """Escape attempts.  Each of these is a way out of the whitelist."""

    def test_sibling_directory_is_rejected(
        self, guard: PathGuard, outside_root: Path
    ) -> None:
        with pytest.raises(PathGuardError):
            guard.check(str(outside_root / "secret.txt"))

    def test_parent_of_the_allowed_root_is_rejected(
        self, guard: PathGuard, tmp_path: Path
    ) -> None:
        # Allowing the parent would silently widen the whitelist to every
        # sibling directory under it.
        with pytest.raises(PathGuardError):
            guard.check(str(tmp_path))

    def test_absolute_path_elsewhere_on_the_volume_is_rejected(
        self, guard: PathGuard, tmp_path: Path
    ) -> None:
        stranger = Path(tmp_path.anchor) / "not_a_bridge_directory" / "x.txt"
        with pytest.raises(PathGuardError):
            guard.check(str(stranger))

    def test_sibling_whose_name_merely_starts_with_the_root_is_rejected(
        self, guard: PathGuard, tmp_path: Path
    ) -> None:
        # The classic prefix bug: a string ``startswith`` check would admit
        # ``...\\allowed_evil`` because it begins with ``...\\allowed``.
        # Component-wise containment is what makes this safe.
        evil = tmp_path / "allowed_evil"
        evil.mkdir()
        with pytest.raises(PathGuardError):
            guard.check(str(evil / "loot.txt"))

    def test_dotdot_traversal_out_of_the_root_is_rejected(
        self, guard: PathGuard, allowed_root: Path, outside_root: Path
    ) -> None:
        escape = allowed_root / ".." / "outside" / "secret.txt"
        with pytest.raises(PathGuardError):
            guard.check(str(escape))

    def test_repeated_dotdot_climbing_to_the_volume_root_is_rejected(
        self, guard: PathGuard, allowed_root: Path
    ) -> None:
        with pytest.raises(PathGuardError):
            guard.check(str(allowed_root / ".." / ".." / ".." / ".." / ".." / "x"))

    def test_symlink_out_of_the_root_is_rejected(
        self,
        guard: PathGuard,
        allowed_root: Path,
        outside_root: Path,
        make_symlink: Callable[[Path, Path], Path],
    ) -> None:
        # The link lives inside the whitelist, so any check done on the literal
        # string would pass.  Resolving before deciding is the only thing that
        # stops a symlink from being a hole straight out of the sandbox.
        link = make_symlink(allowed_root / "escape_hatch", outside_root)
        with pytest.raises(PathGuardError):
            guard.check(str(link / "secret.txt"))

    def test_is_allowed_reports_the_same_verdict_as_check(
        self, guard: PathGuard, allowed_root: Path, outside_root: Path
    ) -> None:
        assert guard.is_allowed(str(allowed_root / "ok.txt")) is True
        assert guard.is_allowed(str(outside_root / "secret.txt")) is False


def test_path_guard_refuses_to_start_without_a_usable_root(
    make_config: Callable[..., Config]
) -> None:
    """A guard with no roots would allow nothing, but constructing one silently
    would hide a broken config until the first tool call."""
    cfg = make_config(allowed_paths=["%DEFINITELY_NOT_SET_ANYWHERE%"])
    assert cfg.resolved_allowed_paths == []
    with pytest.raises(ValueError):
        PathGuard(cfg)


# ====================================================================== #
#  TransferTicketStore — the one-time credential
# ====================================================================== #

class TestTransferTickets:
    """A ticket is the sole credential on /download and /upload, so its
    single-use property is the whole security model of that channel."""

    def test_minted_ticket_redeems_exactly_once(
        self, tickets: TransferTicketStore, allowed_root: Path
    ) -> None:
        ticket_id, _ = tickets.mint("download", allowed_root / "a.bin")
        redeemed = tickets.redeem(ticket_id, "download")
        assert redeemed.kind == "download"

        # A replayed URL — from the sandbox's shell history, a proxy log, or a
        # retry — must not move the file a second time.
        with pytest.raises(TransferTicketError):
            tickets.redeem(ticket_id, "download")

    def test_unknown_ticket_id_is_rejected(self, tickets: TransferTicketStore) -> None:
        with pytest.raises(TransferTicketError):
            tickets.redeem("never-minted-by-anyone", "download")

    def test_download_ticket_does_not_authorise_an_upload(
        self, tickets: TransferTicketStore, allowed_root: Path
    ) -> None:
        # Direction is part of the grant: a ticket handed out to read a file
        # must not be turned around into permission to overwrite it.
        ticket_id, _ = tickets.mint("download", allowed_root / "a.bin")
        with pytest.raises(TransferTicketError):
            tickets.redeem(ticket_id, "upload")

    def test_wrong_kind_attempt_does_not_burn_the_ticket(
        self, tickets: TransferTicketStore, allowed_root: Path
    ) -> None:
        # redeem() validates the kind before consuming, so a mismatched attempt
        # is rejected without spending the ticket and the legitimate redemption
        # still succeeds.  Consuming on a wrong-kind request would turn one
        # confused call into a dead transfer.
        ticket_id, _ = tickets.mint("upload", allowed_root / "a.bin")
        with pytest.raises(TransferTicketError):
            tickets.redeem(ticket_id, "download")

        assert tickets.redeem(ticket_id, "upload").path.name == "a.bin"

        # Still single-use once it has actually been redeemed.
        with pytest.raises(TransferTicketError):
            tickets.redeem(ticket_id, "upload")

    def test_expired_ticket_is_rejected(
        self, tickets: TransferTicketStore, allowed_root: Path
    ) -> None:
        # A negative ttl puts the expiry in the past deterministically; sleeping
        # would trade a second of wall clock for the same assertion.
        ticket_id, _ = tickets.mint("download", allowed_root / "a.bin", ttl=-1)
        with pytest.raises(TransferTicketError):
            tickets.redeem(ticket_id, "download")

    def test_expiry_is_enforced_even_when_the_store_is_otherwise_idle(
        self, tickets: TransferTicketStore, allowed_root: Path
    ) -> None:
        # Expired tickets are purged lazily, so an expired one must not become
        # redeemable just because nothing else has touched the store since.
        stale, _ = tickets.mint("download", allowed_root / "a.bin", ttl=-5)
        fresh, _ = tickets.mint("download", allowed_root / "b.bin", ttl=60)
        with pytest.raises(TransferTicketError):
            tickets.redeem(stale, "download")
        assert tickets.redeem(fresh, "download").path.name == "b.bin"

    def test_outstanding_tickets_are_capped_rather_than_growing_forever(
        self, allowed_root: Path
    ) -> None:
        # A caller that mints tickets it never redeems must not be able to grow
        # the daemon's memory without bound.
        store = TransferTicketStore(ttl=600, max_outstanding=4)
        for i in range(50):
            store.mint("download", allowed_root / f"f{i}.bin")
        assert len(store._tickets) <= 4  # noqa: SLF001 — no public size accessor

    def test_eviction_drops_the_soonest_expiring_ticket_first(
        self, allowed_root: Path
    ) -> None:
        store = TransferTicketStore(ttl=600, max_outstanding=2)
        # Staggered ttls make "oldest" unambiguous; wall-clock resolution on
        # Windows is too coarse to order same-ttl mints reliably.
        first, _ = store.mint("download", allowed_root / "first.bin", ttl=60)
        second, _ = store.mint("download", allowed_root / "second.bin", ttl=120)
        third, _ = store.mint("download", allowed_root / "third.bin", ttl=180)

        with pytest.raises(TransferTicketError):
            store.redeem(first, "download")
        assert store.redeem(second, "download").path.name == "second.bin"
        assert store.redeem(third, "download").path.name == "third.bin"

    def test_ticket_ids_are_unique_across_many_mints(
        self, allowed_root: Path
    ) -> None:
        # A repeat would let one agent redeem another's ticket by accident.
        store = TransferTicketStore(ttl=600, max_outstanding=2048)
        ids = [store.mint("download", allowed_root / "a.bin")[0] for _ in range(500)]
        assert len(set(ids)) == len(ids)

    def test_ticket_id_is_long_enough_to_be_unguessable(
        self, tickets: TransferTicketStore, allowed_root: Path
    ) -> None:
        # The ticket is the only credential on the transfer endpoints, so its
        # entropy is what stands between a stranger and the file.
        ticket_id, _ = tickets.mint("download", allowed_root / "a.bin")
        assert len(ticket_id) >= 32

    def test_mint_rejects_an_unknown_transfer_kind(
        self, tickets: TransferTicketStore, allowed_root: Path
    ) -> None:
        with pytest.raises(ValueError):
            tickets.mint("sideways", allowed_root / "a.bin")

    def test_redeemed_ticket_carries_its_path_and_byte_limit(
        self, tickets: TransferTicketStore, allowed_root: Path
    ) -> None:
        target = allowed_root / "upload_here.bin"
        ticket_id, _ = tickets.mint("upload", target, max_bytes=1234)
        redeemed = tickets.redeem(ticket_id, "upload")
        assert redeemed.path == target
        assert redeemed.max_bytes == 1234


# ====================================================================== #
#  OperationLogger — the audit trail
# ====================================================================== #

def _read_records(path: Path) -> list[dict[str, Any]]:
    """Parse a JSONL log into records, failing loudly on a malformed line."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line]


class TestOperationLogger:
    """The audit log is the only record of what the remote agent did, so its
    format has to stay machine-readable and its growth has to stay bounded."""

    def test_creates_the_parent_directory(self, log_path: Path) -> None:
        assert not log_path.parent.exists()
        OperationLogger(str(log_path), max_bytes=0)
        assert log_path.parent.is_dir()

    def test_writes_one_parseable_json_object_per_line(self, log_path: Path) -> None:
        oplog = OperationLogger(str(log_path), max_bytes=0)
        for i in range(3):
            oplog.log(tool=f"tool_{i}", arguments={"i": i}, status="success", duration_ms=1.0)

        records = _read_records(log_path)
        assert [r["tool"] for r in records] == ["tool_0", "tool_1", "tool_2"]

    def test_record_carries_the_expected_keys(self, log_path: Path) -> None:
        oplog = OperationLogger(str(log_path), max_bytes=0)
        oplog.log(
            tool="read_file",
            arguments={"path": "C:/x.txt"},
            status="error",
            duration_ms=12.3456,
            error="boom",
            result_summary="{}",
        )
        record = _read_records(log_path)[0]

        assert set(record) >= {
            "timestamp", "tool", "arguments", "status", "duration_ms",
        }
        assert record["tool"] == "read_file"
        assert record["arguments"] == {"path": "C:/x.txt"}
        assert record["status"] == "error"
        assert record["duration_ms"] == 12.35  # rounded to 2dp
        assert record["error"] == "boom"

    def test_optional_fields_are_absent_when_not_supplied(self, log_path: Path) -> None:
        oplog = OperationLogger(str(log_path), max_bytes=0)
        oplog.log(tool="glob", arguments={}, status="success", duration_ms=0.0)
        record = _read_records(log_path)[0]
        assert "error" not in record
        assert "result_summary" not in record

    def test_non_ascii_arguments_are_written_verbatim(self, log_path: Path) -> None:
        # ensure_ascii=False keeps the log readable by a human; a mangled path
        # in an audit trail is worse than no audit trail.
        oplog = OperationLogger(str(log_path), max_bytes=0)
        oplog.log(tool="read_file", arguments={"path": "D:/项目/报告.txt"},
                  status="success", duration_ms=0.0)
        assert "报告.txt" in log_path.read_text(encoding="utf-8")

    def test_rotates_past_max_bytes_and_starts_a_fresh_file(self, log_path: Path) -> None:
        # max_bytes=1 makes every write after the first trip the threshold, so
        # the rotation boundary is exercised without writing megabytes.
        oplog = OperationLogger(str(log_path), max_bytes=1)
        oplog.log(tool="first", arguments={}, status="success", duration_ms=0.0)
        oplog.log(tool="second", arguments={}, status="success", duration_ms=0.0)

        backup = log_path.with_name(log_path.name + ".1")
        assert backup.is_file()
        assert [r["tool"] for r in _read_records(backup)] == ["first"]
        # The live file restarts empty and holds only what came after rotation.
        assert [r["tool"] for r in _read_records(log_path)] == ["second"]

    def test_rotation_keeps_exactly_one_generation(self, log_path: Path) -> None:
        # Deliberately not an archive: the previous .1 is replaced, and no .2
        # is ever created.
        oplog = OperationLogger(str(log_path), max_bytes=1)
        for name in ("first", "second", "third"):
            oplog.log(tool=name, arguments={}, status="success", duration_ms=0.0)

        backup = log_path.with_name(log_path.name + ".1")
        assert [r["tool"] for r in _read_records(backup)] == ["second"]
        assert [r["tool"] for r in _read_records(log_path)] == ["third"]
        assert not log_path.with_name(log_path.name + ".2").exists()

    def test_max_bytes_zero_disables_rotation(self, log_path: Path) -> None:
        oplog = OperationLogger(str(log_path), max_bytes=0)
        for i in range(20):
            oplog.log(tool=f"t{i}", arguments={"pad": "x" * 400},
                      status="success", duration_ms=0.0)

        assert not log_path.with_name(log_path.name + ".1").exists()
        assert len(_read_records(log_path)) == 20

    def test_long_string_arguments_are_truncated_in_the_record(
        self, log_path: Path
    ) -> None:
        # A write_file call can carry hundreds of kilobytes of content; copying
        # it into the audit log would turn the log into a second copy of the
        # filesystem.
        oplog = OperationLogger(str(log_path), max_bytes=0)
        payload = "A" * 5000
        oplog.log(tool="write_file", arguments={"content": payload},
                  status="success", duration_ms=0.0)

        logged = _read_records(log_path)[0]["arguments"]["content"]
        assert len(logged) < len(payload)
        assert logged.startswith("A" * 500)
        assert "truncated" in logged
        assert "5000" in logged  # the original length is still recoverable

    def test_short_argument_values_are_left_alone(self, log_path: Path) -> None:
        oplog = OperationLogger(str(log_path), max_bytes=0)
        oplog.log(tool="grep", arguments={"pattern": "def .*", "context_lines": 2},
                  status="success", duration_ms=0.0)
        record = _read_records(log_path)[0]
        assert record["arguments"] == {"pattern": "def .*", "context_lines": 2}

    def test_oversized_structured_arguments_are_truncated(self, log_path: Path) -> None:
        oplog = OperationLogger(str(log_path), max_bytes=0)
        oplog.log(tool="x", arguments={"items": [f"item-{i}" for i in range(500)]},
                  status="success", duration_ms=0.0)
        logged = _read_records(log_path)[0]["arguments"]["items"]
        # Serialised to a string once it is too big to keep whole.
        assert isinstance(logged, str)
        assert logged.endswith("...<truncated>")


# ====================================================================== #
#  BearerAuthMiddleware — the front door
# ====================================================================== #

class TestBearerAuth:
    """Nothing but /health and the ticketed transfer endpoints may pass without
    a valid token."""

    @staticmethod
    def _bearer(token: str) -> list[tuple[bytes, bytes]]:
        return [(b"authorization", f"Bearer {token}".encode())]

    async def test_health_is_public(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        # The tunnel's health check has no credential to offer.
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN)
        result = await run_asgi(app, http_scope(path="/health"))
        assert result.status == 200
        assert downstream_app.reached

    async def test_request_without_any_credential_is_rejected(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN)
        result = await run_asgi(app, http_scope(path="/sse"))
        assert result.status == 401
        assert not downstream_app.reached

    async def test_wrong_bearer_token_is_rejected(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN)
        scope = http_scope(path="/messages", method="POST",
                           headers=self._bearer("w" * 32))
        result = await run_asgi(app, scope)
        assert result.status == 403
        assert not downstream_app.reached

    async def test_token_of_the_wrong_length_is_rejected(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        # compare_digest raises on mismatched-length bytes in some usages; the
        # middleware must return a clean 403 rather than a 500.
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN)
        scope = http_scope(path="/messages", method="POST", headers=self._bearer("short"))
        result = await run_asgi(app, scope)
        assert result.status == 403

    async def test_non_bearer_auth_scheme_is_rejected(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN)
        scope = http_scope(path="/messages", method="POST",
                           headers=[(b"authorization", b"Basic YWJjOmRlZg==")])
        result = await run_asgi(app, scope)
        assert result.status == 401
        assert not downstream_app.reached

    async def test_correct_bearer_token_reaches_the_app(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN)
        scope = http_scope(path="/messages", method="POST",
                           headers=self._bearer(TEST_TOKEN))
        result = await run_asgi(app, scope)
        assert result.status == 200
        assert downstream_app.reached

    async def test_query_parameter_token_is_accepted_when_enabled(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        # URL-only clients cannot send headers; this is the documented fallback.
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN, allow_query_token=True)
        result = await run_asgi(app, http_scope(path="/sse", query=f"token={TEST_TOKEN}"))
        assert result.status == 200
        assert downstream_app.reached

    async def test_query_parameter_token_is_refused_when_disabled(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN, allow_query_token=False)
        result = await run_asgi(app, http_scope(path="/sse", query=f"token={TEST_TOKEN}"))
        assert result.status == 401
        assert not downstream_app.reached

    async def test_wrong_query_parameter_token_is_rejected(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN)
        result = await run_asgi(app, http_scope(path="/sse", query="token=nope"))
        assert result.status == 403
        assert not downstream_app.reached

    async def test_unregistered_session_id_does_not_admit_a_post(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        # Session admission is the one path that skips the token, so a
        # made-up session_id must not be enough on its own.
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN)
        scope = http_scope(path="/messages/", method="POST",
                           query="session_id=fabricated")
        result = await run_asgi(app, scope)
        assert result.status == 401
        assert not downstream_app.reached

    @pytest.mark.parametrize("path", ["/download/abc123", "/upload/abc123"])
    async def test_transfer_endpoints_bypass_the_bearer_token(
        self, path: str, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        # Deliberate: the transfer URL is handed to a remote sandbox, so it
        # carries a single-use ticket instead of the long-lived token.  The
        # ticket is checked downstream — this only pins that the middleware
        # steps aside rather than 401-ing the request.
        app = BearerAuthMiddleware(downstream_app, TEST_TOKEN)
        result = await run_asgi(app, http_scope(path=path))
        assert result.status == 200
        assert downstream_app.reached


# ====================================================================== #
#  RateLimitMiddleware
# ====================================================================== #

class TestRateLimit:
    """The token bucket is what keeps a runaway agent from hammering the
    machine, so exhaustion has to actually refuse."""

    async def test_requests_up_to_capacity_pass_then_the_next_is_refused(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        # refill_per_sec=0 freezes the bucket, so the assertion does not depend
        # on how long the test itself takes to run.
        app = RateLimitMiddleware(downstream_app, capacity=3, refill_per_sec=0.0)
        for _ in range(3):
            assert (await run_asgi(app, http_scope(path="/health"))).status == 200

        refused = await run_asgi(app, http_scope(path="/health"))
        assert refused.status == 429
        assert len(downstream_app.scopes) == 3

    async def test_refusal_tells_the_client_when_to_retry(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        app = RateLimitMiddleware(downstream_app, capacity=1, refill_per_sec=0.0)
        await run_asgi(app, http_scope(path="/health"))
        refused = await run_asgi(app, http_scope(path="/health"))

        assert refused.status == 429
        assert refused.header("retry-after") == "1"
        assert "error" in refused.json()

    async def test_bucket_refills_over_time(
        self, downstream_app: Any, http_scope: Any, run_asgi: Any
    ) -> None:
        # Rather than sleeping, wind the internal clock back: the refill is a
        # function of elapsed monotonic time, and one second at 10/s is plenty.
        app = RateLimitMiddleware(downstream_app, capacity=2, refill_per_sec=10.0)
        for _ in range(2):
            await run_asgi(app, http_scope(path="/health"))
        assert (await run_asgi(app, http_scope(path="/health"))).status == 429

        app._last_refill -= 1.0  # noqa: SLF001 — no seam for injecting a clock
        assert (await run_asgi(app, http_scope(path="/health"))).status == 200
