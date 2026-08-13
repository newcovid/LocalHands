"""Tests for Config: validation at load time and path expansion.

A bad config is the failure mode that matters most here — the daemon hands the
resulting whitelist straight to PathGuard, so a value that slips through
validation becomes a security decision rather than a typo.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from localhands.config import Config, ConfigError

from conftest import TEST_TOKEN


def _minimal(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    """Smallest dict that ``from_dict`` accepts, before overrides."""
    data: dict[str, Any] = {
        "auth_token": TEST_TOKEN,
        "allowed_paths": [str(tmp_path)],
    }
    data.update(overrides)
    return data


# ====================================================================== #
#  Required fields
# ====================================================================== #

class TestRequiredFields:
    """Two settings have no safe default: the token and the whitelist."""

    @pytest.mark.parametrize("token", [None, "", 0, False])
    def test_missing_or_empty_auth_token_is_refused(
        self, tmp_path: Path, token: Any
    ) -> None:
        # Defaulting the token to anything would publish the whole machine to
        # whoever finds the tunnel URL first.
        data = _minimal(tmp_path)
        if token is None:
            del data["auth_token"]
        else:
            data["auth_token"] = token
        with pytest.raises(ConfigError, match="auth_token"):
            Config.from_dict(data)

    def test_short_auth_token_is_accepted_with_a_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Deliberately not fatal — an operator mid-setup should not be locked
        # out — but it must not pass silently either.
        with caplog.at_level("WARNING"):
            cfg = Config.from_dict(_minimal(tmp_path, auth_token="short"))
        assert cfg.auth_token == "short"
        assert any("auth_token" in r.message for r in caplog.records)

    @pytest.mark.parametrize("paths", [None, [], "D:/single/string", {}, ["  "], [123]])
    def test_unusable_allowed_paths_is_refused(
        self, tmp_path: Path, paths: Any
    ) -> None:
        # An empty whitelist would leave PathGuard with nothing to compare
        # against; a bare string would iterate character by character.
        data = _minimal(tmp_path)
        if paths is None:
            del data["allowed_paths"]
        else:
            data["allowed_paths"] = paths
        with pytest.raises(ConfigError):
            Config.from_dict(data)

    def test_non_mapping_root_is_refused(self) -> None:
        with pytest.raises(ConfigError):
            Config.from_dict(["not", "a", "mapping"])  # type: ignore[arg-type]

    def test_path_entries_are_stripped(self, tmp_path: Path) -> None:
        cfg = Config.from_dict(_minimal(tmp_path, allowed_paths=[f"  {tmp_path}  "]))
        assert cfg.allowed_paths == [str(tmp_path)]


# ====================================================================== #
#  Numeric ranges
# ====================================================================== #

class TestNumericValidation:
    """Out-of-range numbers are caught at load, not at first use."""

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("port", 0),
            ("port", -1),
            ("port", 65536),
            ("max_file_size", 0),
            ("max_file_size", 1023),
            ("bash_timeout", 0),
            ("bash_timeout", -5),
            ("bash_timeout", 3601),
            ("rate_limit", 0),
            ("rate_limit", -1),
            ("sse_ping_interval", -1),
            ("log_max_bytes", -1),
            ("transfer_ticket_ttl", 0),
            ("upload_max_bytes", 0),
        ],
    )
    def test_out_of_range_value_is_refused(
        self, tmp_path: Path, key: str, value: int
    ) -> None:
        with pytest.raises(ConfigError, match=key):
            Config.from_dict(_minimal(tmp_path, **{key: value}))

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("port", 1),
            ("port", 65535),
            ("max_file_size", 1024),
            ("bash_timeout", 1),
            ("bash_timeout", 3600),
            ("rate_limit", 1),
            ("sse_ping_interval", 0),
            ("log_max_bytes", 0),
        ],
    )
    def test_boundary_value_is_accepted(
        self, tmp_path: Path, key: str, value: int
    ) -> None:
        # The boundaries are inclusive; an off-by-one here would reject a
        # perfectly ordinary config such as rate_limit: 1.
        cfg = Config.from_dict(_minimal(tmp_path, **{key: value}))
        assert getattr(cfg, key) == value

    def test_public_base_url_must_carry_a_scheme(self, tmp_path: Path) -> None:
        # Without a scheme the transfer tools would hand the agent a URL that
        # curl cannot resolve.
        with pytest.raises(ConfigError, match="public_base_url"):
            Config.from_dict(_minimal(tmp_path, public_base_url="bridge.example"))

    def test_public_base_url_trailing_slash_is_dropped(self, tmp_path: Path) -> None:
        # Transfer URLs are built as f"{base}/download/{id}"; a trailing slash
        # would produce a double slash in the path the agent curls.
        cfg = Config.from_dict(
            _minimal(tmp_path, public_base_url="https://bridge.example/")
        )
        assert cfg.public_base_url == "https://bridge.example"


# ====================================================================== #
#  resolved_allowed_paths
# ====================================================================== #

class TestResolvedAllowedPaths:
    """The whitelist as PathGuard actually sees it."""

    def test_environment_variables_are_expanded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # %TEMP% is often redirected away from its default location, which is
        # exactly why the config may name a variable instead of a literal path.
        target = tmp_path / "workspace"
        target.mkdir()
        monkeypatch.setenv("BRIDGE_TEST_ROOT", str(target))

        cfg = Config.from_dict(
            _minimal(tmp_path, allowed_paths=["%BRIDGE_TEST_ROOT%"])
        )
        assert cfg.resolved_allowed_paths == [target.resolve()]

    def test_variable_expansion_composes_with_a_subdirectory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "workspace" / "projects"
        target.mkdir(parents=True)
        monkeypatch.setenv("BRIDGE_TEST_ROOT", str(tmp_path / "workspace"))

        cfg = Config.from_dict(
            _minimal(tmp_path, allowed_paths=[r"%BRIDGE_TEST_ROOT%\projects"])
        )
        assert cfg.resolved_allowed_paths == [target.resolve()]

    def test_entries_resolving_to_the_same_directory_are_de_duplicated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Expansion and ".." normalisation can make three different-looking
        # entries name one directory; PathGuard would then compare against the
        # same root three times on every single check.
        target = tmp_path / "workspace"
        (target / "sub").mkdir(parents=True)
        monkeypatch.setenv("BRIDGE_TEST_ROOT", str(target))

        cfg = Config.from_dict(
            _minimal(
                tmp_path,
                allowed_paths=[
                    str(target),
                    "%BRIDGE_TEST_ROOT%",
                    str(target) + os.sep,
                    str(target / "sub" / ".."),
                ],
            )
        )
        assert cfg.resolved_allowed_paths == [target.resolve()]

    def test_order_is_preserved_across_de_duplication(self, tmp_path: Path) -> None:
        # The first entry is the default root for tools called without a path,
        # so ordering is behaviour, not cosmetics.
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()

        cfg = Config.from_dict(
            _minimal(tmp_path, allowed_paths=[str(first), str(second), str(first)])
        )
        assert cfg.resolved_allowed_paths == [first.resolve(), second.resolve()]

    def test_unresolvable_variable_is_dropped_not_taken_literally(
        self, tmp_path: Path
    ) -> None:
        # os.path.expandvars leaves an unknown %VAR% untouched.  Keeping it
        # would put a directory literally named "%NOPE%" on the whitelist —
        # harmless in itself, but it hides the operator's typo.
        target = tmp_path / "workspace"
        target.mkdir()

        cfg = Config.from_dict(
            _minimal(tmp_path, allowed_paths=["%NOPE%", str(target)])
        )
        assert cfg.resolved_allowed_paths == [target.resolve()]
        assert not any("NOPE" in str(p) for p in cfg.resolved_allowed_paths)

    def test_every_entry_unresolvable_yields_an_empty_whitelist(
        self, tmp_path: Path
    ) -> None:
        cfg = Config.from_dict(
            _minimal(tmp_path, allowed_paths=["%NOPE%", "%ALSO_NOPE%"])
        )
        assert cfg.resolved_allowed_paths == []

    def test_relative_entry_is_made_absolute(self, tmp_path: Path) -> None:
        cfg = Config.from_dict(_minimal(tmp_path, allowed_paths=["."]))
        resolved = cfg.resolved_allowed_paths
        assert len(resolved) == 1
        assert resolved[0].is_absolute()


class TestValidatePaths:
    """The startup self-check reports, but does not enforce."""

    def test_missing_directory_is_reported_as_a_warning(self, tmp_path: Path) -> None:
        # Non-fatal on purpose: the directory may be created after startup.
        cfg = Config.from_dict(
            _minimal(tmp_path, allowed_paths=[str(tmp_path / "not_yet")])
        )
        warnings = cfg.validate_paths()
        assert len(warnings) == 1
        assert "does not exist" in warnings[0]

    def test_file_used_as_an_allowed_path_is_reported(self, tmp_path: Path) -> None:
        target = tmp_path / "a_file.txt"
        target.write_text("x", encoding="utf-8")
        cfg = Config.from_dict(_minimal(tmp_path, allowed_paths=[str(target)]))
        warnings = cfg.validate_paths()
        assert len(warnings) == 1
        assert "not a directory" in warnings[0]

    def test_a_healthy_whitelist_produces_no_warnings(self, tmp_path: Path) -> None:
        assert Config.from_dict(_minimal(tmp_path)).validate_paths() == []


# ====================================================================== #
#  YAML loading
# ====================================================================== #

class TestFromYaml:
    """Loading is thin, but its failure messages are what an operator sees."""

    def test_round_trips_a_valid_file(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "bridge.yaml"
        cfg_file.write_text(
            f"auth_token: {TEST_TOKEN}\n"
            f"allowed_paths:\n"
            f"  - {tmp_path.as_posix()}\n"
            f"port: 18765\n",
            encoding="utf-8",
        )
        cfg = Config.from_yaml(cfg_file)
        assert cfg.auth_token == TEST_TOKEN
        assert cfg.port == 18765

    def test_missing_file_is_reported_clearly(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            Config.from_yaml(tmp_path / "absent.yaml")

    def test_empty_file_is_refused(self, tmp_path: Path) -> None:
        # An empty file would otherwise yield None and crash later with a much
        # less helpful message.
        cfg_file = tmp_path / "empty.yaml"
        cfg_file.write_text("", encoding="utf-8")
        with pytest.raises(ConfigError, match="empty"):
            Config.from_yaml(cfg_file)

    def test_malformed_yaml_is_refused(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "broken.yaml"
        cfg_file.write_text("auth_token: [unclosed\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="parse"):
            Config.from_yaml(cfg_file)


def test_config_fixture_never_reads_the_real_project_config(
    config: Config, tmp_path: Path
) -> None:
    """Guard rail for the suite itself.

    Every path the fixtures hand to PathGuard must live under tmp_path.  If a
    test ever picked up the operator's real config.yaml, the file tools
    below would be writing into their live workspace.
    """
    for root in config.resolved_allowed_paths:
        assert root.is_relative_to(tmp_path.resolve())
