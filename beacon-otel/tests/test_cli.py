"""Behavior of the Beacon command-line entry point."""

from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch

import pytest
from beacon_otel import __version__
from beacon_otel.cli import main


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(sys, "argv", ["beacon", "--version"]):
        main()
    assert capsys.readouterr().out == f"Beacon Python {__version__}\n"


def test_help(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(sys, "argv", ["beacon", "--help"]):
        main()
    assert "usage: beacon" in capsys.readouterr().out


def test_missing_command(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(sys, "argv", ["beacon"]):
        with pytest.raises(SystemExit, match="2"):
            main()
    assert "usage: beacon" in capsys.readouterr().out


def test_launch_selects_beacon_entry_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OTEL_PYTHON_DISTRO", raising=False)
    monkeypatch.delenv("OTEL_PYTHON_CONFIGURATOR", raising=False)
    with (
        patch.object(sys, "argv", ["beacon", "python", "app.py"]),
        patch(
            "beacon_otel.cli.distribution",
            side_effect=PackageNotFoundError,
        ),
        patch("beacon_otel.cli.run") as run,
    ):
        main()
    run.assert_called_once_with()
    assert os.environ["OTEL_PYTHON_DISTRO"] == "beacon"
    assert os.environ["OTEL_PYTHON_CONFIGURATOR"] == "beacon"


def test_launch_keeps_explicit_distro(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OTEL_PYTHON_DISTRO", "custom")
    monkeypatch.setenv("OTEL_PYTHON_CONFIGURATOR", "custom")
    with (
        patch.object(sys, "argv", ["beacon", "python", "app.py"]),
        patch(
            "beacon_otel.cli.distribution",
            side_effect=PackageNotFoundError,
        ),
        patch("beacon_otel.cli.run"),
    ):
        main()
    assert os.environ["OTEL_PYTHON_DISTRO"] == "custom"
    assert os.environ["OTEL_PYTHON_CONFIGURATOR"] == "custom"


def test_legacy_profiling_conflict_is_actionable() -> None:
    with (
        patch.object(sys, "argv", ["beacon", "python", "app.py"]),
        patch("beacon_otel.cli.distribution") as legacy_distribution,
    ):
        legacy_distribution.return_value = object()
        with pytest.raises(SystemExit, match="conflicting legacy profiling"):
            main()
