from __future__ import annotations

import importlib
import importlib.util
import py_compile
import sys
from pathlib import Path

import pytest


def _loader(monkeypatch, tmp_path, module_name: str):
    loader = importlib.import_module("beacon_security.loader")
    loader.uninstall()
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", module_name)
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_EXCLUDE", "")
    monkeypatch.syspath_prepend(str(tmp_path))
    return loader


def _remove_module(loader, module_name: str) -> None:
    sys.modules.pop(module_name, None)
    loader.uninstall()


def test_loader_install_is_idempotent_and_uninstall_is_repeatable(
    monkeypatch, tmp_path
):
    module_name = "qa_loader_repeat_fixture"
    loader = _loader(monkeypatch, tmp_path, module_name)
    try:
        loader.install()
        finder = loader._finder
        assert finder is not None
        assert sys.meta_path.count(finder) == 1

        loader.install()
        assert loader._finder is finder
        assert sys.meta_path.count(finder) == 1
    finally:
        _remove_module(loader, module_name)
    assert finder not in sys.meta_path
    loader.uninstall()


def test_loader_executes_source_without_rewriting_existing_source_pyc(
    monkeypatch, tmp_path
):
    module_name = "qa_loader_pyc_fixture"
    uncached_name = "qa_loader_uncached_fixture"
    loader = _loader(monkeypatch, tmp_path, f"{module_name},{uncached_name}")
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text("VALUE = 41 + 1\n", encoding="utf-8")
    pyc_path = Path(importlib.util.cache_from_source(str(module_path)))
    pyc_path.parent.mkdir(parents=True, exist_ok=True)
    py_compile.compile(str(module_path), cfile=str(pyc_path), doraise=True)
    before_bytes = pyc_path.read_bytes()
    before_mtime = pyc_path.stat().st_mtime_ns
    uncached_path = tmp_path / f"{uncached_name}.py"
    uncached_path.write_text("VALUE = 43 + 1\n", encoding="utf-8")
    uncached_pyc = Path(importlib.util.cache_from_source(str(uncached_path)))
    assert not uncached_pyc.exists()
    try:
        loader.install()
        imported = importlib.import_module(module_name)
        uncached = importlib.import_module(uncached_name)
        assert imported.VALUE == 42
        assert uncached.VALUE == 44
        assert pyc_path.read_bytes() == before_bytes
        assert pyc_path.stat().st_mtime_ns == before_mtime
        assert not uncached_pyc.exists()
    finally:
        _remove_module(loader, module_name)
        sys.modules.pop(uncached_name, None)


def test_loader_application_failure_executes_transformed_module_once(
    monkeypatch, tmp_path
):
    module_name = "qa_loader_failure_fixture"
    loader = _loader(monkeypatch, tmp_path, module_name)
    counter = tmp_path / "failure-count.txt"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text(
        "from pathlib import Path\n"
        f"counter = Path({str(counter)!r})\n"
        "count = int(counter.read_text() or '0') if counter.exists() else 0\n"
        "counter.write_text(str(count + 1))\n"
        "raise RuntimeError('application import failure')\n",
        encoding="utf-8",
    )
    try:
        loader.install()
        try:
            importlib.import_module(module_name)
        except RuntimeError as error:
            assert str(error) == "application import failure"
        else:
            raise AssertionError("the failing module unexpectedly imported")
        assert counter.read_text(encoding="utf-8") == "1"
    finally:
        _remove_module(loader, module_name)


def test_loader_compile_failure_falls_back_once_and_records_gap(
    monkeypatch, tmp_path
):
    module_name = "qa_loader_compile_fixture"
    loader = _loader(monkeypatch, tmp_path, module_name)
    counter = tmp_path / "compile-count.txt"
    module_path = tmp_path / f"{module_name}.py"
    module_path.write_text(
        "from pathlib import Path\n"
        f"counter = Path({str(counter)!r})\n"
        "count = int(counter.read_text() or '0') if counter.exists() else 0\n"
        "counter.write_text(str(count + 1))\n"
        "VALUE = 'fallback'\n",
        encoding="utf-8",
    )
    runtime = importlib.import_module("beacon_security.runtime")
    gaps: list[str] = []
    monkeypatch.setattr(runtime, "startup_gap", gaps.append)

    def fail_compile(*args, **kwargs):
        raise SyntaxError("forced loader compile failure")

    loader_module = importlib.import_module("beacon_security.loader")
    monkeypatch.setattr(loader_module, "compile", fail_compile, raising=False)
    try:
        loader.install()
        imported = importlib.import_module(module_name)
        assert imported.VALUE == "fallback"
        assert counter.read_text(encoding="utf-8") == "1"
        assert any(
            reason.startswith(
                f"ast_transform_failed:{module_name}:SyntaxError"
            )
            for reason in gaps
        )
    finally:
        _remove_module(loader, module_name)


@pytest.mark.parametrize(
    "limit,reason",
    [
        ("MAX_SOURCE_BYTES", "transform_source_limit"),
        ("MAX_AST_NODES", "transform_node_limit"),
        ("MAX_ANALYSIS_WORK", "transform_analysis_limit"),
    ],
)
def test_loader_transform_limits_keep_native_execution_and_report_gap(
    monkeypatch, tmp_path, limit, reason
):
    module_name = "qa_loader_budget_fixture"
    loader = _loader(monkeypatch, tmp_path, module_name)
    transformer = importlib.import_module("beacon_security.transform")
    monkeypatch.setattr(transformer, limit, 1)
    counter = tmp_path / "executions.txt"
    (tmp_path / f"{module_name}.py").write_text(
        "from pathlib import Path\n"
        f"counter = Path({str(counter)!r})\n"
        "counter.write_text(counter.read_text() + 'x' if counter.exists() else 'x')\n"
        "def check():\n    business = 42\n    return locals()['business']\n",
        encoding="utf-8",
    )
    gaps = []
    monkeypatch.setattr(
        importlib.import_module("beacon_security.runtime"),
        "startup_gap",
        gaps.append,
    )
    try:
        loader.install()
        imported = importlib.import_module(module_name)
        assert imported.check() == 42
        assert counter.read_text() == "x"
        assert f"{reason}:{module_name}" in gaps
    finally:
        _remove_module(loader, module_name)
