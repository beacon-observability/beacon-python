from __future__ import annotations

import importlib.abc
import importlib.machinery
import os
import sys
import threading

from . import config


class Loader(importlib.abc.Loader):
    def __init__(self, original, fullname, filename):
        self.original = original
        self.fullname = fullname
        self.filename = filename

    def create_module(self, spec):
        create = getattr(self.original, "create_module", None)
        return create(spec) if create is not None else None

    def exec_module(self, module):
        from .runtime import startup_gap
        from .tracking import register_constants
        from .transform import TransformLimit, transform

        try:
            source = self.original.get_source(self.fullname)
            if source is None:
                raise ValueError("source_unavailable")
            tree = transform(source, self.filename, self.fullname)
            code = compile(tree, self.filename, "exec", dont_inherit=True)
            register_constants(code)
        except TransformLimit as error:
            startup_gap(f"{error}:{self.fullname}")
            return self.original.exec_module(module)
        except Exception as error:
            startup_gap(
                f"ast_transform_failed:{self.fullname}:{type(error).__name__}"
            )
            return self.original.exec_module(module)
        # Import-time application failures must not trigger a second execution.
        exec(code, module.__dict__)

    def __getattr__(self, name):
        return getattr(self.original, name)


class Finder(importlib.abc.MetaPathFinder):
    def __init__(self):
        self.resolving = threading.local()

    def find_spec(self, fullname, path=None, target=None):
        if not config.included(fullname):
            return None
        names = getattr(self.resolving, "names", set())
        if fullname in names:
            return None
        self.resolving.names = names | {fullname}
        try:
            return self._find_spec(fullname, path, target)
        finally:
            self.resolving.names = names

    def _find_spec(self, fullname, path, target):
        from .runtime import startup_gap

        for finder in tuple(sys.meta_path):
            if finder is self or not hasattr(finder, "find_spec"):
                continue
            spec = finder.find_spec(fullname, path, target)
            if spec is None:
                continue
            if isinstance(spec.loader, Loader):
                return spec
            if (
                spec.loader is not None
                and hasattr(spec.loader, "get_source")
                and spec.origin
                and spec.origin.endswith(".py")
            ):
                spec.loader = Loader(spec.loader, fullname, spec.origin)
            elif spec.loader is not None:
                startup_gap("module_source_unavailable:" + fullname)
            return spec
        return None


_finder = None
_lock = threading.RLock()


def install():
    global _finder
    with _lock:
        if _finder is not None:
            return
        from .runtime import startup_gap

        for name, module in tuple(sys.modules.items()):
            if config.included(name) and module is not None:
                startup_gap("module_imported_before_instrumentation:" + name)
        _finder = Finder()
        sys.meta_path.insert(0, _finder)


def uninstall():
    global _finder
    with _lock:
        if _finder in sys.meta_path:
            sys.meta_path.remove(_finder)
        _finder = None


def _after_fork():
    global _lock
    _lock = threading.RLock()
    if _finder is not None:
        _finder.resolving = threading.local()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)
