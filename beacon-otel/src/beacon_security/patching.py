from __future__ import annotations

import importlib
import inspect

import wrapt


class Patches:
    def __init__(self):
        self.entries = []
        self._inherited: set[int] = set()

    def wrap(self, target, attribute: str, wrapper) -> bool:
        if isinstance(target, str):
            target = importlib.import_module(target)
        original = getattr(target, attribute, None)
        if original is None:
            return False
        installed = wrapt.FunctionWrapper(original, wrapper)
        descriptor = inspect.getattr_static(target, attribute, original)
        inherited = attribute not in getattr(target, "__dict__", {})
        setattr(target, attribute, installed)
        self.entries.append((target, attribute, descriptor, installed))
        if inherited:
            self._inherited.add(id(installed))
        return True

    def restore_from(
        self, checkpoint: int = 0, *, suppress_errors: bool = False
    ) -> None:
        for target, attribute, original, installed in reversed(
            self.entries[checkpoint:]
        ):
            # Class lookup can manufacture a fresh BoundFunctionWrapper.
            # Compare the installed descriptor without invoking __get__.
            try:
                if (
                    inspect.getattr_static(target, attribute, None)
                    is installed
                ):
                    if id(installed) in self._inherited:
                        delattr(target, attribute)
                    else:
                        setattr(target, attribute, original)
            except BaseException:
                if not suppress_errors:
                    raise
            self._inherited.discard(id(installed))
        del self.entries[checkpoint:]

    def restore(self) -> None:
        self.restore_from()
