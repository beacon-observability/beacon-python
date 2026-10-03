from __future__ import annotations

import importlib

import wrapt


class Patches:
    def __init__(self):
        self.entries = []

    def wrap(self, target, attribute: str, wrapper) -> bool:
        if isinstance(target, str):
            target = importlib.import_module(target)
        original = getattr(target, attribute, None)
        if original is None:
            return False
        installed = wrapt.FunctionWrapper(original, wrapper)
        setattr(target, attribute, installed)
        self.entries.append((target, attribute, original, installed))
        return True

    def restore(self):
        for target, attribute, original, installed in reversed(self.entries):
            if getattr(target, attribute, None) is installed:
                setattr(target, attribute, original)
        self.entries.clear()
