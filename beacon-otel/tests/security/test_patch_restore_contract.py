from __future__ import annotations

import inspect

from beacon_security.patching import Patches


def _passthrough(wrapped, instance, args, kwargs):
    return wrapped(*args, **kwargs)


def test_class_method_descriptor_and_inheritance_restore_exactly() -> None:
    class Parent:
        def execute(self, value):
            return value

        @classmethod
        def factory(cls):
            return cls()

    class Child(Parent):
        pass

    execute = inspect.getattr_static(Parent, "execute")
    factory = inspect.getattr_static(Parent, "factory")
    patches = Patches()
    for _ in range(2):
        patches.wrap(Parent, "execute", _passthrough)
        patches.wrap(Parent, "factory", _passthrough)
        patches.wrap(Child, "execute", _passthrough)
        assert Child().execute(42) == 42
        patches.restore()
        assert inspect.getattr_static(Parent, "execute") is execute
        assert inspect.getattr_static(Parent, "factory") is factory
        assert "execute" not in Child.__dict__
        assert type(Child.factory()) is Child


def test_partial_rollback_keeps_earlier_hooks_and_external_replacements() -> (
    None
):
    class Target:
        def first(self):
            return 1

        def second(self):
            return 2

    patches = Patches()
    first = inspect.getattr_static(Target, "first")
    second = inspect.getattr_static(Target, "second")
    patches.wrap(Target, "first", _passthrough)
    installed = inspect.getattr_static(Target, "first")
    checkpoint = len(patches.entries)
    patches.wrap(Target, "second", _passthrough)
    patches.restore_from(checkpoint)
    assert inspect.getattr_static(Target, "first") is installed
    assert inspect.getattr_static(Target, "second") is second

    def replacement(self):
        return 3

    Target.first = replacement
    patches.restore()
    assert Target.first is replacement
    assert first is not replacement
