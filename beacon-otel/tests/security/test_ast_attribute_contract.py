from __future__ import annotations

import importlib

from beacon_security.transform import transform


def _start_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("BEACON_SECURITY_ENABLED", "true")
    monkeypatch.setenv("BEACON_SECURITY_PYTHON_INCLUDE", "security_sample")
    monkeypatch.setenv("BEACON_SECURITY_OUTPUT", str(tmp_path))
    monkeypatch.setenv("BEACON_SECURITY_SBOM_ENABLED", "false")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")
    monkeypatch.setenv("OTEL_METRICS_EXPORTER", "none")
    monkeypatch.setenv("OTEL_LOGS_EXPORTER", "none")
    runtime = importlib.import_module("beacon_security.runtime")
    if getattr(runtime, "_runtime", None) is not None:
        runtime.stop()
    runtime = importlib.reload(runtime)
    state = runtime.start_request({"route": "/ast-attributes"})
    token = runtime.attach_state(state)
    return runtime, state, token


def _execute_transformed(source_text, filename, runtime, **extra):
    tree = transform(source_text, filename, "security_sample.ast_attributes")
    namespace = {
        "__name__": "security_sample.ast_attributes",
        "__file__": filename,
        "runtime": runtime,
        **extra,
    }
    exec(compile(tree, filename, "exec"), namespace)
    return namespace


def test_attribute_helper_preserves_private_names_super_and_property_evaluation(
    monkeypatch, tmp_path
):
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    try:
        namespace = _execute_transformed(
            """
class Parent:
    def greet(self):
        return "parent"

class Child(Parent):
    def __init__(self, value):
        self.__value = value
        self.calls = []

    @property
    def query(self):
        self.calls.append("query")
        return self.__value

    def render(self):
        private_value = self.__value
        inherited_value = super().greet()
        property_value = self.query
        frame_sensitive = "private_value" in locals()
        return private_value, inherited_value, property_value, tuple(self.calls), frame_sensitive
""",
            "ast_attributes_fixture.py",
            runtime,
        )
        value = "private-query"
        runtime.source(value, "http.request.parameter", "q")
        result = namespace["Child"](value).render()
        assert result == (value, "parent", value, ("query",), True)
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def test_fstring_custom_format_and_mapping_unknown_call_execute_once_and_fail_open(
    monkeypatch, tmp_path
):
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)

    unknown_calls: list[str] = []

    def unknown(value):
        unknown_calls.append(value)
        return "mapped:" + value

    try:
        namespace = _execute_transformed(
            """
class CustomFormatter:
    def __init__(self, calls):
        self.calls = calls

    def __format__(self, spec):
        self.calls.append(spec)
        return "formatted:" + spec

def render(value, unknown):
    format_calls = []
    def make_spec():
        format_calls.append("spec")
        return ">8"
    formatted = f"{CustomFormatter(format_calls):{make_spec()}}"
    mapped = "{item}".format_map({"item": unknown(value)})
    return formatted, mapped, format_calls
""",
            "ast_custom_format_fixture.py",
            runtime,
            unknown=unknown,
        )
        value = "mapping-query"
        runtime.source(value, "http.request.parameter", "q")
        formatted, mapped, format_calls = namespace["render"](value, unknown)
        assert type(formatted) is str and formatted == "formatted:>8"
        assert type(mapped) is str and mapped == "mapped:" + value
        assert format_calls == ["spec", ">8"]
        assert unknown_calls == [value]
        assert "unmodeled_call_result" in state.gaps
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def test_type_observation_does_not_execute_business_class_getters(
    monkeypatch, tmp_path
):
    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    try:
        namespace = _execute_transformed(
            """
class Carrier:
    def __init__(self): self.probes = 0
    @property
    def __class__(self):
        self.probes += 1
        raise AssertionError("unexpected class read")
def consume(value): return value.probes
def run(value): return consume(value)
""",
            "type_observation.py",
            runtime,
        )
        for active in (False, True):
            value = namespace["Carrier"]()
            with runtime.bound_state(state if active else None):
                assert namespace["run"](value) == 0
            assert value.probes == 0
        assert not any(
            gap.startswith(
                ("call_observation_error", "attribute_observation_error")
            )
            for gap in state.gaps
        )
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)


def test_url_subclass_observation_does_not_iterate_or_read_business_properties(
    monkeypatch, tmp_path
):
    import urllib.parse

    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    try:
        fixture = _execute_transformed(
            """
def inspect(value):
    count = len(value)
    host = value.hostname
    return count, host
""",
            "url_subclass.py",
            runtime,
        )
        calls = []

        class Parts(urllib.parse.SplitResult):
            def __iter__(self):
                calls.append("iteration")
                raise AssertionError("business iterator must not be called")

            @property
            def hostname(self):
                calls.append("hostname")
                return "business-host"

            @property
            def netloc(self):
                calls.append("netloc")
                raise AssertionError("unrequested property")

        for active in (False, True):
            calls.clear()
            with runtime.bound_state(state) if active else runtime.suppress():
                assert fixture["inspect"](
                    Parts("https", "example.com", "/", "", "")
                ) == (5, "business-host")
            assert calls == ["hostname"]
        normal = urllib.parse.urlsplit("https://example.com/path")
        state.source(normal.netloc, "http.request.parameter", "authority")
        result = fixture["inspect"](normal)
        assert result == (5, "example.com")
        assert state.marks(result[1])
        assert "unmodeled_url_parts_subclass" in state.gaps
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)
