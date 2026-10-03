from __future__ import annotations

import importlib
import json

from beacon_security.sinks.http import _report_http
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
    state = runtime.start_request({"route": "/url-components"})
    token = runtime.attach_state(state)
    return runtime, state, token


def _execute_transformed(source_text, filename, runtime):
    tree = transform(source_text, filename, "security_sample.url_components")
    namespace = {
        "__name__": "security_sample.url_components",
        "__file__": filename,
        "runtime": runtime,
    }
    exec(compile(tree, filename, "exec"), namespace)
    return namespace


def test_query_only_marks_do_not_become_ssrf_for_conservative_string_forms(
    monkeypatch, tmp_path
):
    """A fixed host plus a marked query stays HTTP-input-only for common forms."""

    runtime, state, token = _start_runtime(monkeypatch, tmp_path)
    query = "".join(("name", "=alice/bob"))
    runtime.source(query, "http.request.parameter", "q")
    namespace = _execute_transformed(
        """
from urllib.parse import quote

def urls(value):
    encoded = quote(value)
    fstring_url = f"http://fixed.invalid/search?q={encoded}"
    quote_url = "http://fixed.invalid/search?q=" + quote(value)
    percent_url = "http://fixed.invalid/search?q=%s" % quote(value)
    format_url = "http://fixed.invalid/search?q={}".format(quote(value))
    return fstring_url, quote_url, percent_url, format_url
""",
        "url_components_fixture.py",
        runtime,
    )
    try:
        urls = namespace["urls"](query)
        assert all(type(url) is str for url in urls)
        for index, url in enumerate(urls):
            _report_http(f"test.url.form.{index}", url)

        by_function = {
            event["sink"]["function"]: event for event in state.pending
        }
        assert set(by_function) == {
            "test.url.form.0",
            "test.url.form.1",
            "test.url.form.2",
            "test.url.form.3",
        }
        for event in by_function.values():
            assert event["rule"] == "http_request_input"
            assert event["sink"]["role"] == "path_or_query"
            assert event["sink"]["input_part"] == "path_or_query"
            assert all("value" not in source for source in event["sources"])
            assert query not in json.dumps(event, sort_keys=True)
    finally:
        runtime.end_request(state)
        runtime.detach_state(token)
