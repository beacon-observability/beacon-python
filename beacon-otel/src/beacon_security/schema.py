from __future__ import annotations

import datetime as dt
import hashlib
import re

SCHEMA_VERSION = 2
FINGERPRINT_VERSION = 1
PRODUCT = "io.beacon.security"


def sink_fields(rule, role, function, location):
    aliases = {
        "template": "sql_template",
        "shell": "shell_script",
        "shell_command": "shell_script",
        "argv": "argument",
        "ordinary_argument": "argument",
        "unknown_target": "destination_unknown",
        "request_path": "path_or_query",
        "request_query": "path_or_query",
        "path_query": "path_or_query",
    }
    sink = {
        "function": function,
        "role": aliases.get(role, role),
        "location": location,
        "operation": "",
        "path_role": "",
        "input_part": "",
    }
    if rule == "http_request_input":
        sink["input_part"] = (
            "path" if role == "request_path" else "query" if role == "request_query" else "path_or_query"
        )
    if rule == "path_traversal":
        sink["role"] = "file_path"
        name = function.lower()
        operation = "unknown"
        if re.search(r"copy|\.cp(?:sync)?$|\.link(?:sync)?$", name):
            operation = "copy"
        elif re.search(r"rename|\.move$", name):
            operation = "rename"
        elif re.search(r"delete|unlink|rmdir|\.rm(?:sync)?$", name):
            operation = "delete"
        elif role in ("read", "write", "delete", "rename"):
            operation = role
        elif role == "source" or re.search(r"inputstream|reader|directorystream|\.read", name):
            operation = "read"
        elif role == "target" or re.search(r"outputstream|writer|\.write", name):
            operation = "write"
        sink["operation"] = operation
        sink["path_role"] = "unknown"
        if role in ("source", "read"):
            sink["path_role"] = "source"
        elif role in ("target", "write", "delete", "destination_path"):
            sink["path_role"] = "target"
        elif role == "file_path" and operation in ("copy", "rename", "read"):
            sink["path_role"] = "source"
        elif role == "file_path" and operation in ("write", "delete"):
            sink["path_role"] = "target"
    return sink


def _normalize_surrogates(value):
    text = str(value)
    result = []
    index = 0
    while index < len(text):
        code = ord(text[index])
        if 0xD800 <= code <= 0xDBFF:
            if index + 1 < len(text):
                low = ord(text[index + 1])
                if 0xDC00 <= low <= 0xDFFF:
                    result.append(chr(0x10000 + ((code - 0xD800) << 10) + low - 0xDC00))
                    index += 2
                    continue
            result.append("\ufffd")
        elif 0xDC00 <= code <= 0xDFFF:
            result.append("\ufffd")
        else:
            result.append(text[index])
        index += 1
    return "".join(result)


def _utf16_sort_key(value):
    return value.encode("utf-16-be")


def finding_fingerprint(application_id, language, rule, sink, signatures):
    result = hashlib.sha256()
    normalized_signatures = sorted(
        {_normalize_surrogates(value) for value in signatures},
        key=_utf16_sort_key,
    )
    parts = [
        "1",
        application_id,
        language,
        rule,
        sink["role"],
        sink["function"],
        sink["location"],
        sink["operation"],
        sink["path_role"],
        sink["input_part"],
        *normalized_signatures,
    ]
    for part in parts:
        value = _normalize_surrogates(part).encode("utf-8")
        result.update(len(value).to_bytes(4, "big"))
        result.update(value)
    return "finding-" + result.hexdigest()


def trace_id(value, length):
    text = str(value or "").lower()
    return text if len(text) == length and re.fullmatch("[0-9a-f]+", text) and set(text) != {"0"} else ""


def component_reference(value=None):
    value = value or {}
    if value.get("name") is None:
        return {}
    return {key: value[key] for key in ("name", "version", "hash") if value.get(key) is not None}


def request_fields(value=None):
    return {
        "method": "",
        "route": "",
        "route_status": "unavailable",
        "status_code": None,
        "started_at": None,
        "ended_at": None,
        "framework": "",
        "transport": "",
        "error_type": "",
        **(value or {}),
    }


def event_record(original, identity=None):
    event = dict(original)
    from .config import runtime_identity

    source = {
        "application_id": "",
        "instance_id": "",
        "service": {},
        "code": {
            "repository": "",
            "commit": "",
            "build_id": "",
            "service_version": "",
        },
        "runtime": runtime_identity(),
        "identity_status": "incomplete",
        **(identity or {}),
        **(event.pop("identity", None) or {}),
    }
    for field in (
        "application_id",
        "instance_id",
        "service",
        "code",
        "runtime",
        "identity_status",
    ):
        if field not in event and field in source:
            event[field] = source[field]
    event["schema_version"] = SCHEMA_VERSION
    name = event.get("event_name")
    event["source"] = "beacon_security_sbom" if name == "beacon.security.sbom.inventory" else "beacon_security"
    event.setdefault(
        "observed_at",
        dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )
    if event.get("event_name") == "beacon.security.finding":
        event["request"] = request_fields(event.get("request"))
        event["trace_id"] = trace_id(event.get("trace_id"), 32)
        event["server_span_id"] = trace_id(event.get("server_span_id"), 16) if event["trace_id"] else ""
        event["current_span_id"] = trace_id(event.get("current_span_id"), 16) if event["trace_id"] else ""
        event["trace_flags"] = int(event.get("trace_flags") or 0) & 0xFF if event["server_span_id"] else 0
        event["trace_availability"] = "not_guaranteed_by_trace_id"
    if event.get("event_name") == "beacon.security.finding":
        event["component"] = component_reference(event.get("component"))
        event.setdefault("stack", [])
    if name == "beacon.security.finding":
        event.setdefault(
            "attack_evidence",
            {
                "status": "unknown",
                "reason": "analysis_unavailable",
                "outcome": "not_assessed",
            },
        )
    return event
