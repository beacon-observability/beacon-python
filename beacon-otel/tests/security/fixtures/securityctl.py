#!/usr/bin/env python3
"""Local inspection and controlled verification for Beacon Security."""

import argparse
import datetime as dt
import fcntl
import json
import os
import re
import sys
import tempfile
import time
import uuid
from pathlib import Path


def now():
    return dt.datetime.now(dt.timezone.utc)


def stamp(value=None):
    return (
        (value or now())
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def read(path):
    path = Path(path)
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("snapshot exceeds 128 MiB reader limit")
    with path.open() as stream:
        return json.load(stream)


def write(path, data):
    data = {**data, "source": "beacon_security"}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".securityctl-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parse_time(value):
    # Java Instant can carry nanoseconds; older Python accepts only 3 or 6 fractional digits.
    normalized = re.sub(
        r"\.(\d+)",
        lambda match: "." + (match.group(1) + "000000")[:6],
        value,
        count=1,
    )
    return dt.datetime.fromisoformat(normalized.replace("Z", "+00:00"))


def age(document):
    return (now() - parse_time(document["updated_at"])).total_seconds()


def fresh_health(directory):
    health = read(directory / "health.json")
    if age(health) > 15:
        raise ValueError(
            "health is stale; process state and control acknowledgement are unknown"
        )
    return health


def control(args, mutate):
    directory = Path(args.dir)
    health = fresh_health(directory)
    path = Path(args.control) if args.control else directory / "control.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with (path.parent / (path.name + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        value = (
            read(path)
            if path.exists()
            else {
                "schema_version": 1,
                "source": "beacon_security",
                "paused": False,
            }
        )
        mutate(value, health)
        revision = str(uuid.uuid4())
        value["revision"] = revision
        write(path, value)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        latest = fresh_health(directory)
        if latest.get("control_revision") == revision:
            return latest
        if (
            latest.get("control_error")
            and latest.get("control_error_revision") == revision
        ):
            raise ValueError(
                "agent rejected control: " + latest["control_error"]
            )
        time.sleep(0.2)
    raise ValueError(
        "control acknowledgement timed out; inspect health/control_error; action is not confirmed"
    )


def query(args):
    directory = Path(args.dir)
    name = {
        "findings": "findings.json",
        "runs": "runs.json",
        "sbom": "application.cdx.json",
        "history": "sbom-history.json",
    }[args.kind]
    value = read(directory / name)
    key = {"sbom": "components", "history": "entries"}.get(
        args.kind, args.kind
    )
    rows = value.get(key, [])
    ids = None
    if args.run and args.kind == "findings":
        runs = read(directory / "runs.json").get("runs", [])
        selected = next(
            (run for run in runs if run["run_id"] == args.run), None
        )
        ids = selected.get("finding_counts", {}) if selected else {}
    if args.case and args.kind == "findings":
        case_ids = {
            key
            for run in read(directory / "runs.json").get("runs", [])
            if run.get("case_id") == args.case
            for key in run.get("finding_counts", {})
        }
        ids = case_ids if ids is None else set(ids) & case_ids
    filtered = []
    for row in rows:
        if args.rule and row.get("rule") != args.rule:
            continue
        if (
            args.finding
            and row.get("finding_id", row.get("bom-ref")) != args.finding
        ):
            continue
        if ids is not None and row.get("finding_id") not in ids:
            continue
        if args.kind == "runs" and (
            (args.run and row.get("run_id") != args.run)
            or (args.case and row.get("case_id") != args.case)
        ):
            continue
        filtered.append(row)
    filtered.sort(
        key=lambda row: str(
            row.get("finding_id", row.get("run_id", row.get("bom-ref", "")))
        )
    )
    return {
        "schema_version": 1,
        "source": "beacon_security",
        "total": len(filtered),
        "offset": args.offset,
        "next_offset": args.offset + args.limit
        if args.offset + args.limit < len(filtered)
        else None,
        "updated_at": value.get(
            "updated_at", value.get("metadata", {}).get("timestamp")
        ),
        "items": filtered[args.offset : args.offset + args.limit],
    }


def run_start(args):
    run_id = args.id or "run-" + str(uuid.uuid4())

    def mutate(value, health):
        existing = value.get("run")
        if existing and parse_time(existing["expires_at"]) > now():
            raise ValueError(
                "another verification run is active; stop it first"
            )
        if not health.get("effective"):
            raise ValueError(
                "collection must be effective before starting verification"
            )
        if not health.get("rule_status", {}).get(args.rule):
            raise ValueError("selected rule is disabled or unsupported")
        value["run"] = {
            "run_id": run_id,
            "case_id": args.case,
            "rule": args.rule,
            "expires_at": stamp(now() + dt.timedelta(seconds=args.ttl)),
            "conditions": {
                "suite": args.suite,
                "fixture": args.fixture,
                "expected_requests": args.expected_requests,
            },
        }

    control(args, mutate)
    return {
        "run_id": run_id,
        "status": "active",
        "scope": "all HTTP requests in this process during this run; isolate test traffic",
    }


def run_stop(args):
    active = {}

    def mutate(value, health):
        active.update(value.get("run") or {})
        if not active:
            raise ValueError("no active verification run")
        value["run"] = None

    control(args, mutate)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        run = next(
            (
                run
                for run in read(Path(args.dir) / "runs.json")["runs"]
                if run["run_id"] == active["run_id"]
            ),
            None,
        )
        if run and run.get("status") == "closed":
            if args.output:
                write(args.output, run)
            return run
        time.sleep(0.2)
    raise ValueError(
        "run is draining active requests; query runs before verifying"
    )


def verify(args):
    baseline, candidate = read(args.baseline), read(args.candidate)
    reasons = []
    comparable = []
    for field in ("case_id", "rule", "instrumentation_profile", "conditions"):
        if not baseline.get(field) or baseline.get(field) != candidate.get(
            field
        ):
            comparable.append("mismatched_or_missing_" + field)
    if baseline.get("identity", {}).get("application_id") != candidate.get(
        "identity", {}
    ).get("application_id"):
        comparable.append("application_mismatch")
    for label, run in (("baseline", baseline), ("candidate", candidate)):
        for field in ("repository", "commit", "build_id"):
            if not run.get("identity", {}).get("code", {}).get(field):
                reasons.append(label + "_missing_" + field)
        if run.get("status") != "closed" or run.get("active_requests", 1) != 0:
            reasons.append(label + "_not_closed")
        if (
            not run.get("collection_enabled")
            or not run.get("rule_enabled")
            or run.get("expired")
        ):
            reasons.append(label + "_disabled_or_expired")
        expected = run.get("conditions", {}).get("expected_requests", 0)
        if (
            not isinstance(expected, int)
            or expected <= 0
            or run.get("requests") != expected
        ):
            reasons.append(label + "_unexpected_traffic")
        for field in ("source_requests", "sink_requests"):
            if run.get(field, 0) < max(
                1, expected if isinstance(expected, int) else 1
            ):
                reasons.append(label + "_missing_" + field)
        for field in ("incomplete_requests", "error_requests"):
            if run.get(field, 0):
                reasons.append(label + "_" + field)
        if run.get("delivery_loss", 0) or run.get("snapshot_failures", 0):
            reasons.append(label + "_observation_or_delivery_loss")
    baseline_sources = baseline.get("risk_source_signatures", {})
    if not baseline_sources:
        reasons.append("baseline_risk_source_identity_missing")
    expected = candidate.get("conditions", {}).get("expected_requests", 1)
    for signature in baseline_sources:
        if candidate.get("source_signatures", {}).get(signature, 0) < (
            expected if isinstance(expected, int) and expected > 0 else 1
        ):
            reasons.append("candidate_missing_baseline_source:" + signature)
    if baseline.get("observations", 0) <= 0:
        reasons.append("baseline_did_not_reproduce_risk")
    if candidate.get("observations", 0) > 0:
        outcome = "observed"
    elif reasons or comparable:
        outcome = "inconclusive"
    else:
        outcome = "not_observed"
    result = {
        "schema_version": 1,
        "source": "beacon_security",
        "report_id": "verification-" + str(uuid.uuid4()),
        "created_at": stamp(),
        "outcome": outcome,
        "baseline_run_id": baseline.get("run_id"),
        "candidate_run_id": candidate.get("run_id"),
        "case_id": candidate.get("case_id"),
        "rule": candidate.get("rule"),
        "conditions": candidate.get("conditions"),
        "baseline_identity": baseline.get("identity"),
        "candidate_identity": candidate.get("identity"),
        "baseline_findings": baseline.get("finding_counts", {}),
        "candidate_findings": candidate.get("finding_counts", {}),
        "reasons": comparable + reasons,
        "comparability": "caller_declared_suite_and_fixture_with_observed_request_source_sink_counters",
        "meaning": {
            "observed": "Risk dataflow was observed; exploitation is not confirmed.",
            "not_observed": "Risk was not observed under these specified test conditions; this is not proof of a fix or complete coverage.",
            "inconclusive": "The observations cannot support a negative verification conclusion.",
        }[outcome],
    }
    if args.output:
        write(args.output, result)
    return result


def compare(args):
    def findings(path):
        path = Path(path)
        value = read(path / "findings.json" if path.is_dir() else path)
        return value, {item["finding_id"]: item for item in value["findings"]}

    before, left = findings(args.before)
    after, right = findings(args.after)
    return {
        "schema_version": 1,
        "source": "beacon_security",
        "before_identity": before.get("identity"),
        "after_identity": after.get("identity"),
        "new_in_snapshot": sorted(right.keys() - left.keys()),
        "not_observed_in_snapshot": sorted(left.keys() - right.keys()),
        "present_in_both": sorted(left.keys() & right.keys()),
        "meaning": "Snapshot membership comparison, not repair verification. Fingerprints include source code line positions.",
    }


def exception_add(args):
    if not args.reason.strip():
        raise ValueError("a non-empty review reason is required")

    def mutate(value, health):
        identity = health["identity"]["application_id"]
        if args.finding not in {
            item["finding_id"]
            for item in read(Path(args.dir) / "findings.json")["findings"]
        }:
            raise ValueError(
                "finding is not present in this instance snapshot"
            )
        entries = [
            item
            for item in value.get("exceptions", [])
            if item["scope"].get("finding_id") != args.finding
        ]
        entries.append(
            {
                "scope": {
                    "application_id": identity,
                    "finding_id": args.finding,
                },
                "decision": args.decision,
                "reason": args.reason,
                "expires_at": stamp(now() + dt.timedelta(seconds=args.ttl)),
            }
        )
        value["exceptions"] = entries

    control(args, mutate)
    return {
        "finding_id": args.finding,
        "decision": args.decision,
        "meaning": "Scoped review annotation; collection and verification counts are preserved.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir",
        default="beacon-security-output",
        help="one process output directory",
    )
    parser.add_argument(
        "--control",
        help="override control file to match beacon.security.control.file",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    for name in ("pause", "resume"):
        commands.add_parser(name)
    q = commands.add_parser("query")
    q.add_argument(
        "kind",
        choices=("findings", "runs", "sbom", "history"),
        default="findings",
        nargs="?",
    )
    for name in ("rule", "finding", "run", "case"):
        q.add_argument("--" + name)
    q.add_argument("--offset", type=int, default=0)
    q.add_argument("--limit", type=int, default=100)
    start = commands.add_parser("run-start")
    for name in ("case", "rule", "suite", "fixture"):
        start.add_argument("--" + name, required=True)
    start.add_argument("--id")
    start.add_argument("--expected-requests", type=int, default=1)
    start.add_argument("--ttl", type=int, default=300)
    stop = commands.add_parser("run-stop")
    stop.add_argument("--output")
    v = commands.add_parser("verify")
    v.add_argument("--baseline", required=True)
    v.add_argument("--candidate", required=True)
    v.add_argument("--output")
    c = commands.add_parser("compare")
    c.add_argument("--before", required=True)
    c.add_argument("--after", required=True)
    e = commands.add_parser("exception-add")
    e.add_argument("--finding", required=True)
    e.add_argument(
        "--decision",
        required=True,
        choices=("accepted_risk", "false_positive"),
    )
    e.add_argument("--reason", required=True)
    e.add_argument("--ttl", type=int, required=True)
    remove = commands.add_parser("exception-remove")
    remove.add_argument("--finding", required=True)
    args = parser.parse_args()
    if hasattr(args, "ttl") and not 1 <= args.ttl <= 30 * 86400:
        parser.error("ttl must be 1..2592000 seconds")
    if hasattr(args, "expected_requests") and args.expected_requests < 1:
        parser.error("expected-requests must be positive")
    if hasattr(args, "limit") and (
        not 1 <= args.limit <= 1000 or args.offset < 0
    ):
        parser.error("limit must be 1..1000 and offset non-negative")
    try:
        if args.command == "status":
            result = read(Path(args.dir) / "health.json")
            result["stale"] = age(result) > 15
        elif args.command in ("pause", "resume"):
            result = control(
                args,
                lambda value, health: value.update(
                    paused=args.command == "pause"
                ),
            )
        elif args.command == "exception-remove":
            result = control(
                args,
                lambda value, health: value.update(
                    exceptions=[
                        item
                        for item in value.get("exceptions", [])
                        if item["scope"].get("finding_id") != args.finding
                    ]
                ),
            )
        else:
            result = {
                "query": query,
                "run-start": run_start,
                "run-stop": run_stop,
                "verify": verify,
                "compare": compare,
                "exception-add": exception_add,
            }[args.command](args)
        result["source"] = "beacon_security"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return (
            3
            if args.command == "verify" and result["outcome"] == "inconclusive"
            else 0
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(
            json.dumps({"source": "beacon_security", "error": str(error)}),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
