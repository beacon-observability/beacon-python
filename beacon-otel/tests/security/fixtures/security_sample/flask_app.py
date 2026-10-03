from __future__ import annotations

import os

from flask import Flask, Response, jsonify, request

from .scenario import form_sql_case, run_case, stream_chunks, target_payload

app = Flask(__name__)


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/target")
def target():
    return target_payload(request.args.get("q", "target"))


@app.post("/probe/<item>")
def probe(item: str):
    raw = request.get_data(cache=True)
    payload = request.get_json(silent=True) or {}
    query = request.args.get("q") or payload.get("query", "body-query")
    return jsonify(
        run_case(
            query=query,
            item=item,
            header=request.headers.get("x-security-query", ""),
            body=raw.decode("utf-8", "replace"),
            body_query=payload.get("query", "body-query"),
            filename=request.args.get("filename")
            or payload.get("filename", "safe.txt"),
            callback=request.args.get("callback") or payload.get("callback"),
            target_url=app.config.get("TARGET_URL"),
        )
    )


@app.post("/form")
def form():
    return jsonify(form_sql_case(request.form.get("query", "")))


@app.post("/text")
def text():
    raw = request.get_data(cache=True)
    return jsonify(form_sql_case(raw.decode("utf-8", "replace")))


@app.get("/source-only/<item>")
def source_only(item: str):
    return {
        "item_length": len(item),
        "query_length": len(request.args.get("q", "")),
    }


@app.post("/stream/<item>")
def stream(item: str):
    payload = request.get_json(silent=True) or {}
    return Response(
        stream_chunks(str(payload.get("query", ""))), mimetype="text/plain"
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("BEACON_SECURITY_SAMPLE_PORT", "8000")),
        threaded=True,
    )
