"""Small deterministic FastAPI workload used only by the QA benchmark."""

from __future__ import annotations

import sqlite3

from fastapi import FastAPI

app = FastAPI()


@app.get("/bench")
def bench(query: str = "benchmark-query"):
    """Propagate a query into a parameterized local lookup.

    The response deliberately omits the input and stays a fixed small JSON
    shape.  There are no command, filesystem, or self-HTTP operations in this
    workload, so the measured cost is request handling plus the intended
    parameterized database boundary.
    """

    lookup = "lookup:{}".format(query)
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("create table benchmark_values (value text)")
        connection.execute(
            "insert into benchmark_values(value) values (?)", ("known",)
        )
        rows = connection.execute(
            "select value from benchmark_values where value = ?", (lookup,)
        ).fetchall()
    finally:
        connection.close()
    return {"ok": True, "matched": len(rows)}
