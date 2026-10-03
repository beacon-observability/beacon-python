from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict

from .scenario import form_sql_case, run_case, stream_chunks, target_payload


class Payload(BaseModel):
    model_config = ConfigDict(extra="allow")
    query: str = "body-query"
    filename: str = "safe.txt"
    callback: str | None = None


app = FastAPI()


@app.get("/health")
async def health():
    return {"ok": True}


@app.get("/target")
async def target(request: Request):
    return target_payload(request.query_params.get("q", "target"))


@app.post("/probe/{item}")
async def probe(item: str, request: Request, payload: Payload | None = None):
    raw = await request.body()
    data = payload or Payload()
    query = request.query_params.get("q") or data.query
    callback = request.query_params.get("callback") or data.callback
    return JSONResponse(
        run_case(
            query=query,
            item=item,
            header=request.headers.get("x-security-query", ""),
            body=raw.decode("utf-8", "replace"),
            body_query=data.query,
            filename=request.query_params.get("filename") or data.filename,
            callback=callback,
            target_url=request.app.state.target_url
            if hasattr(request.app.state, "target_url")
            else None,
        )
    )


@app.post("/form")
async def form(request: Request):
    values = await request.form()
    return JSONResponse(form_sql_case(str(values.get("query", ""))))


@app.post("/text")
async def text(request: Request):
    raw = await request.body()
    return JSONResponse(form_sql_case(raw.decode("utf-8", "replace")))


@app.get("/source-only/{item}")
async def source_only(item: str, request: Request):
    # Do not read the body in this route.  The request source adapter must not
    # require application pre-reading before it can capture query/path/header.
    return {
        "item_length": len(item),
        "query_length": len(request.query_params.get("q", "")),
    }


@app.post("/stream/{item}")
async def stream(item: str, request: Request):
    payload = await request.json()
    query = str(payload.get("query", ""))
    return StreamingResponse(stream_chunks(query), media_type="text/plain")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("security_sample.fastapi_app:app", host="127.0.0.1", port=8000)
