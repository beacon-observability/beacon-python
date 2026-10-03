from __future__ import annotations

import json
import os

from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="security-sample-only",
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["*"],
        MIDDLEWARE=[],
        DEFAULT_CHARSET="utf-8",
    )

import django

django.setup()

from django.core.wsgi import get_wsgi_application
from django.http import JsonResponse, StreamingHttpResponse
from django.urls import path

from .scenario import form_sql_case, run_case, stream_chunks, target_payload


def health(request):
    return JsonResponse({"ok": True})


def target(request):
    return JsonResponse(target_payload(request.GET.get("q", "target")))


def probe(request, item: str):
    raw = request.body
    try:
        payload = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = {}
    query = request.GET.get("q") or payload.get("query", "body-query")
    return JsonResponse(
        run_case(
            query=query,
            item=item,
            header=request.headers.get("x-security-query", ""),
            body=raw.decode("utf-8", "replace"),
            body_query=payload.get("query", "body-query"),
            filename=request.GET.get("filename")
            or payload.get("filename", "safe.txt"),
            callback=request.GET.get("callback") or payload.get("callback"),
            target_url=os.environ.get("BEACON_SECURITY_SAMPLE_TARGET_URL"),
        )
    )


def form(request):
    return JsonResponse(form_sql_case(request.POST.get("query", "")))


def text(request):
    return JsonResponse(form_sql_case(request.body.decode("utf-8", "replace")))


def source_only(request, item: str):
    return JsonResponse(
        {
            "item_length": len(item),
            "query_length": len(request.GET.get("q", "")),
        }
    )


def stream(request, item: str):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = {}
    return StreamingHttpResponse(
        stream_chunks(str(payload.get("query", ""))), content_type="text/plain"
    )


urlpatterns = [
    path("health", health),
    path("target", target),
    path("probe/<str:item>", probe),
    path("form", form),
    path("text", text),
    path("source-only/<str:item>", source_only),
    path("stream/<str:item>", stream),
]

wsgi = get_wsgi_application()


if __name__ == "__main__":
    from wsgiref.simple_server import make_server

    make_server("127.0.0.1", 8000, wsgi).serve_forever()
