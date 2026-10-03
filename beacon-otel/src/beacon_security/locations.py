from __future__ import annotations

import os
import sys

from .config import included


def caller_location() -> str:
    frame = sys._getframe(1)
    try:
        for _ in range(64):
            if frame is None:
                break
            module = frame.f_globals.get("__name__", "")
            if included(module):
                code = frame.f_code
                return f"{module}#{code.co_qualname}({os.path.basename(code.co_filename)}:{frame.f_lineno})"[
                    :1024
                ]
            frame = frame.f_back
        return "python#unknown"
    finally:
        del frame


def call_stack() -> list[str]:
    result = []
    frame = sys._getframe(1)
    try:
        for _ in range(64):
            if frame is None or len(result) >= 24:
                break
            name = frame.f_globals.get("__name__", "")
            if not name.startswith(
                ("beacon_security", "opentelemetry", "wrapt")
            ):
                result.append(
                    f"{name}#{frame.f_code.co_qualname}({os.path.basename(frame.f_code.co_filename)}:{frame.f_lineno})"[
                        :1024
                    ]
                )
            frame = frame.f_back
        return result
    finally:
        del frame
