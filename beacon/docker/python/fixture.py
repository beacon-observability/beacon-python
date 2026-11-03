"""Application with no telemetry imports, launched through the public beacon command."""

import sys
import time

import requests

response = requests.get(sys.argv[1] + "/application", timeout=10)
response.raise_for_status()
print("TRACEPARENT " + response.text, flush=True)
deadline = time.monotonic() + 4
while time.monotonic() < deadline:
    sum(i * i for i in range(10000))
    time.sleep(0.01)
