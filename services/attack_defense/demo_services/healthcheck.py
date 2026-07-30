from __future__ import annotations

import json
import sys
import urllib.request


try:
    with urllib.request.urlopen("http://127.0.0.1:9000/health", timeout=2) as response:
        payload = json.load(response)
    raise SystemExit(0 if payload.get("status") == "healthy" else 1)
except Exception:
    raise SystemExit(1)
