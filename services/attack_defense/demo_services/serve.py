from __future__ import annotations

import os
import signal
import subprocess
import sys


def main() -> int:
    module = os.environ["DEMO_SERVICE_MODULE"]
    public = subprocess.Popen([
        sys.executable, "-m", "uvicorn", f"{module}:game_app",
        "--host", "0.0.0.0", "--port", "9000", "--no-access-log",
    ])
    management = subprocess.Popen([
        sys.executable, "-m", "uvicorn", f"{module}:management_app",
        "--host", "0.0.0.0", "--port", "9001", "--no-access-log",
    ])

    def stop(*_: object) -> None:
        public.terminate()
        management.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        code = public.poll()
        if code is not None:
            management.terminate()
            return code
        code = management.poll()
        if code is not None:
            public.terminate()
            return code
        signal.pause()


if __name__ == "__main__":
    raise SystemExit(main())
