from __future__ import annotations
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import scan

INTERVAL_SECONDS = max(300, int(os.getenv("SCAN_INTERVAL_SECONDS", "1800")))

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/health"):
            self.send_error(404)
            return
        body = b'{"ok":true,"service":"crypto-secret-exposure-worker"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        return

def scan_loop():
    while True:
        started = time.monotonic()
        try:
            print("Starting scheduled repository discovery and incremental scan.", flush=True)
            scan.main()
        except Exception as exc:
            # Do not print request bodies, environment values, or scanner output that could contain secrets.
            print(f"Worker cycle failed: {type(exc).__name__}", flush=True)
        elapsed = time.monotonic() - started
        delay = max(60, INTERVAL_SECONDS - int(elapsed))
        print(f"Next discovery cycle in {delay} seconds.", flush=True)
        time.sleep(delay)

if __name__ == "__main__":
    if not scan.WORKER_INGEST_TOKEN:
        raise SystemExit("WORKER_INGEST_TOKEN is required for hosted worker mode.")
    threading.Thread(target=scan_loop, name="scanner-loop", daemon=True).start()
    port = int(os.getenv("PORT", "10000"))
    HTTPServer(("0.0.0.0", port), HealthHandler).serve_forever()
