"""Minimal status/admin HTTP interface (no external web framework)."""

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = logging.getLogger("ps2smb.admin")


def make_admin_handler(state):
    class AdminHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # route through our logger
            LOG.debug("admin %s", fmt % args)

        def _send(self, code, payload):
            body = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.rstrip("/") or "/"
            if path == "/":
                self._send(200, {
                    "endpoints": ["/games", "/cache", "/downloads", "/errors", "/health"],
                })
            elif path == "/games":
                self._send(200, {"games": state["games"]()})
            elif path == "/cache":
                self._send(200, {
                    "root": state["cache_root"],
                    "chunk_size": state["chunk_size"],
                    "total_bytes": state["cache_bytes"](),
                })
            elif path == "/downloads":
                self._send(200, {"active_prefetches": state["active_downloads"]()})
            elif path == "/errors":
                self._send(200, {"recent_errors": state["recent_errors"]()})
            elif path == "/health":
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not found"})

    return AdminHandler


class AdminServer:
    def __init__(self, address: str, port: int, state):
        self._httpd = ThreadingHTTPServer((address, port), make_admin_handler(state))
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True, name="ps2smb-admin")

    def start(self):
        self._thread.start()

    def stop(self):
        self._httpd.shutdown()
