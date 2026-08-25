"""Shared test fixtures: a local HTTP server that supports Range requests,
backed by in-memory or on-disk fake ISOs."""

import http.server
import os
import re
import threading

import pytest

from ps2smb.cache import ChunkCache


class FakeISOHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # silence

    def _body(self):
        if self.path not in self.server.files:
            return None
        return self.server.files[self.path]

    def _send_404(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        body = self._body()
        if body is None:
            return self._send_404()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        if self.server.support_ranges:
            self.send_header("Accept-Ranges", "bytes")
        self.end_headers()

    def do_GET(self):
        body = self._body()
        if body is None:
            return self._send_404()
        range_header = self.headers.get("Range")
        if range_header and self.server.support_ranges:
            m = re.match(r"bytes=(\d+)-(\d*)$", range_header)
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else len(body) - 1
            end = min(end, len(body) - 1)
            if start >= len(body):
                self.send_response(416)
                self.send_header("Content-Range", "bytes */%d" % len(body))
                self.end_headers()
                return
            chunk = body[start : end + 1]
            self.send_response(206)
            self.send_header("Content-Length", str(len(chunk)))
            self.send_header(
                "Content-Range", "bytes %d-%d/%d" % (start, end, len(body)))
            self.end_headers()
            self.wfile.write(chunk)
        else:
            # No range support (or no Range header): full body.
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class FakeISOServer(http.server.ThreadingHTTPServer):
    def __init__(self, files, support_ranges=True):
        super().__init__(("127.0.0.1", 0), FakeISOHandler)
        self.files = files          # path -> bytes
        self.support_ranges = support_ranges


@pytest.fixture
def iso_data():
    """Deterministic pseudo-random data so reads can be verified."""
    def make(size, seed=123456789):
        out = bytearray(size)
        x = seed
        for i in range(size):
            x = (1103515245 * x + 12345) & 0x7FFFFFFF
            out[i] = x & 0xFF
        return bytes(out)
    return make


@pytest.fixture
def fake_iso_server(iso_data):
    servers = []

    def start(files, support_ranges=True):
        srv = FakeISOServer(files, support_ranges=support_ranges)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        servers.append(srv)
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        return srv, base

    yield start

    for s in servers:
        s.shutdown()
        s.server_close()


@pytest.fixture
def cache(tmp_path):
    c = ChunkCache(str(tmp_path / "cache"), chunk_size=1024 * 1024)  # 1 MiB chunks for tests
    yield c
