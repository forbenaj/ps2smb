"""RemoteFile: a sparse, seekable, random-access view of a remote ISO.

    SMB read(offset, length)
        -> RemoteFile.read(offset, length)
        -> ChunkCache lookup
        -> HTTP Range request if needed
        -> remote host

Capabilities are probed once per URL (HEAD: Content-Length + Accept-Ranges,
verified with a tiny test Range GET). Servers without byte-range support are
rejected loudly instead of silently downloading whole multi-GB ISOs.
"""

import logging
import threading
from typing import Optional

import requests

from .cache import ChunkCache

LOG = logging.getLogger("ps2smb.remote")

USER_AGENT = "ps2smb-poc/0.1"
PROBE_BYTES = 16


class RemoteFileError(IOError):
    """Raised when the remote server cannot serve the file the way we need."""


class NoRangeSupport(RemoteFileError):
    """Remote server does not support byte ranges; file cannot be served."""


class RemoteFile:
    def __init__(self, url: str, cache: ChunkCache, timeout: float = 30.0):
        self.url = url
        self.cache = cache
        self.timeout = timeout
        self.file_key = cache.key_for(url)

        self.size: Optional[int] = None
        self.accept_ranges = False
        self.probed = False
        self.error: Optional[str] = None

        self._session = requests.Session()
        self._session.headers["User-Agent"] = USER_AGENT
        self._probe_lock = threading.Lock()
        self._prefetch_lock = threading.Lock()
        self._pending_prefetch: set = set()

    # ---------------------------------------------------------------- probe

    def probe(self) -> bool:
        """Check HEAD/Content-Length/Range support. Returns True if usable."""
        with self._probe_lock:
            if self.probed:
                return self.error is None
            try:
                self._probe()
            except (requests.RequestException, RemoteFileError) as e:
                self.error = "probe failed for %s: %s" % (self.url, e)
                LOG.error(self.error)
            self.probed = True
            if self.error is None:
                LOG.info("remote OK   %s (size=%s, ranges=%s)",
                         self.url, self.size, self.accept_ranges)
            return self.error is None

    def _probe(self) -> None:
        resp = self._session.head(self.url, timeout=self.timeout, allow_redirects=True)
        LOG.info("HEAD %s -> %d", self.url, resp.status_code)
        if resp.status_code >= 400:
            raise RemoteFileError("HEAD %s returned HTTP %d" % (self.url, resp.status_code))

        length = resp.headers.get("Content-Length")
        if length is None:
            # Some hosts omit Content-Length on HEAD but still serve ranges.
            LOG.warning("no Content-Length on HEAD for %s; trying range probe", self.url)
        else:
            self.size = int(length)

        accept_ranges = resp.headers.get("Accept-Ranges", "").lower() == "bytes"

        # Verify range support with an actual tiny request; headers can lie.
        r = self._session.get(
            self.url,
            headers={"Range": "bytes=0-%d" % (PROBE_BYTES - 1)},
            timeout=self.timeout,
            allow_redirects=True,
        )
        if r.status_code == 206:
            self.accept_ranges = True
            if self.size is None and "Content-Range" in r.headers:
                # Content-Range: bytes 0-15/123456789
                total = r.headers["Content-Range"].rsplit("/", 1)[-1]
                if total.isdigit():
                    self.size = int(total)
        elif r.status_code == 200:
            self.accept_ranges = False
        else:
            raise RemoteFileError(
                "range probe for %s returned unexpected HTTP %d" % (self.url, r.status_code)
            )

        if not self.accept_ranges:
            raise NoRangeSupport(
                "%s does not support byte-range requests. "
                "Serving this game would require downloading the entire ISO; "
                "refusing. (Accept-Ranges=%r, probe status=%d)"
                % (self.url, resp.headers.get("Accept-Ranges"), r.status_code)
            )
        if self.size is None:
            raise RemoteFileError(
                "cannot determine size of %s (no Content-Length / Content-Range)" % self.url
            )

    # ------------------------------------------------------------------ read

    def _chunk_len(self, index: int) -> int:
        start = index * self.cache.chunk_size
        return min(self.cache.chunk_size, max(0, self.size - start))

    def _fetch_range(self, start: int, end_exclusive: int) -> bytes:
        """HTTP GET with Range header; returns exactly end-start bytes."""
        end_inclusive = end_exclusive - 1
        resp = self._session.get(
            self.url,
            headers={"Range": "bytes=%d-%d" % (start, end_inclusive)},
            timeout=self.timeout,
            stream=False,
        )
        LOG.info("HTTP GET %s Range: bytes=%d-%d -> %d",
                 self.url, start, end_inclusive, resp.status_code)
        if resp.status_code == 416:
            raise RemoteFileError(
                "range %d-%d out of bounds for %s (size=%s)"
                % (start, end_inclusive, self.url, self.size)
            )
        if resp.status_code != 206:
            raise RemoteFileError(
                "expected 206 Partial Content from %s, got HTTP %d "
                "(server may not honor Range despite advertising it)"
                % (self.url, resp.status_code)
            )
        data = resp.content
        if len(data) != end_exclusive - start:
            raise RemoteFileError(
                "short body from %s: asked %d bytes, got %d"
                % (self.url, end_exclusive - start, len(data))
            )
        return data

    def ensure_probed(self) -> None:
        if not self.probe():
            err = self.error or "remote file unusable"
            if "does not support byte-range" in err:
                raise NoRangeSupport(err)
            raise RemoteFileError(err)

    def read(self, offset: int, length: int) -> bytes:
        """Read up to `length` bytes at `offset`, serving from cache when possible."""
        self.ensure_probed()
        if offset >= self.size:
            return b""
        length = min(length, self.size - offset)

        first = offset // self.cache.chunk_size
        last = (offset + length - 1) // self.cache.chunk_size

        parts = []
        for index in range(first, last + 1):
            chunk = self.cache.get_or_download(
                self.file_key, index, self._fetch_range, self._chunk_len
            )
            cstart = index * self.cache.chunk_size
            lo = max(offset, cstart)
            hi = min(offset + length, cstart + len(chunk))
            parts.append(chunk[lo - cstart : hi - cstart])

        data = b"".join(parts)
        assert len(data) == length, (len(data), length)
        return data

    def prefetch(self, chunk_index: int) -> None:
        """Best-effort background download of one chunk (sequential prefetch).
        Skips chunks already cached or already being prefetched."""
        if self.cache.has_chunk(self.file_key, chunk_index):
            return
        with self._prefetch_lock:
            if chunk_index in self._pending_prefetch:
                return
            self._pending_prefetch.add(chunk_index)

        def worker():
            try:
                self.cache.get_or_download(
                    self.file_key, chunk_index, self._fetch_range, self._chunk_len
                )
                LOG.info("prefetch done %s chunk %d", self.file_key, chunk_index)
            except Exception as e:
                LOG.warning("prefetch failed %s chunk %d: %s", self.file_key, chunk_index, e)
            finally:
                with self._prefetch_lock:
                    self._pending_prefetch.discard(chunk_index)

        threading.Thread(target=worker, daemon=True, name="prefetch-%d" % chunk_index).start()

    # ------------------------------------------------------------- metadata

    def stat(self):
        """(size, mtime) tuple compatible with impacket's os.stat usage."""
        import os
        self.ensure_probed()
        marker = os.path.join(self.cache.root, self.file_key, "meta")
        try:
            mtime = os.path.getmtime(marker)
        except OSError:
            mtime = 0.0
        return (0o100644, 0, 0, 1, 0, 0, self.size, mtime, mtime, mtime)
