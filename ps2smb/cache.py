"""Persistent chunk-based cache for remote ISO data.

Each remote file gets its own directory under the cache root:

    <cache_root>/<file_key>/chunks/<NNNNNN>.chunk

A chunk file is only created once fully downloaded, so partial chunks are
never served. Chunk size is fixed (default 8 MiB). The last chunk of a file
may be shorter.

Thread safety: a per-file lock serializes downloads of the same chunk, while
reads of already-present chunks are lock-free apart from an existence check.
"""

import hashlib
import logging
import os
import threading
from typing import Dict, Optional, Set

LOG = logging.getLogger("ps2smb.cache")

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB


class ChunkCache:
    def __init__(self, root: str, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.root = os.path.abspath(root)
        self.chunk_size = chunk_size
        os.makedirs(self.root, exist_ok=True)
        # file_key -> {chunk_index: path} of chunks known to exist on disk
        self._present: Dict[str, Set[int]] = {}
        # file_key -> {chunk_index: threading.Lock} of per-chunk download locks
        self._locks: Dict[str, Dict[int, threading.Lock]] = {}
        self._locks_guard = threading.Lock()

    # ------------------------------------------------------------------ keys

    def key_for(self, url: str) -> str:
        """Deterministic cache directory key for a URL."""
        return hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]

    def _file_dir(self, file_key: str) -> str:
        return os.path.join(self.root, file_key)

    def _chunks_dir(self, file_key: str) -> str:
        return os.path.join(self._file_dir(file_key), "chunks")

    def _chunk_path(self, file_key: str, index: int) -> str:
        return os.path.join(self._chunks_dir(file_key), "%08d.chunk" % index)

    def _lock_for(self, file_key: str, index: int) -> threading.Lock:
        """One lock per (file, chunk): a foreground read only ever waits on
        the chunk it actually needs, never on unrelated downloads."""
        with self._locks_guard:
            return self._locks.setdefault(file_key, {}).setdefault(index, threading.Lock())

    # ------------------------------------------------------------- discovery

    def scan(self, file_key: str) -> None:
        """Rebuild the set of cached chunk indices from disk (startup/restart)."""
        present: Set[int] = set()
        chunks_dir = self._chunks_dir(file_key)
        if os.path.isdir(chunks_dir):
            for name in os.listdir(chunks_dir):
                if name.endswith(".chunk"):
                    try:
                        present.add(int(name[: -len(".chunk")]))
                    except ValueError:
                        continue
        with self._locks_guard:
            self._present[file_key] = present

    def has_chunk(self, file_key: str, index: int) -> bool:
        with self._locks_guard:
            return index in self._present.get(file_key, set())

    def cached_chunks(self, file_key: str) -> Set[int]:
        with self._locks_guard:
            return set(self._present.get(file_key, set()))

    def cached_bytes(self, file_key: Optional[str] = None) -> int:
        """Total bytes stored. For one file, or the whole cache."""
        if file_key is not None:
            total = 0
            chunks_dir = self._chunks_dir(file_key)
            if os.path.isdir(chunks_dir):
                for name in os.listdir(chunks_dir):
                    try:
                        total += os.path.getsize(os.path.join(chunks_dir, name))
                    except OSError:
                        pass
            return total
        total = 0
        for entry in os.listdir(self.root):
            total += self.cached_bytes(entry)
        return total

    # ------------------------------------------------------------------- I/O

    def read_chunk(self, file_key: str, index: int) -> Optional[bytes]:
        """Return chunk bytes if present on disk, else None."""
        if not self.has_chunk(file_key, index):
            return None
        path = self._chunk_path(file_key, index)
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError as e:
            LOG.warning("chunk %s/%d read failed (%s); will re-download", file_key, index, e)
            with self._locks_guard:
                self._present.get(file_key, set()).discard(index)
            return None

    def store_chunk(self, file_key: str, index: int, data: bytes) -> None:
        """Atomically write a chunk to disk and mark it present."""
        chunks_dir = self._chunks_dir(file_key)
        os.makedirs(chunks_dir, exist_ok=True)
        final_path = self._chunk_path(file_key, index)
        tmp_path = final_path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, final_path)
        with self._locks_guard:
            self._present.setdefault(file_key, set()).add(index)
        LOG.debug("cache write %s chunk %d (%d bytes)", file_key, index, len(data))

    def get_or_download(
        self,
        file_key: str,
        index: int,
        fetch_range,  # callable(start, end_exclusive) -> bytes
        expected_len=None,  # callable(index) -> exact length of this chunk
    ) -> bytes:
        """Return chunk bytes, downloading via fetch_range if not cached.

        A per-chunk lock prevents two threads from downloading the same chunk
        concurrently; after acquiring it we re-check the cache. Different
        chunks (e.g. a foreground read vs. background prefetch of the next
        chunk) download in parallel.
        """
        data = self.read_chunk(file_key, index)
        if data is not None:
            LOG.info("cache HIT  %s chunk %d", file_key, index)
            return data

        with self._lock_for(file_key, index):
            data = self.read_chunk(file_key, index)
            if data is not None:
                LOG.info("cache HIT  %s chunk %d (after wait)", file_key, index)
                return data
            start = index * self.chunk_size
            length = expected_len(index) if expected_len else self.chunk_size
            LOG.info("cache MISS %s chunk %d -> HTTP range [%d, %d)",
                     file_key, index, start, start + length)
            data = fetch_range(start, start + length)
            if len(data) != length:
                raise IOError(
                    "short read for %s chunk %d: got %d bytes, expected %d"
                    % (file_key, index, len(data), length)
                )
            self.store_chunk(file_key, index, data)
            return data
