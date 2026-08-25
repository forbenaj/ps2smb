"""ps2smb server entrypoint.

    python -m ps2smb.server --catalog catalogs/games.json --cache ./cache

Serves an SMB share of remote ISOs backed by HTTP Range + local chunk cache,
plus a small status HTTP interface.
"""

import argparse
import json
import logging
import os
import sys
import threading
from collections import deque

from .admin import AdminServer
from .cache import ChunkCache, DEFAULT_CHUNK_SIZE
from .catalog import load_catalog
from .smb import GameSMBServer


def build_state(smb_server: GameSMBServer, cache: ChunkCache, errors: deque):
    def active_downloads():
        return [
            t.name for t in threading.enumerate() if t.name.startswith("prefetch-")
        ]

    return {
        "games": smb_server.status,
        "cache_root": cache.root,
        "chunk_size": cache.chunk_size,
        "cache_bytes": cache.cached_bytes,
        "active_downloads": active_downloads,
        "recent_errors": lambda: list(errors),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ps2smb",
        description="HTTP-backed PS2 SMB game server (proof of concept)",
    )
    parser.add_argument("--catalog", required=True, help="path to games JSON catalog")
    parser.add_argument("--cache", default="./cache", help="cache directory")
    parser.add_argument("--share", default="PS2", help="SMB share name")
    parser.add_argument("--smb-host", default="0.0.0.0", help="SMB listen address")
    parser.add_argument("--smb-port", type=int, default=445, help="SMB listen port")
    parser.add_argument("--admin-host", default="127.0.0.1", help="status HTTP bind address")
    parser.add_argument("--admin-port", type=int, default=9090, help="status HTTP port")
    parser.add_argument("--chunk-mib", type=int, default=DEFAULT_CHUNK_SIZE // (1024 * 1024),
                        help="cache chunk size in MiB")
    parser.add_argument("--prefetch", type=int, default=2,
                        help="number of chunks to prefetch ahead")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    LOG = logging.getLogger("ps2smb")

    games = load_catalog(args.catalog)
    if not games:
        LOG.error("no usable games in catalog %s; exiting", args.catalog)
        return 1

    cache = ChunkCache(args.cache, chunk_size=args.chunk_mib * 1024 * 1024)
    for g in games:
        cache.scan(cache.key_for(g.url))

    errors = deque(maxlen=100)

    smb_server = GameSMBServer(
        listen_address=args.smb_host,
        port=args.smb_port,
        share_name=args.share,
        games=games,
        cache=cache,
        prefetch_count=args.prefetch,
    )

    admin = AdminServer(args.admin_host, args.admin_port,
                        build_state(smb_server, cache, errors))
    admin.start()
    LOG.info("status interface on http://%s:%d/  (games, cache, downloads, errors)",
             args.admin_host, args.admin_port)

    LOG.info("=" * 60)
    LOG.info("OPL config:  SMB share \\\\%s\\%s   (guest, no password)", _local_ip(), args.share)
    LOG.info("Games visible to OPL: %d", len(games))
    LOG.info("=" * 60)

    try:
        smb_server.start()  # blocks
    except KeyboardInterrupt:
        LOG.info("shutting down")
        smb_server.stop()
    return 0


def _local_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(main())
