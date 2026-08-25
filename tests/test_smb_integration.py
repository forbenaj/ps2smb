"""Integration test: access the SMB share from a normal SMB client and read
arbitrary regions of a virtual ISO.

Uses impacket's SMB1/SMB2 client against our hooked server, with a local
fake HTTP range server standing in for the remote ISO host. This exercises
the full path: SMB open -> virtual handle -> RemoteFile -> cache -> HTTP Range.
"""

import threading

import pytest

from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection

from ps2smb.cache import ChunkCache
from ps2smb.catalog import Game
from ps2smb.smb import GameSMBServer


@pytest.fixture
def smb_setup(fake_iso_server, iso_data, tmp_path):
    data = iso_data(5 * 1024 * 1024 + 999)  # > 2 chunks at 1 MiB
    _, base = fake_iso_server({"/remote.iso": data})

    cache = ChunkCache(str(tmp_path / "cache"), chunk_size=1024 * 1024)
    games = [Game(name="Test Game", url=base + "/remote.iso", filename="Test Game.iso")]

    # port 0 lets the OS pick a free port for parallel-safe tests
    server = GameSMBServer("127.0.0.1", 0, "PS2", games, cache, prefetch_count=0)
    port = server.raw_server.socket.getsockname()[1]
    t = threading.Thread(target=server.start, daemon=True)
    t.start()

    yield {"server": server, "cache": cache, "data": data,
           "port": port, "games": games}

    server.stop()


class TestSMBIntegration:
    def _connect(self, port):
        # OPL speaks SMB1; impacket's SimpleSMBServer has SMB2 disabled by
        # default, so the client must negotiate the SMB1 dialect.
        conn = SMBConnection("*SMBSERVER", "127.0.0.1",
                             sess_port=port, preferredDialect=SMB_DIALECT)
        conn.login("", "")
        return conn

    def test_list_share(self, smb_setup):
        conn = self._connect(smb_setup["port"])
        try:
            conn.connectTree("PS2")
            shares = conn.listPath("PS2", "*")
            names = [f.get_longname() for f in shares]
            assert any("Test Game.iso" in n for n in names)
        finally:
            conn.close()

    def test_read_arbitrary_regions(self, smb_setup):
        conn = self._connect(smb_setup["port"])
        data = smb_setup["data"]
        try:
            tid = conn.connectTree("PS2")
            fid = conn.openFile("PS2", "Test Game.iso")

            regions = [
                (0, 4096),
                (1024 * 1024 - 100, 200),   # straddles chunk boundary
                (4 * 1024 * 1024 + 500, 400),
                (123456, 64000),            # SMB1 MaxCount is 16-bit; client caps at 64000
                (5 * 1024 * 1024 + 900, 99),  # near EOF
            ]
            for offset, length in regions:
                out = conn.readFile(tid, fid, offset, length)
                got = out if isinstance(out, (bytes, bytearray)) else b"".join(out)
                expected = data[offset : offset + length]
                assert got == expected, "mismatch at offset %d" % offset
        finally:
            conn.close()

    def test_sequential_reads_via_file_handle(self, smb_setup):
        """Simulate OPL-style sequential reading through one open file."""
        conn = self._connect(smb_setup["port"])
        data = smb_setup["data"]
        try:
            tid = conn.connectTree("PS2")
            fid = conn.openFile("PS2", "Test Game.iso")
            pos = 2048
            for _ in range(10):
                out = conn.readFile(tid, fid, pos, 32 * 1024)
                got = out if isinstance(out, (bytes, bytearray)) else b"".join(out)
                assert got == data[pos : pos + 32 * 1024]
                pos += 32 * 1024
        finally:
            conn.close()

    def test_cache_populated_through_smb(self, smb_setup):
        conn = self._connect(smb_setup["port"])
        cache = smb_setup["cache"]
        game = smb_setup["games"][0]
        key = cache.key_for(game.url)
        try:
            tid = conn.connectTree("PS2")
            fid = conn.openFile("PS2", "Test Game.iso")
            conn.readFile(tid, fid, 0, 1024)
            assert cache.has_chunk(key, 0)

            # second client read of same region must hit cache (no new HTTP)
            http_calls_before = sum(
                1 for r in smb_setup["server"]._remotes.values())
            conn.readFile(tid, fid, 0, 1024)
            assert sum(1 for r in smb_setup["server"]._remotes.values()) == http_calls_before
        finally:
            conn.close()
