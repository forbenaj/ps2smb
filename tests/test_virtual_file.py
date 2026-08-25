"""Tests for the HTTP-backed virtual-file layer (RemoteFile + ChunkCache),
independent of SMB."""

import threading

import pytest

from ps2smb.cache import ChunkCache
from ps2smb.remote import NoRangeSupport, RemoteFile, RemoteFileError


def make_remote(url, cache):
    r = RemoteFile(url, cache)
    assert r.probe(), "probe failed: %s" % r.error
    return r


class TestBasicReads:
    def test_read_uncached_range(self, fake_iso_server, iso_data, cache):
        data = iso_data(5 * 1024 * 1024 + 12345)
        _, base = fake_iso_server({"/game.iso": data})
        r = make_remote(base + "/game.iso", cache)

        out = r.read(1000, 64000)
        assert out == data[1000:1000 + 64000]

    def test_same_range_twice_is_cache_hit(self, fake_iso_server, iso_data, cache):
        data = iso_data(3 * 1024 * 1024)
        _, base = fake_iso_server({"/game.iso": data})
        r = make_remote(base + "/game.iso", cache)

        first = r.read(1024 * 512, 4096)
        chunks_before = len(cache.cached_chunks(r.file_key))
        second = r.read(1024 * 512, 4096)
        assert first == second == data[1024 * 512 : 1024 * 512 + 4096]
        # no new chunk downloads happened
        assert len(cache.cached_chunks(r.file_key)) == chunks_before

    def test_read_across_two_chunks(self, fake_iso_server, iso_data, cache):
        data = iso_data(3 * 1024 * 1024)
        _, base = fake_iso_server({"/game.iso": data})
        r = make_remote(base + "/game.iso", cache)

        # straddle the 1 MiB chunk boundary
        start = 1024 * 1024 - 100
        length = 200
        out = r.read(start, length)
        assert out == data[start : start + length]
        assert cache.has_chunk(r.file_key, 0)
        assert cache.has_chunk(r.file_key, 1)

    def test_random_seeking_reads(self, fake_iso_server, iso_data, cache):
        data = iso_data(8 * 1024 * 1024)
        _, base = fake_iso_server({"/game.iso": data})
        r = make_remote(base + "/game.iso", cache)

        for offset in (7_000_000, 12, 4_000_000, 1_048_576 - 1, 8 * 1024 * 1024 - 10):
            out = r.read(offset, 64)
            assert out == data[offset : offset + 64], offset

    def test_read_past_eof_returns_short(self, fake_iso_server, iso_data, cache):
        data = iso_data(100_000)
        _, base = fake_iso_server({"/small.iso": data})
        r = make_remote(base + "/small.iso", cache)

        out = r.read(99_990, 1000)
        assert out == data[99_990:]
        assert len(out) == 10

    def test_last_partial_chunk(self, fake_iso_server, iso_data, cache):
        data = iso_data(1024 * 1024 + 777)  # 1 MiB + partial
        _, base = fake_iso_server({"/odd.iso": data})
        r = make_remote(base + "/odd.iso", cache)

        out = r.read(1024 * 1024, 777)
        assert out == data[1024 * 1024 :]
        assert len(cache.read_chunk(r.file_key, 1)) == 777


class TestCachePersistence:
    def test_restart_with_existing_cache(self, fake_iso_server, iso_data, tmp_path):
        data = iso_data(2 * 1024 * 1024)
        _, base = fake_iso_server({"/game.iso": data})
        url = base + "/game.iso"
        root = str(tmp_path / "cache")

        cache1 = ChunkCache(root, chunk_size=1024 * 1024)
        r1 = RemoteFile(url, cache1)
        assert r1.probe()
        expected = r1.read(500_000, 100_000)

        # "restart": brand-new cache object over same directory
        cache2 = ChunkCache(root, chunk_size=1024 * 1024)
        key = cache2.key_for(url)
        cache2.scan(key)
        assert cache2.has_chunk(key, 0)

        r2 = RemoteFile(url, cache2)
        assert r2.probe()
        assert r2.read(500_000, 100_000) == expected


class TestConcurrency:
    def test_concurrent_reads(self, fake_iso_server, iso_data, cache):
        data = iso_data(4 * 1024 * 1024)
        _, base = fake_iso_server({"/game.iso": data})
        r = make_remote(base + "/game.iso", cache)

        results = {}
        errors = []

        def worker(i, offset):
            try:
                results[i] = r.read(offset, 50_000)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(i, i * 300_000))
            for i in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        for i in range(8):
            off = i * 300_000
            assert results[i] == data[off : off + 50_000]

    def test_two_clients_same_game_no_corruption(self, fake_iso_server, iso_data, tmp_path):
        """Two independent RemoteFile objects (like two SMB sessions) sharing
        one cache must never corrupt each other's chunks."""
        data = iso_data(3 * 1024 * 1024)
        _, base = fake_iso_server({"/shared.iso": data})
        url = base + "/shared.iso"

        cache_a = ChunkCache(str(tmp_path / "c"), chunk_size=1024 * 1024)
        ra = RemoteFile(url, cache_a)
        rb = RemoteFile(url, cache_a)
        ra.probe()
        rb.probe()

        out_a, out_b = {}, {}

        def run(r, store, seed):
            for k in range(5):
                off = (seed * 111_111 + k * 250_000) % (len(data) - 60_000)
                store[(seed, k)] = r.read(off, 60_000)

        ta = threading.Thread(target=run, args=(ra, out_a, 1))
        tb = threading.Thread(target=run, args=(rb, out_b, 2))
        ta.start(); tb.start(); ta.join(); tb.join()

        for (seed, k), blob in {**out_a, **out_b}.items():
            off = (seed * 111_111 + k * 250_000) % (len(data) - 60_000)
            assert blob == data[off : off + 60_000]


class TestRemoteErrors:
    def test_http_404(self, fake_iso_server, cache):
        srv, base = fake_iso_server({"/exists.iso": b"x" * 1000})
        r = RemoteFile(base + "/missing.iso", cache)
        assert not r.probe()
        assert "404" in r.error

    def test_no_range_support_rejected(self, fake_iso_server, iso_data, cache):
        data = iso_data(2 * 1024 * 1024)
        _, base = fake_iso_server({"/big.iso": data}, support_ranges=False)
        r = RemoteFile(base + "/big.iso", cache)
        with pytest.raises(NoRangeSupport):
            r.ensure_probed()


class TestMultipleGames:
    def test_multiple_games_different_urls(self, fake_iso_server, iso_data, cache):
        d1 = iso_data(1 * 1024 * 1024 + 11, seed=1)
        d2 = iso_data(2 * 1024 * 1024 + 22, seed=2)
        _, base = fake_iso_server({"/a.iso": d1, "/b.iso": d2})

        ra = make_remote(base + "/a.iso", cache)
        rb = make_remote(base + "/b.iso", cache)

        assert ra.file_key != rb.file_key
        assert ra.read(0, 1000) == d1[:1000]
        assert rb.read(0, 1000) == d2[:1000]
        assert ra.read(1_000_000, 100) == d1[1_000_000 : 1_000_100]
        assert rb.read(2_000_000, 100) == d2[2_000_000 : 2_000_100]

        # separate cache dirs per game
        assert cache.has_chunk(ra.file_key, 0)
        assert cache.has_chunk(rb.file_key, 0)
