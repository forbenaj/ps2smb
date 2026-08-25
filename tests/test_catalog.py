"""Tests for catalog loading and filename sanitization."""

import json

import pytest

from ps2smb.catalog import load_catalog, sanitize


def write_catalog(tmp_path, entries):
    p = tmp_path / "games.json"
    p.write_text(json.dumps(entries), encoding="utf-8")
    return str(p)


class TestSanitize:
    def test_strips_illegal_characters(self):
        assert sanitize('AC/DC: Live? *Rock* <Pack>') == "AC DC Live Rock Pack"

    def test_deterministic(self):
        assert sanitize("Some Game: Edition") == sanitize("Some Game: Edition")

    def test_empty_becomes_unnamed(self):
        assert sanitize("???") == "unnamed"

    def test_length_truncated(self):
        s = sanitize("A" * 300)
        assert len(s) <= 80


class TestLoadCatalog:
    def test_basic(self, tmp_path):
        path = write_catalog(tmp_path, [
            {"name": "Game One", "download_url": "https://x/y1.iso"},
            {"name": "Game Two", "download_url": "https://x/y2.iso"},
        ])
        games = load_catalog(path)
        assert [g.filename for g in games] == ["Game One.iso", "Game Two.iso"]
        assert games[0].url == "https://x/y1.iso"

    def test_collision_gets_suffix(self, tmp_path):
        path = write_catalog(tmp_path, [
            {"name": "Same: Name", "download_url": "https://x/a.iso"},
            {"name": "Same Name", "download_url": "https://x/b.iso"},
        ])
        games = load_catalog(path)
        names = [g.filename for g in games]
        assert len(set(names)) == 2
        assert names[0] == "Same Name.iso"
        assert names[1] == "Same Name-1.iso"

    def test_invalid_url_skipped(self, tmp_path):
        path = write_catalog(tmp_path, [
            {"name": "Bad", "download_url": "ftp://not-http/x.iso"},
            {"name": "Good", "download_url": "http://ok/x.iso"},
        ])
        games = load_catalog(path)
        assert [g.name for g in games] == ["Good"]

    def test_duplicate_urls_skipped(self, tmp_path):
        path = write_catalog(tmp_path, [
            {"name": "First", "download_url": "https://x/same.iso"},
            {"name": "Second", "download_url": "https://x/same.iso"},
        ])
        games = load_catalog(path)
        assert [g.name for g in games] == ["First"]

    def test_real_catalog_shape(self):
        """The catalogs shipped in this repo must load cleanly."""
        import os
        for cat in ("catalogs/playstation-2-games-iso.json",
                    "catalogs/ps2-games-collection_202501.json"):
            if os.path.exists(cat):
                games = load_catalog(cat)
                assert len(games) > 0
                filenames = {g.filename.lower() for g in games}
                assert len(filenames) == len(games), "filename collision in %s" % cat
