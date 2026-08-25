"""Catalog loading: JSON name/download_url pairs -> sanitized virtual filenames.

The catalog stays the source of truth for display name -> URL. Filenames are
deterministic: sanitize(name) + optional -N suffix on collision.
"""

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Dict, List

LOG = logging.getLogger("ps2smb.catalog")

# OPL SMB mode historically works best with 8.3-safe ASCII names; keep names
# readable but strip characters that are illegal or problematic on Windows
# shares and truncate to a length OPL handles comfortably.
MAX_BASE_LEN = 80


@dataclass(frozen=True)
class Game:
    name: str          # display name from catalog
    url: str           # download_url from catalog
    filename: str      # sanitized, collision-free filename (with .iso)


def sanitize(name: str) -> str:
    """Convert an arbitrary game name into a filesystem-safe base name."""
    s = name.strip()
    # Replace common separators with spaces first for readability
    s = s.replace(":", " ").replace("/", " ").replace("\\", " ")
    # Remove characters illegal on Windows / awkward over SMB
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "", s)
    # Collapse whitespace and dots at edges
    s = re.sub(r"\s+", " ", s).strip().strip(".")
    if not s:
        s = "unnamed"
    if len(s) > MAX_BASE_LEN:
        s = s[:MAX_BASE_LEN].rstrip()
    return s


def load_catalog(path: str) -> List[Game]:
    """Load the JSON catalog and assign deterministic, unique filenames."""
    with open(path, "r", encoding="utf-8") as f:
        entries = json.load(f)

    games: List[Game] = []
    seen: Dict[str, int] = {}
    urls_seen: Dict[str, str] = {}

    for i, entry in enumerate(entries):
        name = entry.get("name")
        url = entry.get("download_url")
        if not name or not url:
            LOG.warning("catalog entry %d missing name/download_url: %r", i, entry)
            continue
        if not re.match(r"^https?://", url, re.IGNORECASE):
            LOG.error("invalid URL for game %r: %s", name, url)
            continue
        if url in urls_seen:
            LOG.warning("duplicate URL for %r (already used by %r); skipping", name, urls_seen[url])
            continue

        base = sanitize(name)
        n = seen.get(base, 0)
        seen[base] = n + 1
        filename = ("%s-%d.iso" % (base, n)) if n else ("%s.iso" % base)

        urls_seen[url] = name
        games.append(Game(name=name, url=url, filename=filename))

    LOG.info("loaded %d games from %s", len(games), path)
    return games


def filename_to_game(games: List[Game]) -> Dict[str, Game]:
    return {g.filename.lower(): g for g in games}
