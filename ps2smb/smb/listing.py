"""Directory-listing entry construction shared by SMB1 and SMB2 handlers.

Both dialects need the same thing: (filename, size) pairs for virtual games
matching a glob, turned into dialect-specific info records with correct
sizes, timestamps, and chained NextEntryOffset links.
"""

import fnmatch
import logging
import struct
import time

from impacket import smb, smb3structs as smb2

LOG = logging.getLogger("ps2smb.smb.listing")

# SMB2 QUERY_DIRECTORY info levels reuse the SMB1 find-item structures from
# impacket.smb; only the level constants differ.
_SMB2_ITEM_CLASSES = {
    smb2.SMB2_FILE_DIRECTORY_INFO: smb.SMBFindFileDirectoryInfo,
    smb2.SMB2_FULL_DIRECTORY_INFO: smb.SMBFindFileFullDirectoryInfo,
    smb2.SMB2_FILE_ID_FULL_DIRECTORY_INFO: smb.SMBFindFileIdFullDirectoryInfo,
    smb2.SMB2_FILE_BOTH_DIRECTORY_INFO: smb.SMBFindFileBothDirectoryInfo,
    smb2.SMB2_FILE_ID_BOTH_DIRECTORY_INFO: smb.SMBFindFileIdBothDirectoryInfo,
    smb2.SMB2_FILE_NAMES_INFO: smb.SMBFindFileNamesInfo,
}

_SMB1_INFO_CLASSES = {
    smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO: smb.SMBFindFileBothDirectoryInfo,
    smb.SMB_FIND_FILE_DIRECTORY_INFO: smb.SMBFindFileDirectoryInfo,
    smb.SMB_FIND_FILE_FULL_DIRECTORY_INFO: smb.SMBFindFileFullDirectoryInfo,
    smb.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO: smb.SMBFindFileIdFullDirectoryInfo,
    smb.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO: smb.SMBFindFileIdBothDirectoryInfo,
    smb.SMB_FIND_FILE_NAMES_INFO: smb.SMBFindFileNamesInfo,
}


def now_ft() -> int:
    """Current time as an SMB FILETIME."""
    return smb.POSIXtoFT(int(time.time()))


def virtual_entries(games: dict, size_for, pattern: str):
    """(filename, size) pairs for games matching a find-first glob.

    OPL's default ETH layout looks for games in ``\\CD\\`` and ``\\DVD\\``
    subfolders of the share. We keep all ISOs at the share root but answer those
    subfolder searches with the full game list so stock OPL finds the games
    without changing its path setting.

    Previously both ``\\CD\\*`` and ``\\DVD\\*`` were treated identically,
    each returning the full list of games. OPL issues separate directory
    listings for the two virtual folders, which caused duplicate entries to be
    displayed. To avoid this, we now only emulate one of the virtual folders –
    ``\\CD\\`` – and return an empty list for ``\\DVD\\`` searches. This
    preserves compatibility (most OPL configurations use the CD folder) while
    eliminating duplicate listings.
    """
    pattern = (pattern or "*").replace("/", "\\").lower()
    # A search inside CD returns every game; DVD searches return none to avoid
    # duplicate listings.
    if pattern.startswith("\\cd\\"):
        # Strip the leading virtual folder path, keep the actual glob.
        pattern = pattern.rsplit("\\", 1)[-1]
    elif pattern.startswith("\\dvd\\"):
        # Return no entries for DVD virtual folder to prevent duplicates.
        return []
    entries = []
    for fname_lower, game in games.items():
        if fnmatch.fnmatch(game.filename.lower(), pattern):
            entries.append((game.filename, size_for(fname_lower)))
    return entries


def smb1_find_item(level, pkt_flags, fname, size):
    """Build one SMB1 find info record, or None if the level is unsupported."""
    cls = _SMB1_INFO_CLASSES.get(level)
    if cls is None:
        return None
    now = now_ft()
    item = cls(flags=pkt_flags)
    item["FileName"] = fname.encode(
        "utf-16le" if pkt_flags & smb.SMB.FLAGS2_UNICODE else "ascii")
    try:
        item["CreationTime"] = now
        item["LastAccessTime"] = now
        item["LastWriteTime"] = now
        item["LastChangeTime"] = now
    except KeyError:
        pass
    if hasattr(item, "EndOfFile"):
        item["EndOfFile"] = size
        item["AllocationSize"] = size
        item["CreationTime"] = now
        item["LastAccessTime"] = now
        item["LastWriteTime"] = now
        item["LastChangeTime"] = now
    if hasattr(item, "EaSize"):
        item["EaSize"] = 0
    try:
        item["ShortName"] = "\x00" * 24
    except KeyError:
        pass
    return item


def smb2_item_class(info_class):
    """Class for an SMB2 find info level, or None if unsupported."""
    return _SMB2_ITEM_CLASSES.get(info_class)


def smb2_find_item(info_class, fname, size):
    """Build one SMB2 find info record, or None if the class is unsupported."""
    cls = _SMB2_ITEM_CLASSES.get(info_class)
    if cls is None:
        return None
    now = now_ft()
    item = cls()
    item["FileName"] = fname.encode("utf-16le")
    if hasattr(item, "EndOfFile"):
        item["EndOfFile"] = size
        item["AllocationSize"] = size
        item["CreationTime"] = now
        item["LastAccessTime"] = now
        item["LastWriteTime"] = now
        item["LastChangeTime"] = now
    if hasattr(item, "EaSize"):
        item["EaSize"] = 0
    if hasattr(item, "ShortName"):
        item["ShortName"] = "\x00" * 24
    return item


def chain_entries(blobs_with_pad) -> bytes:
    """Serialize find entries as a NextEntryOffset-linked list.

    Each entry's first 4 bytes point at the next entry from the start of this
    one; 0 marks the last. OPL walks this linked list — all-zero offsets make
    it loop forever.
    """
    blobs = list(blobs_with_pad)
    for j, (blob, pad_len) in enumerate(blobs):
        entry_len = len(blob) + pad_len
        next_off = 0 if j == len(blobs) - 1 else entry_len
        blob[0:4] = struct.pack("<I", next_off)
    return b"".join(bytes(b) + b"\x00" * p for b, p in blobs)


def collect_find_page(items, max_data_count, search_count):
    """Take as many entries as fit in one find response.

    Returns (blobs_with_pad, end_of_search, remaining_items, total_bytes).
    Entries beyond the page limits come back as `remaining_items` for the
    caller to store under a search ID for FIND_NEXT2. At least one entry is
    always emitted — a zero-entry reply with EndOfSearch=0 makes OPL re-issue
    FIND_NEXT2 forever; limits apply from the second entry onwards.
    """
    blobs = []
    total = 0
    count = 0
    for i, item in enumerate(items):
        blob = bytearray(item.getData())
        pad_len = (4 - (len(blob) % 4)) % 4
        if blobs and (total + len(blob) + pad_len > max_data_count
                      or count >= search_count):
            return blobs, 0, items[i:], total
        count += 1
        blobs.append((blob, pad_len))
        total += len(blob) + pad_len
    return blobs, 1, None, total
