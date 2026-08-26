"""Virtual file handles: in-memory stand-ins for real file descriptors.

A VirtualFileHandle is stored in impacket's OpenedFiles[fid]['FileHandle']
slot where stock handlers expect an OS fd. Handlers that receive one serve
bytes from the cache-backed RemoteFile instead of touching the filesystem.
"""

from ..catalog import Game
from ..remote import RemoteFile


class VirtualFileHandle:
    """Stands in for a real fd in connData['OpenedFiles'][fid]['FileHandle']."""

    def __init__(self, game: Game, remote: RemoteFile):
        self.game = game
        self.remote = remote


def is_virtual(opened) -> bool:
    """True if an OpenedFiles entry holds a virtual handle."""
    return isinstance(opened.get("FileHandle"), VirtualFileHandle) if opened else False


def register_open(conn_data, fid, vhandle, path_name: str) -> None:
    """Insert a virtual open-file entry shaped like impacket's own."""
    conn_data["OpenedFiles"][fid] = {
        "FileHandle": vhandle,
        "FileName": path_name,
        "DeleteOnClose": False,
        "Open": {
            "EnumerationLocation": 0,
            "EnumerationSearchPattern": "",
        },
        "Virtual": True,
    }
