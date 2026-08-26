"""SMB layer package: impacket-based server exposing remote ISOs over SMB.

Modules:
    compat   impacket compatibility shims (case-insensitive shares, wire log)
    virtual  VirtualFileHandle + open-file registration
    listing  shared SMB1/SMB2 directory-listing entry construction
    server   GameSMBServer with the SMB1/SMB2 command hooks
"""

from .server import GameSMBServer, MANIFEST_NAME

__all__ = ["GameSMBServer", "MANIFEST_NAME"]
