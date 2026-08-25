"""PS2SMB - HTTP-backed PS2 SMB game server (proof of concept).

Layers:
    remote   : RemoteFile  - sparse random-access view of a remote ISO over HTTP Range
    cache    : ChunkCache  - persistent fixed-size chunk cache on local disk
    catalog  : Catalog     - JSON game list -> sanitized filenames -> URLs
    smb      : impacket-based SMB server exposing the virtual files
    admin    : tiny status HTTP interface
"""

__version__ = "0.1.0"
