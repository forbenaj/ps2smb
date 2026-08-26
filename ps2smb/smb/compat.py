"""Compatibility shims for impacket's SMB server.

Everything here exists to work around quirks of impacket 0.13.x that would
otherwise break virtual (non-on-disk) files or OPL as a client:

* case-insensitive share lookup (`searchShare`)
* a command-ID wire logger so unhooked/stalled commands are visible
* the STATUS_SMB_BAD_TID constant impacket keeps in smbserver, not nt_errors
"""

import logging

from impacket import smb3structs as smb2
from impacket.smbserver import SMBSERVER, normalize_path  # noqa: F401  (re-exported)

LOG = logging.getLogger("ps2smb.smb.compat")

# Defined in impacket.smbserver, not nt_errors
STATUS_SMB_BAD_TID = 0x00050002

_SMB1_CMD_NAMES = {
    0x00: "NEGOTIATE", 0x01: "SETUP_ANDX", 0x02: "TREE_DISCONNECT", 0x03: "TREE_CONNECT",
    0x04: "QUERY_INFORMATION", 0x05: "CHECK_DIRECTORY", 0x06: "WRITE", 0x07: "WRITE_RAW",
    0x08: "CLOSE", 0x09: "FLUSH", 0x0A: "READ", 0x0B: "READ_ANDX", 0x0C: "WRITE_ANDX",
    0x10: "TRANS", 0x20: "READ_RAW", 0x21: "WRITE_MPX", 0x22: "READ_MPX",
    0x24: "WRITE_CLOSE", 0x25: "TRANS2", 0x2B: "ECHO", 0x2D: "OPEN_ANDX",
    0x2E: "READ_ANDX2", 0x32: "TRANS2_2", 0x42: "NT_TRANSACT",
    0x72: "NEGOTIATE2", 0x73: "SESSION_SETUP_ANDX", 0x74: "LOGOFF_ANDX",
    0x75: "TREE_CONNECT_ANDX", 0xA2: "NT_CREATE_ANDX", 0xC0: "NO_OP",
}


def patch_search_share() -> None:
    """Make impacket's share lookup case-insensitive.

    Stock searchShare() does config.has_section(share) against the raw string
    the client sent. OPL requests shares in lowercase while addShare() stores
    them uppercase, so TreeConnect fails with "TreeConnectAndX not found".
    We monkeypatch it to retry with upper/lower variants before giving up.
    """
    import impacket.smbserver as smbserver
    original = smbserver.searchShare

    def searchShare(connId, share, smbServer):
        result = original(connId, share, smbServer)
        if result is None and share:
            config = smbServer.getServerConfig()
            for candidate in (share.upper(), share.lower()):
                if config.has_section(candidate):
                    return dict(config.items(candidate))
        return result

    smbserver.searchShare = searchShare


def install_command_logger(raw_server) -> None:
    """Log every incoming SMB1/SMB2 command ID, including commands we do not
    hook. Without this, a stall inside a stock impacket handler is completely
    invisible."""
    log = logging.getLogger("ps2smb.wire")
    orig_process = raw_server.processRequest

    def processRequest(connId, data):
        try:
            # data is the SMB message WITHOUT the 4-byte NetBIOS header
            # (handler passes p.get_trailer()): '\xffSMB' + cmd at [4].
            if data[0:4] == b"\xffSMB":
                cmd = data[4]
                log.debug("SMB1 cmd=0x%02x (%s)", cmd, _SMB1_CMD_NAMES.get(cmd, "?"))
            else:
                from impacket import smb2 as _smb2mod
                pkt = _smb2mod.SMB2Packet(data=data)
                log.debug("SMB2 cmd=0x%04x", pkt["Command"])
        except Exception:
            pass  # never break dispatch over logging
        return orig_process(connId, data)

    raw_server.processRequest = processRequest


def register_share_alias(raw_server, share_name: str) -> None:
    """Register a lowercase alias section for `share_name` in the server's
    config. impacket's searchShare() is case-sensitive; OPL requests the
    share in lowercase."""
    config = raw_server.getServerConfig()
    if not config.has_section(share_name.lower()):
        config.add_section(share_name.lower())
        for key, value in config.items(share_name):
            config.set(share_name.lower(), key, value)


def normalize_virtual_name(path: str) -> str:
    """Last path component of `path`, normalized for game-name lookup."""
    return normalize_path(path).replace("/", "\\").split("\\")[-1].lower()


def resolve_file_id(packet_field, conn_data) -> bytes:
    """Resolve an SMB2 FileID field against LastRequest, mirroring what stock
    impacket handlers do when a client sends the all-ones 'use previous
    create' FileID."""
    all_ones = b"\xff" * 16
    fid = packet_field.getData()
    if fid == all_ones:
        if "SMB2_CREATE" in conn_data["LastRequest"]:
            return conn_data["LastRequest"]["SMB2_CREATE"]["FileID"]
        return fid
    return fid


def stock_smb2(handler_name: str, connId, smbServer, recvPacket):
    """Delegate an SMB2 command to impacket's stock implementation."""
    from impacket.smbserver import SMB2Commands
    return getattr(SMB2Commands, handler_name)(connId, smbServer, recvPacket)


def stock_smb1(handler_name: str, connId, smbServer, SMBCommand, recvPacket):
    """Delegate an SMB1 command to impacket's stock implementation."""
    from impacket.smbserver import SMBCommands
    return getattr(SMBCommands, handler_name)(connId, smbServer, SMBCommand, recvPacket)


def stock_trans2(handler_name: str, connId, smbServer, recvPacket,
                 parameters, data, maxDataCount):
    """Delegate a TRANS2 subcommand to impacket's stock implementation."""
    from impacket.smbserver import TRANS2Commands
    return getattr(TRANS2Commands, handler_name)(connId, smbServer, recvPacket,
                                                 parameters, data, maxDataCount)
