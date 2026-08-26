"""GameSMBServer: impacket-based SMB server exposing remote ISOs as normal
seekable files.

Approach (verified against impacket 0.13.1 smbserver.py):

* The share's `path` is a real, mostly-empty directory. A tiny `.ps2smb.json`
  manifest inside it maps exposed filenames -> catalog URLs so that *any*
  SMB client can also resolve names without our hooks.
* impacket's stock SMB2/SMB1 CREATE handler calls os.open() on real paths,
  which cannot work for multi-GB remote ISOs. We therefore HOOK:
      - SMB2_CREATE / SMB_COM_NT_CREATE_ANDX / SMB_COM_OPEN_ANDX
        -> for known virtual filenames we register an open with a
           VirtualFileHandle instead of a real fd.
      - SMB2_READ / SMB_COM_READ_ANDX / SMB_COM_READ
        -> if the opened handle is a VirtualFileHandle, serve bytes from
           RemoteFile.read(offset, length) (cache-backed), else fall back to
           the original handler.
      - QUERY_INFO / QUERY_PATH_INFO / FIND_FIRST2 / FIND_NEXT2
        -> supply correct sizes for virtual files (os.stat would fail).
* Everything else (negotiate, session setup, tree connect, close, flush...)
  uses stock impacket behavior, anonymous/guest access, read-only share.

OPL connects as guest; no authentication is required.
"""

import json
import logging
import os
import threading

from impacket import smb, smb3structs as smb2
from impacket.nt_errors import (
    STATUS_ACCESS_DENIED,
    STATUS_END_OF_FILE,
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_INFO_CLASS,
    STATUS_NO_SUCH_FILE,
    STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
)
from impacket.smbserver import SimpleSMBServer

from ..cache import ChunkCache
from ..catalog import Game
from ..remote import RemoteFile, RemoteFileError

from .compat import (
    STATUS_SMB_BAD_TID,
    install_command_logger,
    normalize_virtual_name,
    patch_search_share,
    register_share_alias,
    resolve_file_id,
    stock_smb1,
    stock_smb2,
    stock_trans2,
)
from .listing import (
    chain_entries,
    collect_find_page,
    now_ft,
    smb1_find_item,
    smb2_find_item,
    virtual_entries,
)
from .virtual import (
    VirtualFileHandle,
    is_virtual,
    register_open,
)

patch_search_share()

MANIFEST_NAME = ".ps2smb.json"

LOG = logging.getLogger("ps2smb.smb")


class GameSMBServer:
    def __init__(self, listen_address: str, port: int, share_name: str,
                 games, cache: ChunkCache, prefetch_count: int = 2):
        self.share_name = share_name.upper()
        self.games = {g.filename.lower(): g for g in games}
        self.cache = cache
        self.prefetch_count = prefetch_count

        # filename(lower) -> RemoteFile, created lazily on first access
        self._remotes = {}
        self._remotes_lock = threading.Lock()

        self._server = SimpleSMBServer(listenAddress=listen_address, listenPort=port)
        self.raw_server = self._server.getServer()

        # Share root: a real directory holding only the manifest.
        self.share_root = os.path.join(cache.root, "_share")
        os.makedirs(self.share_root, exist_ok=True)
        self._write_manifest()

        self._server.addShare(self.share_name, self.share_root,
                              shareComment="PS2 SMB HTTP games", readOnly="no")
        register_share_alias(self.raw_server, self.share_name)

        raw = self.raw_server
        install_command_logger(raw)
        raw.hookSmb2Command(smb2.SMB2_CREATE, self._smb2_create)
        raw.hookSmb2Command(smb2.SMB2_READ, self._smb2_read)
        raw.hookSmb2Command(smb2.SMB2_QUERY_INFO, self._smb2_query_info)
        raw.hookSmb2Command(smb2.SMB2_QUERY_DIRECTORY, self._smb2_query_directory)
        raw.hookSmbCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX, self._smb1_nt_create)
        raw.hookSmbCommand(smb.SMB.SMB_COM_READ_ANDX, self._smb1_read_andx)
        raw.hookSmbCommand(smb.SMB.SMB_COM_READ, self._smb1_read)
        raw.hookSmbCommand(smb.SMB.SMB_COM_FLUSH, self._smb1_flush)
        raw.hookSmbCommand(smb.SMB.SMB_COM_CLOSE, self._smb1_close)
        raw.hookTransaction2(smb.SMB.TRANS2_FIND_FIRST2, self._smb1_find_first2)
        raw.hookTransaction2(smb.SMB.TRANS2_FIND_NEXT2, self._smb1_find_next2)

        LOG.info("SMB server configured: %s:%d share \\\\%s\\%s (%d games)",
                 listen_address, port, listen_address or "0.0.0.0", self.share_name, len(self.games))

    # ------------------------------------------------------------------ util

    def _write_manifest(self):
        manifest = {
            g.filename: {"name": g.name, "url": g.url}
            for g in sorted(self.games.values(), key=lambda x: x.filename)
        }
        path = os.path.join(self.share_root, MANIFEST_NAME)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

    def _remote_for(self, filename_lower: str) -> RemoteFile:
        with self._remotes_lock:
            if filename_lower not in self._remotes:
                game = self.games[filename_lower]
                self._remotes[filename_lower] = RemoteFile(game.url, self.cache)
            return self._remotes[filename_lower]

    def _virtual_name(self, path: str):
        """If path refers to one of our virtual ISOs, return its lowercased name."""
        base = normalize_virtual_name(path)
        return base if base in self.games else None

    @staticmethod
    def _opened(connData, fid):
        return connData["OpenedFiles"].get(fid)

    @staticmethod
    def _virtual_handle(opened):
        fh = opened.get("FileHandle") if opened else None
        return fh if isinstance(fh, VirtualFileHandle) else None

    def _remote_size_or_zero(self, fname_lower):
        try:
            return self._remote_for(fname_lower).size or 0
        except Exception:
            return 0

    def _prefetch_after(self, vhandle, offset, length):
        """Sequential prefetch of following chunks in the background."""
        chunk = self.cache.chunk_size
        next_chunk = (offset + length + chunk - 1) // chunk
        for i in range(next_chunk, next_chunk + self.prefetch_count):
            if i * chunk < vhandle.remote.size:
                vhandle.remote.prefetch(i)

    # ------------------------------------------------------------- SMB2 create

    def _smb2_create(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)
        try:
            request = smb2.SMB2Create(recvPacket["Data"])
            name = request["Buffer"][: request["NameLength"]].decode("utf-16le", "replace")
            vname = self._virtual_name(name)
            if vname is None:
                # Not ours: let stock impacket handle it (manifest file, dirs...).
                smbServer.setConnectionData(connId, connData)
                return stock_smb2("smb2Create", connId, smbServer, recvPacket)

            LOG.info("SMB open  %s (client %s)", vname, connData.get("ClientIP", "?"))
            game = self.games[vname]
            remote = self._remote_for(vname)
            try:
                remote.ensure_probed()
            except RemoteFileError as e:
                LOG.error("cannot serve %s: %s", vname, e)
                smbServer.setConnectionData(connId, connData)
                return [smb2.SMB2Error()], None, STATUS_ACCESS_DENIED

            fakefid = _uuid_generate()
            path_name = os.path.join(self.share_root, game.filename)
            register_open(connData, fakefid, VirtualFileHandle(game, remote), path_name)

            resp = smb2.SMB2Create_Response()
            resp["Buffer"] = b"\x00"
            resp["FileID"] = fakefid
            resp["CreateAction"] = 1  # FILE_OPENED
            resp["CreationTime"] = 0
            resp["LastAccessTime"] = 0
            resp["LastWriteTime"] = 0
            resp["ChangeTime"] = 0
            resp["AllocationSize"] = remote.size
            resp["EndOfFile"] = remote.size
            resp["FileAttributes"] = smb.SMB_FILE_ATTRIBUTE_NORMAL
            smbServer.setConnectionData(connId, connData)
            return [resp], None, STATUS_SUCCESS
        finally:
            pass

    # --------------------------------------------------------------- SMB2 read

    def _smb2_read(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)
        readRequest = smb2.SMB2Read(recvPacket["Data"])
        fileID = resolve_file_id(readRequest["FileID"], connData)

        vhandle = None
        if recvPacket["TreeID"] in connData["ConnectedShares"]:
            opened = self._opened(connData, fileID)
            vhandle = self._virtual_handle(opened)

        if vhandle is None:
            smbServer.setConnectionData(connId, connData)
            return stock_smb2("smb2Read", connId, smbServer, recvPacket)

        offset = readRequest["Offset"]
        length = readRequest["Length"]
        LOG.debug("SMB read  %s offset=%d length=%d", vhandle.game.filename, offset, length)
        try:
            content = vhandle.remote.read(offset, length)
        except RemoteFileError as e:
            LOG.error("read failed %s@%d: %s", vhandle.game.filename, offset, e)
            smbServer.setConnectionData(connId, connData)
            # Match stock smbComReadAndX: empty parameters/data on error.
            return [smb.SMBCommand(smb.SMB.SMB_COM_READ_ANDX)], None, STATUS_ACCESS_DENIED

        self._prefetch_after(vhandle, offset, length)

        resp = smb2.SMB2Read_Response()
        resp["Buffer"] = b"\x00"
        resp["DataOffset"] = 0x50
        resp["DataLength"] = len(content)
        resp["DataRemaining"] = 0
        resp["Buffer"] = content
        errorCode = STATUS_END_OF_FILE if len(content) == 0 else STATUS_SUCCESS
        smbServer.setConnectionData(connId, connData)
        return [resp], None, errorCode

    # ---------------------------------------------------------- SMB2 query info

    def _smb2_query_info(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)
        queryInfo = smb2.SMB2QueryInfo(recvPacket["Data"])
        fileID = resolve_file_id(queryInfo["FileID"], connData)

        opened = self._opened(connData, fileID) if fileID != b"\xff" * 16 else None
        vhandle = self._virtual_handle(opened)
        if vhandle is None:
            smbServer.setConnectionData(connId, connData)
            return stock_smb2("smb2QueryInfo", connId, smbServer, recvPacket)

        size = vhandle.remote.size
        fileName = opened["FileName"]

        if queryInfo["InfoType"] == smb2.SMB2_0_INFO_FILE:
            infoRecord = self._file_info_record(queryInfo["FileInfoClass"], size, fileName)
            if infoRecord is None:
                smbServer.setConnectionData(connId, connData)
                return [smb2.SMB2Error()], None, STATUS_INVALID_HANDLE
            resp = smb2.SMB2QueryInfo_Response()
            resp["Buffer"] = b"\x00"
            resp["OutputBufferOffset"] = 0x48
            resp["OutputBufferLength"] = len(infoRecord.getData())
            resp["Buffer"] = infoRecord.getData()
            smbServer.setConnectionData(connId, connData)
            return [resp], None, STATUS_SUCCESS

        smbServer.setConnectionData(connId, connData)
        return stock_smb2("smb2QueryInfo", connId, smbServer, recvPacket)

    @staticmethod
    def _file_info_record(info_class, size, file_name):
        now = now_ft()
        if info_class == smb2.SMB2_FILE_BASIC_INFO:
            r = smb2.FILE_BASIC_INFORMATION()
            r["CreationTime"] = now
            r["LastAccessTime"] = now
            r["LastWriteTime"] = now
            r["ChangeTime"] = now
            r["FileAttributes"] = smb.SMB_FILE_ATTRIBUTE_NORMAL
            return r
        if info_class == smb2.SMB2_FILE_STANDARD_INFO:
            r = smb2.FILE_STANDARD_INFORMATION()
            r["AllocationSize"] = size
            r["EndOfFile"] = size
            r["NumberOfLinks"] = 1
            r["DeletePending"] = 0
            r["Directory"] = 0
            return r
        if info_class == smb2.SMB2_FILE_ALL_INFO:
            r = smb2.FILE_ALL_INFORMATION()
            r["BasicInformation"] = smb2.FILE_BASIC_INFORMATION()
            r["StandardInformation"] = smb2.FILE_STANDARD_INFORMATION()
            r["InternalInformation"] = smb2.FILE_INTERNAL_INFORMATION()
            r["EaInformation"] = smb2.FILE_EA_INFORMATION()
            r["AccessInformation"] = smb2.FILE_ACCESS_INFORMATION()
            r["PositionInformation"] = smb2.FILE_POSITION_INFORMATION()
            r["ModeInformation"] = smb2.FILE_MODE_INFORMATION()
            r["AlignmentInformation"] = smb2.FILE_ALIGNMENT_INFORMATION()
            r["NameInformation"] = smb2.FILE_NAME_INFORMATION()
            for f in ("CreationTime", "LastAccessTime", "LastWriteTime", "ChangeTime"):
                r["BasicInformation"][f] = now
            r["BasicInformation"]["FileAttributes"] = smb.SMB_FILE_ATTRIBUTE_NORMAL
            r["StandardInformation"]["AllocationSize"] = size
            r["StandardInformation"]["EndOfFile"] = size
            r["StandardInformation"]["NumberOfLinks"] = 1
            r["StandardInformation"]["DeletePending"] = 0
            r["StandardInformation"]["Directory"] = 0
            r["InternalInformation"]["IndexNumber"] = 0
            r["AccessInformation"]["AccessFlags"] = 0
            r["PositionInformation"]["CurrentByteOffset"] = 0
            r["ModeInformation"]["mode"] = 0
            r["AlignmentInformation"]["AlignmentRequirement"] = 0
            r["NameInformation"]["FileName"] = file_name.encode("utf-16le")
            r["NameInformation"]["FileNameLength"] = len(file_name.encode("utf-16le"))
            return r
        if info_class == smb2.SMB2_FILE_NETWORK_OPEN_INFO:
            r = smb.SMBFileNetworkOpenInfo()
            r["CreationTime"] = now
            r["LastAccessTime"] = now
            r["LastWriteTime"] = now
            r["ChangeTime"] = now
            r["AllocationSize"] = size
            r["EndOfFile"] = size
            r["FileAttributes"] = smb.SMB_FILE_ATTRIBUTE_NORMAL
            return r
        if info_class == smb2.SMB2_FILE_EA_INFO:
            return smb.SMBQueryFileEaInfo()
        return None

    # ------------------------------------------------------ SMB2 query directory

    def _smb2_query_directory(self, connId, smbServer, recvPacket):
        """Serve directory listings ourselves so virtual ISOs appear with
        correct sizes without existing on disk."""
        connData = smbServer.getConnectionData(connId)
        qd = smb2.SMB2QueryDirectory(recvPacket["Data"])
        fileID = resolve_file_id(qd["FileID"], connData)

        opened = self._opened(connData, fileID)
        if opened is None or not opened.get("FileName", "").rstrip("\\/") \
                .lower().endswith(self.share_root.lower()):
            smbServer.setConnectionData(connId, connData)
            return stock_smb2("smb2QueryDirectory", connId, smbServer, recvPacket)

        pattern = "*"
        if qd["FileNameLength"] > 0:
            pattern = qd["Buffer"].decode("utf-16le") or "*"

        entries = virtual_entries(self.games, self._remote_size_or_zero, pattern)
        total = 0
        buf = b""
        start = max(0, connData["OpenedFiles"][fileID]["Open"]["EnumerationLocation"])
        for idx in range(start, len(entries)):
            fname, size = entries[idx]
            item = smb2_find_item(qd["FileInformationClass"], fname, size)
            if item is None:
                smbServer.setConnectionData(connId, connData)
                return [smb2.SMB2Error()], None, STATUS_INVALID_INFO_CLASS
            data = item.getData()
            pad = (8 - (len(data) % 8)) % 8
            if total + len(data) >= qd["OutputBufferLength"] and total > 0:
                break
            item["NextEntryOffset"] = len(data) + pad
            data = item.getData()
            buf += data + b"\x00" * pad
            total += len(data) + pad
            connData["OpenedFiles"][fileID]["Open"]["EnumerationLocation"] += 1

        if connData["OpenedFiles"][fileID]["Open"]["EnumerationLocation"] >= len(entries):
            connData["OpenedFiles"][fileID]["Open"]["EnumerationLocation"] = -1

        resp = smb2.SMB2QueryDirectory_Response()
        resp["Buffer"] = b"\x00"
        resp["OutputBufferOffset"] = 0x48
        resp["OutputBufferLength"] = total
        resp["Buffer"] = buf
        smbServer.setConnectionData(connId, connData)
        return [resp], None, STATUS_SUCCESS

    # ------------------------------------------------- SMB1 TRANS2 find hooks

    def _smb1_find_first2(self, connId, smbServer, recvPacket, parameters,
                          data, maxDataCount):
        connData = smbServer.getConnectionData(connId)
        req = smb.SMBFindFirst2_Parameters(recvPacket["Flags2"], data=parameters)

        # Only take over when the search targets our share root; otherwise the
        # stock handler must run.
        path = connData["ConnectedShares"].get(recvPacket["Tid"], {}).get("path", "")
        name = req["FileName"]
        if isinstance(name, bytes):
            name = name.decode(
                "utf-16le" if recvPacket["Flags2"] & smb.SMB.FLAGS2_UNICODE else "latin-1")
        if os.path.abspath(path) != os.path.abspath(self.share_root):
            LOG.info("SMB1 find-first %r in %s -> stock", name, path)
            smbServer.setConnectionData(connId, connData)
            return stock_trans2("findFirst2", connId, smbServer, recvPacket,
                                parameters, data, maxDataCount)

        LOG.info("SMB1 find-first %r (share root)", name)
        items = []
        for fname, size in virtual_entries(self.games, self._remote_size_or_zero,
                                           name.rstrip("\x00")):
            item = smb1_find_item(req["InformationLevel"], recvPacket["Flags2"],
                                  fname, size)
            if item is None:
                smbServer.setConnectionData(connId, connData)
                return b"", b"", b"", STATUS_NOT_SUPPORTED
            items.append(item)

        if not items:
            smbServer.setConnectionData(connId, connData)
            return b"", b"", b"", STATUS_NO_SUCH_FILE

        blobs, endOfSearch, remaining, totalData = collect_find_page(
            items, maxDataCount, req["SearchCount"])

        sid = 0x80
        respParameters = smb.SMBFindFirst2Response_Parameters()
        if endOfSearch == 0:
            sid = (max(connData["SIDs"]) + 1) if connData["SIDs"] else 1
            connData["SIDs"][sid] = remaining
            respParameters["LastNameOffset"] = totalData
        respParameters["SID"] = sid
        respParameters["EndOfSearch"] = endOfSearch
        respParameters["SearchCount"] = len(blobs)
        respData = chain_entries(blobs)
        smbServer.setConnectionData(connId, connData)
        return b"", respParameters, respData, STATUS_SUCCESS

    def _smb1_find_next2(self, connId, smbServer, recvPacket, parameters,
                         data, maxDataCount):
        connData = smbServer.getConnectionData(connId)
        req = smb.SMBFindNext2_Parameters(flags=recvPacket["Flags2"], data=parameters)
        sid = req["SID"]
        if sid not in connData["SIDs"]:
            smbServer.setConnectionData(connId, connData)
            return b"", b"", b"", STATUS_INVALID_HANDLE

        searchResult = connData["SIDs"][sid]
        blobs, endOfSearch, remaining, totalData = collect_find_page(
            searchResult, maxDataCount, req["SearchCount"])

        respData = chain_entries(blobs)

        respParameters = smb.SMBFindNext2Response_Parameters()
        if endOfSearch > 0:
            del connData["SIDs"][sid]
        else:
            connData["SIDs"][sid] = remaining
            respParameters["LastNameOffset"] = totalData
        respParameters["EndOfSearch"] = endOfSearch
        respParameters["SearchCount"] = len(blobs)
        LOG.debug("SMB1 find-next sid=%d returned=%d eos=%d pending=%d",
                  sid, len(blobs), endOfSearch,
                  len(connData["SIDs"].get(sid, [])) if endOfSearch == 0 else 0)
        smbServer.setConnectionData(connId, connData)
        return b"", respParameters, respData, STATUS_SUCCESS

    # ------------------------------------------------------------ SMB1 handlers

    def _smb1_nt_create(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)
        ntCreateAndXData = smb.SMBNtCreateAndX_Data(
            flags=recvPacket["Flags2"], data=SMBCommand["Data"])
        name = ntCreateAndXData["FileName"]
        if isinstance(name, (bytes, bytearray)):
            if recvPacket["Flags2"] & smb.SMB.FLAGS2_UNICODE:
                name = name.decode("utf-16le", "replace")
            else:
                name = name.decode("latin-1", "replace")
        vname = self._virtual_name(name)
        if vname is None:
            smbServer.setConnectionData(connId, connData)
            return stock_smb1("smbComNtCreateAndX", connId, smbServer,
                              SMBCommand, recvPacket)

        LOG.info("SMB1 open %s", vname)
        game = self.games[vname]
        remote = self._remote_for(vname)
        try:
            remote.ensure_probed()
        except RemoteFileError as e:
            LOG.error("cannot serve %s: %s", vname, e)
            smbServer.setConnectionData(connId, connData)
            return [smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)], None, STATUS_ACCESS_DENIED

        fid = 1 if not connData["OpenedFiles"] else list(connData["OpenedFiles"].keys())[-1] + 1
        path_name = os.path.join(self.share_root, game.filename)
        register_open(connData, fid, VirtualFileHandle(game, remote), path_name)

        respParameters = smb.SMBNtCreateAndXResponse_Parameters()
        respParameters["Fid"] = fid
        respParameters["CreateAction"] = 1
        respParameters["CreateTime"] = 0
        respParameters["LastAccessTime"] = 0
        respParameters["LastWriteTime"] = 0
        respParameters["LastChangeTime"] = 0
        respParameters["AllocationSize"] = remote.size
        respParameters["EndOfFile"] = remote.size
        respParameters["FileAttributes"] = smb.SMB_FILE_ATTRIBUTE_NORMAL
        respParameters["FileType"] = 0
        respParameters["DeviceState"] = 0
        respParameters["Action"] = 0
        respParameters["IsDirectory"] = 0

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
        respSMBCommand["Parameters"] = respParameters
        respSMBCommand["Data"] = b""
        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, STATUS_SUCCESS

    def _smb1_read_andx(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)
        if SMBCommand["WordCount"] == 0x0A:
            readAndX = smb.SMBReadAndX_Parameters2(SMBCommand["Parameters"])
        else:
            readAndX = smb.SMBReadAndX_Parameters(SMBCommand["Parameters"])

        opened = self._opened(connData, readAndX["Fid"])
        vhandle = self._virtual_handle(opened)
        if vhandle is None:
            smbServer.setConnectionData(connId, connData)
            return stock_smb1("smbComReadAndX", connId, smbServer,
                              SMBCommand, recvPacket)

        offset = readAndX["Offset"]
        if "HighOffset" in readAndX.fields:
            offset += readAndX["HighOffset"] << 32
        length = readAndX["MaxCount"]
        LOG.debug("SMB1 read %s offset=%d length=%d", vhandle.game.filename, offset, length)
        try:
            content = vhandle.remote.read(offset, length)
        except RemoteFileError as e:
            LOG.error("read failed %s@%d: %s", vhandle.game.filename, offset, e)
            smbServer.setConnectionData(connId, connData)
            # Match stock smbComReadAndX: empty parameters/data on error.
            return [smb.SMBCommand(smb.SMB.SMB_COM_READ_ANDX)], None, STATUS_ACCESS_DENIED

        self._prefetch_after(vhandle, offset, length)

        respParameters = smb.SMBReadAndXResponse_Parameters()
        respParameters["Remaining"] = 0xFFFF
        respParameters["DataCount"] = len(content)
        respParameters["DataOffset"] = 59
        respParameters["DataCount_Hi"] = 0
        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_READ_ANDX)
        respSMBCommand["Parameters"] = respParameters
        respSMBCommand["Data"] = content
        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, STATUS_SUCCESS

    def _smb1_read(self, connId, smbServer, SMBCommand, recvPacket):
        """SMB_COM_READ (legacy, non-AndX). Stock handler calls os.lseek/os.read
        on FileHandle, which raises TypeError on a VirtualFileHandle and makes
        the read fail with ACCESS_DENIED -> OPL stalls. Serve virtual handles
        ourselves, delegate everything else to stock."""
        connData = smbServer.getConnectionData(connId)
        readParams = smb.SMBRead_Parameters(SMBCommand["Parameters"])

        opened = self._opened(connData, readParams["Fid"])
        vhandle = self._virtual_handle(opened)
        if vhandle is None:
            smbServer.setConnectionData(connId, connData)
            return stock_smb1("smbComRead", connId, smbServer,
                              SMBCommand, recvPacket)

        offset = readParams["Offset"]
        length = readParams["Count"]
        LOG.debug("SMB1 read(legacy) %s offset=%d length=%d",
                  vhandle.game.filename, offset, length)
        try:
            content = vhandle.remote.read(offset, length)
        except RemoteFileError as e:
            LOG.error("read failed %s@%d: %s", vhandle.game.filename, offset, e)
            smbServer.setConnectionData(connId, connData)
            return [smb.SMBCommand(smb.SMB.SMB_COM_READ)], None, STATUS_ACCESS_DENIED

        respParameters = smb.SMBReadResponse_Parameters()
        respParameters["DataLength"] = len(content)
        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_READ)
        respSMBCommand["Parameters"] = respParameters
        respSMBCommand["Data"] = content
        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, STATUS_SUCCESS

    def _smb1_flush(self, connId, smbServer, SMBCommand, recvPacket):
        """SMB_COM_FLUSH: stock calls os.fsync(FileHandle) which fails on a
        VirtualFileHandle (read-only share anyway). Return success for virtual
        handles, delegate real files to stock."""
        connData = smbServer.getConnectionData(connId)
        comFlush = smb.SMBFlush_Parameters(SMBCommand["Parameters"])

        if recvPacket["Tid"] not in connData["ConnectedShares"]:
            smbServer.setConnectionData(connId, connData)
            return [smb.SMBCommand(smb.SMB.SMB_COM_FLUSH)], None, STATUS_SMB_BAD_TID

        opened = connData["OpenedFiles"].get(comFlush["FID"])
        if opened is None:
            smbServer.setConnectionData(connId, connData)
            return [smb.SMBCommand(smb.SMB.SMB_COM_FLUSH)], None, STATUS_INVALID_HANDLE

        if not is_virtual(opened):
            smbServer.setConnectionData(connId, connData)
            return stock_smb1("smbComFlush", connId, smbServer,
                              SMBCommand, recvPacket)

        LOG.debug("SMB1 flush %s", opened["FileName"])
        smbServer.setConnectionData(connId, connData)
        return [smb.SMBCommand(smb.SMB.SMB_COM_FLUSH)], None, STATUS_SUCCESS

    def _smb1_close(self, connId, smbServer, SMBCommand, recvPacket):
        """Close handler: virtual handles hold a VirtualFileHandle object in
        'FileHandle' where stock impacket expects an OS fd (os.close fails
        with "'VirtualFileHandle' object cannot be interpreted as an
        integer"). Mirror the stock smbComClose but skip os.close for
        virtual entries."""
        connData = smbServer.getConnectionData(connId)
        comClose = smb.SMBClose_Parameters(SMBCommand["Parameters"])
        fid = comClose["FID"]

        if recvPacket["Tid"] not in connData["ConnectedShares"]:
            smbServer.setConnectionData(connId, connData)
            return [smb.SMBCommand(smb.SMB.SMB_COM_CLOSE)], None, STATUS_SMB_BAD_TID

        opened = connData["OpenedFiles"].get(fid)
        if opened is None:
            smbServer.setConnectionData(connId, connData)
            return [smb.SMBCommand(smb.SMB.SMB_COM_CLOSE)], None, STATUS_INVALID_HANDLE

        errorCode = STATUS_SUCCESS
        fh = opened.get("FileHandle")
        if isinstance(fh, VirtualFileHandle):
            LOG.debug("SMB1 close %s", fh.game.filename)
        else:
            # Real file on disk (manifest etc.): let stock impacket do it.
            smbServer.setConnectionData(connId, connData)
            return stock_smb1("smbComClose", connId, smbServer,
                              SMBCommand, recvPacket)

        del connData["OpenedFiles"][fid]
        smbServer.setConnectionData(connId, connData)
        return [smb.SMBCommand(smb.SMB.SMB_COM_CLOSE)], None, errorCode

    # ------------------------------------------------------------------- admin

    def status(self):
        out = []
        for fname_lower, game in sorted(self.games.items()):
            remote = self._remotes.get(fname_lower)
            cached = self.cache.cached_chunks(remote.file_key) if remote else set()
            out.append({
                "name": game.name,
                "filename": game.filename,
                "url": game.url,
                "size": remote.size if remote else None,
                "probed": bool(remote and remote.probed),
                "range_ok": bool(remote and remote.accept_ranges),
                "cached_chunks": len(cached),
                "cached_bytes": self.cache.cached_bytes(remote.file_key) if remote else 0,
                "error": remote.error if remote else None,
            })
        return out

    # -------------------------------------------------------------------- run

    def start(self):
        self._server.start()

    def stop(self):
        self._server.stop()


def _uuid_generate():
    import uuid
    return uuid.generate()


# impacket's SMB2 create response requires FileID to be a 16-byte value;
# uuid.generate() returns exactly that.
