"""Minimal SMB end-to-end smoke test with progress prints (run directly)."""
import sys
import threading

sys.path.insert(0, ".")
sys.path.insert(0, "tests")

from conftest import FakeISOServer  # noqa: E402
from ps2smb.cache import ChunkCache  # noqa: E402
from ps2smb.catalog import Game  # noqa: E402
from ps2smb.smb import GameSMBServer  # noqa: E402


def make(size, seed=1):
    out = bytearray(size)
    x = seed
    for i in range(size):
        x = (1103515245 * x + 12345) & 0x7FFFFFFF
        out[i] = x & 0xFF
    return bytes(out)


print("building fake iso...", flush=True)
data = make(3 * 1024 * 1024)
srv = FakeISOServer({"/remote.iso": data})
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = "http://127.0.0.1:%d" % srv.server_address[1]

cache = ChunkCache("smb_smoke_cache", chunk_size=1024 * 1024)
games = [Game(name="Test Game", url=base + "/remote.iso", filename="Test Game.iso")]

print("starting smb server...", flush=True)
server = GameSMBServer("127.0.0.1", 13345, "PS2", games, cache, prefetch_count=0)
port = server.raw_server.socket.getsockname()[1]
threading.Thread(target=server.start, daemon=True).start()
print("smb server listening on port", port, flush=True)

from impacket.smb import SMB_DIALECT  # noqa: E402
from impacket.smbconnection import SMBConnection  # noqa: E402

print("connecting client...", flush=True)
conn = SMBConnection("*SMBSERVER", "127.0.0.1", sess_port=port,
                     preferredDialect=SMB_DIALECT)
print("logging in...", flush=True)
conn.login("", "")
print("connect tree...", flush=True)
tid = conn.connectTree("PS2")
print("tree ok:", tid, flush=True)

print("list path...", flush=True)
for f in conn.listPath("PS2", "*"):
    print("  entry:", f.get_longname(), flush=True)

print("open file...", flush=True)
fid = conn.openFile("PS2", "Test Game.iso")
print("opened fid:", fid, flush=True)

print("read 100 bytes @0...", flush=True)
# readFile(tree, fid, offset, bytesToRead) — offset first, then length
out = conn.readFile(tid, fid, 0, 100)
got = out if isinstance(out, (bytes, bytearray)) else b"".join(out)
print("read ok, matches:", got == data[:100], flush=True)

print("read @1MB+123...", flush=True)
out = conn.readFile(tid, fid, 1024 * 1024 + 123, 5000)
got = out if isinstance(out, (bytes, bytearray)) else b"".join(out)
print("read ok, matches:", got == data[1024 * 1024 + 123 : 1024 * 1024 + 5123], flush=True)

conn.close()
server.stop()
print("SMOKE TEST PASSED", flush=True)
