#!/usr/bin/env python3
# Living Web Relay / Mesh Node (Python 3.10+)
# - Secure peer sessions (X25519 + Ed25519 + AES-GCM)
# - Direct peer hint (LW_PEER="host:port")
# - Async RPC with mailbox correlation
# - Local kernel (simple summarizer, swappable later)
# - Credits ledger (SQLite) + uptime rewards
# - HTTP dashboard (aiohttp) via lw_dashboard.py (listens on PORT from env)

import os, sys, asyncio, time, json, struct, socket, uuid, hashlib
from dataclasses import dataclass
from typing import Dict, Tuple, Any, List, Optional

# optional faster loop
try:
    import uvloop
    uvloop.install()
except Exception:
    pass

import msgpack
from nacl import signing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import aiosqlite

from lw_dashboard import start_dashboard

IDENTITY_DIR = os.path.expanduser("~/.livingweb")
IDENTITY_PATH = os.path.join(IDENTITY_DIR, "identity.json")
PEERS_DB = os.path.join(IDENTITY_DIR, "peers.msgpack")

DEFAULT_BIND = os.getenv("LW_BIND", "0.0.0.0")     # mesh listener bind
DEFAULT_TCP_PORT = int(os.getenv("LW_TCP_PORT", "42425"))

MCAST_GRP = "239.13.37.42"
MCAST_PORT = 42424
HELLO_MAGIC = b"LW1_HELLO"

def ensure_dirs():
    os.makedirs(IDENTITY_DIR, exist_ok=True)

def now_ms() -> int:
    return int(time.time() * 1000)

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ---------------- Identity ----------------
@dataclass
class Identity:
    node_id: str
    ed25519_pub: bytes
    ed25519_sec: bytes
    x25519_pub: bytes     # raw 32 bytes
    x25519_sec: bytes     # Raw private key bytes

    @staticmethod
    def load_or_create() -> "Identity":
        ensure_dirs()
        if os.path.exists(IDENTITY_PATH):
            with open(IDENTITY_PATH, "r") as f:
                d = json.load(f)
            return Identity(
                node_id=d["node_id"],
                ed25519_pub=bytes.fromhex(d["ed25519_pub"]),
                ed25519_sec=bytes.fromhex(d["ed25519_sec"]),
                x25519_pub=bytes.fromhex(d["x25519_pub"]),
                x25519_sec=bytes.fromhex(d["x25519_sec"]),
            )

        # create new keys
        ed_sign = signing.SigningKey.generate()
        ed_pub = ed_sign.verify_key

        x_priv = x25519.X25519PrivateKey.generate()
        x_pub = x_priv.public_key()

        x_priv_raw = x_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        x_pub_raw = x_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        node_id = "did:lw:" + sha256(bytes(ed_pub))[:16]
        ident = Identity(
            node_id=node_id,
            ed25519_pub=bytes(ed_pub),
            ed25519_sec=bytes(ed_sign),
            x25519_pub=x_pub_raw,
            x25519_sec=x_priv_raw,
        )
        with open(IDENTITY_PATH, "w") as f:
            json.dump({
                "node_id": node_id,
                "ed25519_pub": ident.ed25519_pub.hex(),
                "ed25519_sec": ident.ed25519_sec.hex(),
                "x25519_pub": ident.x25519_pub.hex(),
                "x25519_sec": ident.x25519_sec.hex(),
            }, f, indent=2)
        return ident

# ---------------- Persistence ----------------
@dataclass
class PeerInfo:
    node_id: str
    host: str
    port: int
    ed25519_pub: bytes
    x25519_pub: bytes
    last_seen_ms: int
    capabilities: List[str]

class PeerStore:
    def __init__(self, path: str):
        self.path = path
        self.peers: Dict[str, PeerInfo] = {}

    def load(self):
        if not os.path.exists(self.path):
            return
        with open(self.path, "rb") as f:
            data = msgpack.unpackb(f.read(), raw=False)
        for pid, rec in data.items():
            self.peers[pid] = PeerInfo(
                node_id=pid,
                host=rec["host"],
                port=rec["port"],
                ed25519_pub=bytes.fromhex(rec["ed25519_pub"]),
                x25519_pub=bytes.fromhex(rec["x25519_pub"]),
                last_seen_ms=rec.get("last_seen_ms", 0),
                capabilities=rec.get("capabilities", []),
            )

    def save(self):
        data = {}
        for pid, p in self.peers.items():
            data[pid] = {
                "host": p.host,
                "port": p.port,
                "ed25519_pub": p.ed25519_pub.hex(),
                "x25519_pub": p.x25519_pub.hex(),
                "last_seen_ms": p.last_seen_ms,
                "capabilities": p.capabilities,
            }
        with open(self.path, "wb") as f:
            f.write(msgpack.packb(data, use_bin_type=True))

    def upsert(self, p: PeerInfo):
        self.peers[p.node_id] = p
        self.save()

# ---------------- Session ----------------
class Session:
    def __init__(self, peer_id: str, writer: asyncio.StreamWriter, aead: AESGCM):
        self.peer_id = peer_id
        self.writer = writer
        self.aead = aead
        self.rx_nonce = 0
        self.tx_nonce = 0

    def _nonce(self, n: int) -> bytes:
        return n.to_bytes(12, "big")

    async def send(self, obj: Any):
        payload = msgpack.dumps(obj, use_bin_type=True)
        ct = self.aead.encrypt(self._nonce(self.tx_nonce), payload, None)
        self.tx_nonce += 1
        self.writer.write(struct.pack("!I", len(ct)) + ct)
        await self.writer.drain()

    async def recv(self, reader: asyncio.StreamReader) -> Any:
        hdr = await reader.readexactly(4)
        ln = struct.unpack("!I", hdr)[0]
        ct = await reader.readexactly(ln)
        pt = self.aead.decrypt(self._nonce(self.rx_nonce), ct, None)
        self.rx_nonce += 1
        return msgpack.loads(pt, raw=False)

# ---------------- Local Kernel (swappable) ----------------
class LocalKernel:
    def __init__(self):
        self.docs: List[str] = []
        # Seed with a little context
        self.index("Local energy sensors show evening peaks near 6pm; reduce HVAC by 10% from 5–8pm to save energy.")
        self.index("Traffic near Main St increases after events; stagger signals by 5% to improve flow.")

    def index(self, text: str):
        self.docs.append(text)

    def query(self, q: str) -> Dict[str, Any]:
        if not q.strip():
            return {"node_summary": "Ask me something specific.", "tokens": 5, "hits": 0}
        qwords = set(q.lower().split())
        scored = []
        for i, d in enumerate(self.docs):
            overlap = len(qwords.intersection(set(d.lower().split())))
            if overlap:
                scored.append((overlap, i, d))
        scored.sort(reverse=True)
        top = [d for _, _, d in scored[:3]]
        synthesis = " ".join(top)[:500] if top else "No local context."
        return {"node_summary": synthesis, "tokens": len(synthesis.split()), "hits": len(top)}

# ---------------- Node ----------------
class LivingWebNode:
    def __init__(self):
        self.ident = Identity.load_or_create()
        self.store = PeerStore(PEERS_DB); self.store.load()
        self.kernel = LocalKernel()
        self.capabilities = ["query.basic", "summarize.local", "credits.basic"]

        # mailbox for RPC correlation
        self.mailbox: Dict[str, asyncio.Future] = {}

        # networking
        self.host = DEFAULT_BIND if DEFAULT_BIND else self._get_local_ip()
        self.tcp_port = DEFAULT_TCP_PORT
        self.peer_hint = os.getenv("LW_PEER")  # "host:port"

        # sessions map
        self.sessions: Dict[str, Session] = {}

        # credits DB
        self.db_path = os.path.join(IDENTITY_DIR, "credits.sqlite")

    # ---- helpers
    def _get_local_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def _mk_key(self, typ: str, qid: str) -> str:
        return f"{typ}:{qid}"

    def _await_reply(self, typ: str, qid: str) -> asyncio.Future:
        key = self._mk_key(typ, qid)
        fut = self.mailbox.get(key)
        if fut is None or fut.done():
            fut = asyncio.get_event_loop().create_future()
            self.mailbox[key] = fut
        return fut

    def _fulfill(self, typ: str, qid: str, obj: Dict[str, Any]):
        key = self._mk_key(typ, qid)
        fut = self.mailbox.get(key)
        if fut and not fut.done():
            fut.set_result(obj)

    # ---- DB / credits
    async def _init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
            CREATE TABLE IF NOT EXISTS credits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER,
                node TEXT,
                event TEXT,
                amount REAL,
                meta TEXT
            )""")
            await db.commit()

    async def _credit(self, event: str, node: str, amount: float, meta: Optional[Dict[str, Any]] = None):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO credits (ts,node,event,amount,meta) VALUES (?,?,?,?,?)",
                (now_ms(), node, event, amount, json.dumps(meta or {})),
            )
            await db.commit()

    async def _credit_uptime_loop(self):
        while True:
            try:
                await self._credit("uptime", "local", 0.1, {"sessions": len(self.sessions)})
            except Exception:
                pass
            await asyncio.sleep(30)

    # ---- server
    async def run(self):
        # periodic tasks
        asyncio.create_task(self._init_db())
        asyncio.create_task(self._credit_uptime_loop())

        # optional direct connect (cloud / no multicast)
        if self.peer_hint:
            host, port = self.peer_hint.split(":")
            asyncio.create_task(self._connect_direct_hint(host, int(port)))

        # listen, auto-increment port if needed
        port = self.tcp_port
        while True:
            try:
                server = await asyncio.start_server(self._handle_incoming, self.host, port)
                self.tcp_port = port
                print(f"[node] {self.ident.node_id} @ {self.host}:{self.tcp_port}")
                async with server:
                    await server.serve_forever()
            except OSError as e:
                # address in use
                if getattr(e, "errno", None) in (98, 10048):
                    port += 1
                    if port > DEFAULT_TCP_PORT + 10:
                        raise
                    print(f"[node] port busy, trying {port}…")
                    await asyncio.sleep(0.2)
                else:
                    raise

    # ---- handshake
    async def _handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, initiator: bool) -> Tuple[Session, str, Dict[str, Any]]:
        me = {
            "node_id": self.ident.node_id,
            "ed25519_pub": self.ident.ed25519_pub,
            "x25519_pub": self.ident.x25519_pub,
            "nonce": os.urandom(16),
            "capabilities": self.capabilities,
        }

        async def send_blob(d: Dict[str, Any]):
            b = msgpack.dumps(d, use_bin_type=True)
            writer.write(struct.pack("!I", len(b)) + b)
            await writer.drain()

        async def read_blob() -> Dict[str, Any]:
            hdr = await reader.readexactly(4)
            ln = struct.unpack("!I", hdr)[0]
            body = await reader.readexactly(ln)
            return msgpack.loads(body, raw=False)

        if initiator:
            await send_blob(me)
            other = await read_blob()
        else:
            other = await read_blob()
            await send_blob(me)

        # derive shared key
        my_priv = x25519.X25519PrivateKey.from_private_bytes(self.ident.x25519_sec)
        their_pub = x25519.X25519PublicKey.from_public_bytes(bytes(other["x25519_pub"]))
        shared = my_priv.exchange(their_pub)

        # sign transcript with Ed25519
        transcript = b"".join([
            me["node_id"].encode(), other["node_id"].encode(),
            bytes(me["x25519_pub"]), bytes(other["x25519_pub"]),
            bytes(me["ed25519_pub"]), bytes(other["ed25519_pub"]),
            bytes(me["nonce"]), bytes(other["nonce"])
        ])

        signer = signing.SigningKey(self.ident.ed25519_sec)
        sig = signer.sign(transcript).signature

        # exchange signatures
        writer.write(struct.pack("!I", len(sig)) + sig); await writer.drain()
        hdr = await reader.readexactly(4); ln = struct.unpack("!I", hdr)[0]
        sig_other = await reader.readexactly(ln)

        # verify signature
        verify_key = signing.VerifyKey(bytes(other["ed25519_pub"]))
        verify_key.verify(transcript, sig_other)

        # derive AES-GCM key
        k = hashlib.sha256(shared + bytes(me["nonce"]) + bytes(other["nonce"])).digest()
        aead = AESGCM(k)
        peer_id = other["node_id"]
        sess = Session(peer_id, writer, aead)
        return sess, peer_id, other

    async def _handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            sess, peer_id, other = await self._handshake(reader, writer, initiator=False)
            self.sessions[peer_id] = sess
            self.store.upsert(PeerInfo(
                node_id=peer_id, host=writer.get_extra_info("peername")[0],
                port=0,  # unknown, may learn later
                ed25519_pub=bytes(other["ed25519_pub"]),
                x25519_pub=bytes(other["x25519_pub"]),
                last_seen_ms=now_ms(),
                capabilities=other.get("capabilities", []),
            ))
            asyncio.create_task(self._session_reader(peer_id, reader, sess))
            print(f"[link] accepted <- {peer_id}")
        except Exception:
            try: writer.close()
            except: pass

    async def _connect_direct_hint(self, host: str, port: int):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            sess, peer_id, other = await self._handshake(reader, writer, initiator=True)
            self.sessions[peer_id] = sess
            self.store.upsert(PeerInfo(
                node_id=peer_id, host=host, port=port,
                ed25519_pub=bytes(other["ed25519_pub"]),
                x25519_pub=bytes(other["x25519_pub"]),
                last_seen_ms=now_ms(),
                capabilities=other.get("capabilities", []),
            ))
            asyncio.create_task(self._session_reader(peer_id, reader, sess))
            print(f"[link] direct-connect -> {peer_id} {host}:{port}")
        except Exception as e:
            print(f"[link] direct-connect failed: {e}")

    async def _session_reader(self, peer_id: str, reader: asyncio.StreamReader, sess: Session):
        try:
            while True:
                obj = await sess.recv(reader)
                await self._handle_rpc(peer_id, sess, obj)
        except Exception:
            self.sessions.pop(peer_id, None)

    # ---- RPC
    async def _handle_rpc(self, peer_id: str, sess: Session, obj: Dict[str, Any]):
        t = obj.get("type")

        if t == "ping":
            await sess.send({"type": "pong", "ts": now_ms()})

        elif t == "query":
            q = obj["q"]
            res = self.kernel.query(q)
            await self._credit("answer", peer_id or "local", 1.0, {"tokens": res.get("tokens", 0)})
            await sess.send({"type": "query_result", "qid": obj["qid"], "result": res})

        elif t == "query_result":
            qid = obj.get("qid", "")
            self._fulfill("query_result", qid, obj)

        elif t == "capabilities_req":
            await sess.send({"type": "capabilities_res", "qid": obj["qid"], "capabilities": self.capabilities})

        elif t == "capabilities_res":
            qid = obj.get("qid", "")
            self._fulfill("capabilities_res", qid, obj)

        else:
            pass

    async def get_peer_capabilities(self, timeout: float = 2.5) -> Dict[str, List[str]]:
        qid = uuid.uuid4().hex
        req = {"type": "capabilities_req", "qid": qid}
        awaiting: List[Tuple[str, asyncio.Future]] = []
        for pid, s in list(self.sessions.items()):
            try:
                await s.send(req)
                awaiting.append((pid, self._await_reply("capabilities_res", qid)))
            except Exception:
                pass
        caps: Dict[str, List[str]] = {}
        end = time.time() + timeout
        while time.time() < end and awaiting:
            await asyncio.sleep(0.05)
            done_idx: List[int] = []
            for i, (pid, fut) in enumerate(awaiting):
                if fut.done():
                    obj = fut.result()
                    if obj and isinstance(obj.get("capabilities", []), list):
                        caps[pid] = obj["capabilities"]
                    done_idx.append(i)
            for i in reversed(done_idx):
                awaiting.pop(i)
        return caps

    async def query_mesh(self, question: str, timeout: float = 2.5) -> Dict[str, Any]:
        qid = uuid.uuid4().hex
        req = {"type": "query", "qid": qid, "q": question}

        awaiting: List[Tuple[str, asyncio.Future]] = []
        for pid, s in list(self.sessions.items()):
            try:
                await s.send(req)
                awaiting.append((pid, self._await_reply("query_result", qid)))
            except Exception:
                pass

        local = self.kernel.query(question)
        await self._credit("answer_local", "local", 0.5, {"tokens": local.get("tokens", 0)})

        results = [local]
        end = time.time() + timeout
        while time.time() < end and awaiting:
            await asyncio.sleep(0.05)
            done_idx: List[int] = []
            for i, (pid, fut) in enumerate(awaiting):
                if fut.done():
                    obj = fut.result()
                    if obj and "result" in obj:
                        results.append(obj["result"])
                    done_idx.append(i)
            for i in reversed(done_idx):
                awaiting.pop(i)

        texts = [r.get("node_summary", "") for r in results if r]
        merged = " ".join(texts)[:900] if texts else "No responses."
        return {"answers": results, "synthesis": merged, "responders": len(results)}

# ---------------- CLI REPL (local runs only) ----------------
async def repl(node: LivingWebNode):
    if not sys.stdin or not sys.stdin.isatty():
        return  # not interactive (Render/Replit web deploy)
    print("[cli] /whoami, /peers, /ask <q>, /caps, /balance, Ctrl+C to exit")
    while True:
        try:
            line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
            if not line:
                await asyncio.sleep(0.05)
                continue
            line = line.strip()
            if not line:
                continue
            if line == "/whoami":
                print(node.ident.node_id, node.host, node.tcp_port)
            elif line == "/peers":
                for pid, p in node.store.peers.items():
                    print(f"- {pid} {p.host}:{p.port} caps={p.capabilities}")
            elif line.startswith("/ask "):
                q = line[5:].strip()
                res = await node.query_mesh(q)
                print(json.dumps(res, indent=2))
            elif line == "/caps":
                caps = await node.get_peer_capabilities()
                print(json.dumps(caps, indent=2))
            elif line == "/balance":
                async with aiosqlite.connect(node.db_path) as db:
                    async with db.execute("SELECT COALESCE(SUM(amount),0) FROM credits") as cur:
                        row = await cur.fetchone()
                        print(f"credits: {row[0] if row else 0:.2f}")
            else:
                print("Unknown command.")
        except KeyboardInterrupt:
            break

# ---------------- main ----------------
async def main():
    node = LivingWebNode()
    loop = asyncio.get_event_loop()
    loop.create_task(node.run())

    # start dashboard on $PORT (Render sets PORT); fallback 8088 locally
    dash_host = os.getenv("LW_BIND", "0.0.0.0")
    dash_port = int(os.getenv("PORT", "8088"))
    loop.create_task(start_dashboard(node, host=dash_host, port=dash_port))

    await repl(node)  # no-op on headless deploys
    # keep running forever
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
