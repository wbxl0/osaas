#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, time, json, socket, struct, hashlib, base64, asyncio, logging, ipaddress, platform, shutil, signal, ssl as _ssl, urllib.request, urllib.parse, re, textwrap, io

# ── Config ──────────────────────────────────────────────────────────────
UUID = os.environ.get('UUID', '23ab4e50-f8e7-47d5-9823-3bdc0d38a324')
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', 'nz.wbxl.dpdns.org:443')
NEZHA_PORT = os.environ.get('NEZHA_PORT', '')
NEZHA_KEY = os.environ.get('NEZHA_KEY', 'eQznXSiec5C101xYWVMZQiTrpVUnEAFc')
NEZHA_DOH = os.environ.get('NEZHA_DOH', 'https://8.8.8.8/dns-query')
DOMAIN = os.environ.get('DOMAIN', '')
SUB_PATH = os.environ.get('SUB_PATH', 'wbxl')
NAME = os.environ.get('NAME', '')
WSPATH = os.environ.get('WSPATH', UUID[:8])
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true'
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

VERSION = 'python-9.9.9'
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''
DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = ['speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me', 'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org']

_log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(level=_log_level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CUUID = UUID.replace('-', '')
TLS_PORTS = {'443', '8443', '2096', '2087', '2083', '2053'}
NEZHA_AGENT_VERSION = VERSION
TASK_TYPE_TERMINAL_GRPC = 8
TASK_TYPE_FM = 11

# ── Custom WebSocket Server (zero deps) ────────────────────────────────
_WS_GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

class WebSocket:
    __slots__ = ('reader', 'writer', '_buf', '_closed')
    def __init__(self, reader, writer):
        self.reader = reader; self.writer = writer; self._buf = b''; self._closed = False

    async def _read_frame(self):
        while len(self._buf) < 2:
            c = await self.reader.read(65536)
            if not c: return None
            self._buf += c
        b0, b1 = self._buf[0], self._buf[1]
        fin = bool(b0 & 0x80); opcode = b0 & 0x0f; masked = bool(b1 & 0x80)
        l = b1 & 0x7f; h = 2
        if l == 126:
            while len(self._buf) < 4:
                c = await self.reader.read(65536)
                if not c: return None
                self._buf += c
            l = struct.unpack('!H', self._buf[2:4])[0]; h = 4
        elif l == 127:
            while len(self._buf) < 10:
                c = await self.reader.read(65536)
                if not c: return None
                self._buf += c
            l = struct.unpack('!Q', self._buf[2:10])[0]; h = 10
        ml = 4 if masked else 0; tl = h + ml + l
        while len(self._buf) < tl:
            c = await self.reader.read(65536)
            if not c: return None
            self._buf += c
        payload = bytearray(self._buf[h+ml:h+ml+l])
        if masked:
            key = self._buf[h:h+4]
            for i in range(len(payload)): payload[i] ^= key[i % 4]
        self._buf = self._buf[tl:]
        return fin, opcode, bytes(payload)

    async def recv(self):
        payload = b''; started = False
        while True:
            r = await self._read_frame()
            if r is None: return None
            fin, op, data = r
            if op == 8: self._closed = True; return None
            if op == 9: await self._send_frame(data, 10); continue
            if op in (1, 2):
                payload = data; started = True
                if fin: return payload
            elif op == 0 and started:
                payload += data
                if fin: return payload

    async def _send_frame(self, data, opcode=2):
        p = bytes(data) if data else b''
        if len(p) < 126: h = bytes([0x80 | opcode, len(p)])
        elif len(p) < 65536: h = bytes([0x80 | opcode, 126]) + struct.pack('!H', len(p))
        else: h = bytes([0x80 | opcode, 127]) + struct.pack('!Q', len(p))
        self.writer.write(h + p); await self.writer.drain()

    async def send(self, data):
        await self._send_frame(data, 2)

    async def send_bytes(self, data):
        await self._send_frame(data, 2)

    async def close(self):
        if not self._closed:
            self._closed = True
            try: await self._send_frame(b'', 8); self.writer.close()
            except: pass

class WebSocketUpgrade:
    @staticmethod
    def accept_key(key):
        return base64.b64encode(hashlib.sha1(key.encode() + _WS_GUID).digest()).decode()

# ── HTTP Server (zero deps) ────────────────────────────────────────────
async def _parse_http(reader):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = await reader.read(4096)
        if not chunk: return None
        data += chunk
    head, _, body = data.partition(b'\r\n\r\n')
    lines = head.decode('utf-8', errors='replace').split('\r\n')
    if not lines: return None
    first = lines[0].split()
    if len(first) < 2: return None
    method, path = first[0], first[1]
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip().lower()] = v.strip()
    cl = int(headers.get('content-length', 0))
    while len(body) < cl:
        body += await asyncio.wait_for(reader.read(65536), timeout=30)
    return method, path, headers, body

async def _http_respond(writer, status, content_type, body=b'', extra_headers=None):
    resp = f'HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\nCache-Control: no-cache, no-store, must-revalidate\r\nConnection: keep-alive\r\n'
    if extra_headers:
        for k, v in extra_headers.items(): resp += f'{k}: {v}\r\n'
    resp += '\r\n'
    writer.write(resp.encode() + body); await writer.drain()

async def _http_respond_ws(writer, key):
    accept = WebSocketUpgrade.accept_key(key)
    resp = (f'HTTP/1.1 101 Switching Protocols\r\n'
            f'Upgrade: websocket\r\nConnection: Upgrade\r\n'
            f'Sec-WebSocket-Accept: {accept}\r\n\r\n')
    writer.write(resp.encode()); await writer.drain()

# ── Async HTTP Client (urllib wrapper) ─────────────────────────────────
async def http_get(url, timeout=10):
    return await asyncio.get_event_loop().run_in_executor(None, _sync_http_get, url, timeout)

def _sync_http_get(url, timeout):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()

async def http_post(url, data, timeout=10):
    return await asyncio.get_event_loop().run_in_executor(None, _sync_http_post, url, data, timeout)

def _sync_http_post(url, data, timeout):
    j = json.dumps(data).encode()
    req = urllib.request.Request(url, data=j, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()

async def http_get_json(url, headers=None, timeout=10):
    return await asyncio.get_event_loop().run_in_executor(None, _sync_http_get_json, url, headers, timeout)

def _sync_http_get_json(url, headers, timeout):
    h = {'User-Agent': 'Mozilla/5.0'}; h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())

# ── Helper functions ────────────────────────────────────────────────────
def is_blocked_domain(host):
    if not host: return False
    hl = host.lower()
    return any(hl == b or hl.endswith('.' + b) for b in BLOCKED_DOMAINS)

async def get_isp():
    global ISP
    try:
        d = await http_get_json('https://api.ip.sb/geoip', {'User-Agent': 'Mozilla/5.0'}, 3)
        ISP = f"{d.get('country_code', '')}-{d.get('isp', '')}".replace(' ', '_'); return
    except: pass
    try:
        d = await http_get_json('http://ip-api.com/json', {'User-Agent': 'Mozilla/5.0'}, 3)
        ISP = f"{d.get('countryCode', '')}-{d.get('org', '')}".replace(' ', '_'); return
    except: pass
    ISP = 'Unknown'

async def get_ip():
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            ip = (await http_get('https://api-ipv4.ip.sb/ip', 5)).strip()
            CurrentDomain = ip; Tls = 'none'; CurrentPort = PORT
        except Exception as e:
            logger.error(f'Failed to get IP: {e}')
            CurrentDomain = 'change-your-domain.com'; Tls = 'tls'; CurrentPort = 443
    else:
        CurrentDomain = DOMAIN; Tls = 'tls'; CurrentPort = 443

async def resolve_host(host):
    try:
        ipaddress.ip_address(host); return host
    except: pass
    for dns in DNS_SERVERS:
        try:
            d = await http_get_json(f'https://dns.google/resolve?name={host}&type=A', {'Accept': 'application/dns-json'}, 5)
            if d.get('Status') == 0 and d.get('Answer'):
                for a in d['Answer']:
                    if a.get('type') == 1: return a.get('data')
        except: continue
    return host

async def fetch_text(url, timeout=20):
    return await asyncio.get_event_loop().run_in_executor(None, _sync_fetch_text, url, timeout)

def _sync_fetch_text(url, timeout):
    req = urllib.request.Request(url, headers={'User-Agent': 'nezha-agent/1.0'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', errors='replace')

# ── Proxy Handlers ──────────────────────────────────────────────────────
def _decode_atyp(data, offset):
    """VLESS ATYP: 1=IPv4, 2=domain, 3=IPv6"""
    if offset >= len(data): return None, offset
    atyp = data[offset]; offset += 1
    if atyp == 1:
        if offset + 4 > len(data): return None, offset
        host = '.'.join(str(b) for b in data[offset:offset+4]); offset += 4
    elif atyp == 2:
        if offset >= len(data): return None, offset
        hl = data[offset]; offset += 1
        if offset + hl > len(data): return None, offset
        host = data[offset:offset+hl].decode(); offset += hl
    elif atyp == 3:
        if offset + 16 > len(data): return None, offset
        host = ':'.join(f'{(data[j] << 8) + data[j+1]:04x}' for j in range(offset, offset+16, 2)); offset += 16
    else: return None, offset
    return host, offset

def _decode_atyp_std(data, offset):
    """Standard SOCKS ATYP: 1=IPv4, 3=domain, 4=IPv6"""
    if offset >= len(data): return None, offset
    atyp = data[offset]; offset += 1
    if atyp == 1:
        if offset + 4 > len(data): return None, offset
        host = '.'.join(str(b) for b in data[offset:offset+4]); offset += 4
    elif atyp == 3:
        if offset >= len(data): return None, offset
        hl = data[offset]; offset += 1
        if offset + hl > len(data): return None, offset
        host = data[offset:offset+hl].decode(); offset += hl
    elif atyp == 4:
        if offset + 16 > len(data): return None, offset
        host = ':'.join(f'{(data[j] << 8) + data[j+1]:04x}' for j in range(offset, offset+16, 2)); offset += 16
    else: return None, offset
    return host, offset

class ProxyHandler:
    def __init__(self, uuid_bytes):
        self.uuid_bytes = uuid_bytes

    async def handle_vless(self, ws, msg):
        try:
            if len(msg) < 18 or msg[0] != 0 or msg[1:17] != self.uuid_bytes: return False
            i = msg[17] + 19
            if i + 3 > len(msg): return False
            port = struct.unpack('!H', msg[i:i+2])[0]; i += 2
            host, i = _decode_atyp(msg, i)
            if host is None: return False
            if is_blocked_domain(host): await ws.close(); return False
            await ws.send_bytes(bytes([0, 0]))
            rh = await resolve_host(host)
            try:
                r, w = await asyncio.open_connection(rh, port)
                if i < len(msg): w.write(msg[i:]); await w.drain()
                async def f1():
                    try:
                        while True:
                            d = await ws.recv()
                            if d is None: break
                            w.write(d); await w.drain()
                    except: pass
                    finally: w.close(); await w.wait_closed()
                async def f2():
                    try:
                        while True:
                            d = await r.read(4096)
                            if not d: break
                            await ws.send_bytes(d)
                    except: pass
                await asyncio.gather(f1(), f2())
            except Exception as e:
                if DEBUG: logger.error(f"VLESS conn: {e}")
            return True
        except Exception as e:
            if DEBUG: logger.error(f"VLESS err: {e}")
            return False

    async def handle_trojan(self, ws, msg):
        try:
            if len(msg) < 58: return False
            rh = msg[:56]
            if not all(0x30 <= b <= 0x39 or 0x61 <= b <= 0x66 or 0x41 <= b <= 0x46 for b in rh):
                return False
            rh_s = rh.decode('ascii')
            h1 = hashlib.sha224(CUUID.encode()).hexdigest()
            h2 = hashlib.sha224(UUID.encode()).hexdigest()
            if rh_s != h1 and rh_s != h2: return False
            off = 56
            if msg[off:off+2] == b'\r\n': off += 2
            if off >= len(msg) or msg[off] != 1: return False
            off += 1
            host, off = _decode_atyp_std(msg, off)
            if host is None: return False
            if off + 2 > len(msg): return False
            port = struct.unpack('!H', msg[off:off+2])[0]; off += 2
            if msg[off:off+2] == b'\r\n': off += 2
            if is_blocked_domain(host): await ws.close(); return False
            rh = await resolve_host(host)
            try:
                r, w = await asyncio.open_connection(rh, port)
                if off < len(msg): w.write(msg[off:]); await w.drain()
                async def f1():
                    try:
                        while True:
                            d = await ws.recv()
                            if d is None: break
                            w.write(d); await w.drain()
                    except: pass
                    finally: w.close(); await w.wait_closed()
                async def f2():
                    try:
                        while True:
                            d = await r.read(4096)
                            if not d: break
                            await ws.send_bytes(d)
                    except: pass
                await asyncio.gather(f1(), f2())
            except Exception as e:
                if DEBUG: logger.error(f"Tro conn: {e}")
            return True
        except Exception as e:
            if DEBUG: logger.error(f"Tro err: {e}")
            return False

    async def handle_shadowsocks(self, ws, msg):
        try:
            if len(msg) < 7:
                if DEBUG: logger.warning('ss: msg too short %d', len(msg))
                return False
            off = 0
            host, off = _decode_atyp_std(msg, off)
            if host is None: return False
            if off + 2 > len(msg): return False
            port = struct.unpack('!H', msg[off:off+2])[0]; off += 2
            if is_blocked_domain(host): await ws.close(); return False
            rh = await resolve_host(host)
            try:
                r, w = await asyncio.open_connection(rh, port)
                if off < len(msg): w.write(msg[off:]); await w.drain()
                async def f1():
                    try:
                        while True:
                            d = await ws.recv()
                            if d is None: break
                            w.write(d); await w.drain()
                    except: pass
                    finally: w.close(); await w.wait_closed()
                async def f2():
                    try:
                        while True:
                            d = await r.read(4096)
                            if not d: break
                            await ws.send_bytes(d)
                    except: pass
                await asyncio.gather(f1(), f2())
            except Exception as e:
                if DEBUG: logger.error(f"SS conn: {e}")
            return True
        except Exception as e:
            if DEBUG: logger.error(f"SS err: {e}")
            return False

# ── Connection Handler ─────────────────────────────────────────────────
async def handle_connection(r, w):
    try:
        req = await asyncio.wait_for(_parse_http(r), timeout=10)
        if req is None: w.close(); return
        method, path, headers, body = req
        upgrade = headers.get('upgrade', '').lower()
        if upgrade == 'websocket' and method == 'GET':
            key = headers.get('sec-websocket-key', '')
            if f'/{WSPATH}' not in path: w.close(); return
            ws = WebSocket(r, w)
            await _http_respond_ws(w, key)
            proxy = ProxyHandler(bytes.fromhex(CUUID))
            first = await asyncio.wait_for(ws.recv(), timeout=5)
            if first is None: return
            if len(first) > 17 and first[0] == 0:
                if await proxy.handle_vless(ws, first): return
            if len(first) >= 58:
                if await proxy.handle_trojan(ws, first): return
            if len(first) > 0 and first[0] in (1, 3, 4):
                if await proxy.handle_shadowsocks(ws, first): return
            await ws.close()
            return
        if method == 'GET':
            if path == '/':
                try:
                    with open('index.html', 'r', encoding='utf-8') as f: content = f.read()
                    ct = 'text/html'; body = content.encode()
                except: ct = 'text/html'; body = b'Hello world!'
                await _http_respond(w, '200 OK', ct, body)
                return
            if path == f'/{SUB_PATH}':
                await get_isp(); await get_ip()
                np = f"{NAME}-{ISP}" if NAME else ISP
                tp = 'tls' if Tls == 'tls' else 'none'
                st = 'tls;' if Tls == 'tls' else ''
                vl = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tp}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{np}"
                tr = f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}?security={tp}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{np}"
                ssb = base64.b64encode(f"none:{UUID}".encode()).decode()
                ss = f"ss://{ssb}@{CurrentDomain}:{CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{CurrentDomain};path%3D%2F{WSPATH};{st}sni%3D{CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#{np}"
                sub = base64.b64encode(f"{vl}\n{tr}\n{ss}".encode()).decode() + '\n'
                await _http_respond(w, '200 OK', 'text/plain', sub.encode())
                return
        await _http_respond(w, '404 Not Found', 'text/plain', b'Not Found\n')
    except asyncio.TimeoutError: pass
    except Exception as e:
        if DEBUG: logger.error(f"HTTP err: {e}")
    finally:
        try: w.close()
        except: pass

# ── Access Task ─────────────────────────────────────────────────────────
async def add_access_task():
    if not AUTO_ACCESS or not DOMAIN: return
    try:
        await http_post(f"https://oooo.serv00.net/add-url", {'url': f'https://{DOMAIN}/{SUB_PATH}'})
        logger.info('Automatic Access Task added')
    except: pass

def cleanup_files():
    for f in ['npm', 'config.yaml']:
        try:
            if os.path.exists(f): os.remove(f)
        except: pass

# ── Manual Protobuf Codec (zero deps) ──────────────────────────────────
def _pb_varint(n):
    b = bytearray()
    while n > 0x7f:
        b.append((n & 0x7f) | 0x80); n >>= 7
    b.append(n & 0x7f); return bytes(b)

def _pb_tag(fn, wt):
    return _pb_varint((fn << 3) | wt)

def pb_str(fn, v):
    if not v: return b''
    d = v.encode('utf-8') if isinstance(v, str) else v
    return _pb_tag(fn, 2) + _pb_varint(len(d)) + d

def pb_u64(fn, v):
    if not v: return b''
    return _pb_tag(fn, 0) + _pb_varint(int(v))

def pb_bool(fn, v):
    if not v: return b''
    return _pb_tag(fn, 0) + b'\x01'

def pb_dbl(fn, v):
    if v is None: return b''
    return _pb_tag(fn, 1) + struct.pack('<d', float(v))

def pb_rep_str(fn, v):
    if not v: return b''
    return b''.join(pb_str(fn, s) for s in v)

def pb_rep_dbl(fn, v):
    if not v: return b''
    return b''.join(pb_dbl(fn, x) for x in v)

def pb_bytes(fn, v):
    if not v: return b''
    d = bytes(v) if not isinstance(v, (bytes, bytearray)) else v
    return _pb_tag(fn, 2) + _pb_varint(len(d)) + d

def pb_msg(fn, v):
    if not v: return b''
    return _pb_tag(fn, 2) + _pb_varint(len(v)) + v

def _read_varint(buf, off):
    v = 0; s = 0
    while off < len(buf):
        b = buf[off]; off += 1
        v |= (b & 0x7f) << s; s += 7
        if not (b & 0x80): break
    return v, off

def _skip_field(buf, off, wt):
    if wt == 0: _, off = _read_varint(buf, off)
    elif wt == 1: off += 8
    elif wt == 2: l, off = _read_varint(buf, off); off += l
    elif wt == 5: off += 4
    return off

def encode_host(h):
    return b''.join([
        pb_str(1, h.get('platform', '')), pb_str(2, h.get('platform_version', '')),
        pb_rep_str(3, h.get('cpu', [])), pb_u64(4, h.get('mem_total', 0)),
        pb_u64(5, h.get('disk_total', 0)), pb_u64(6, h.get('swap_total', 0)),
        pb_str(7, h.get('arch', '')), pb_str(8, h.get('virtualization', '')),
        pb_u64(9, h.get('boot_time', 0)), pb_str(10, h.get('version', '')),
        pb_rep_str(11, h.get('gpu', []))
    ])

def encode_state(s):
    temps = s.get('temperatures') or []
    temp_fields = b''
    for t in temps:
        tb = pb_str(1, t.get('name', '')) + pb_dbl(2, t.get('temperature', 0))
        temp_fields += _pb_tag(1, 2) + _pb_varint(len(tb)) + tb
    return b''.join([
        pb_dbl(1, s.get('cpu', 0)), pb_u64(2, s.get('mem_used', 0)),
        pb_u64(3, s.get('swap_used', 0)), pb_u64(4, s.get('disk_used', 0)),
        pb_u64(5, s.get('net_in_transfer', 0)), pb_u64(6, s.get('net_out_transfer', 0)),
        pb_u64(7, s.get('net_in_speed', 0)), pb_u64(8, s.get('net_out_speed', 0)),
        pb_u64(9, s.get('uptime', 0)), pb_dbl(10, s.get('load1', 0)),
        pb_dbl(11, s.get('load5', 0)), pb_dbl(12, s.get('load15', 0)),
        pb_u64(13, s.get('tcp_conn_count', 0)), pb_u64(14, s.get('udp_conn_count', 0)),
        pb_u64(15, s.get('process_count', 0)), temp_fields,
        pb_rep_dbl(17, s.get('gpu', []))
    ])

def encode_task_result(r):
    return b''.join([
        pb_u64(1, r.get('id', 0)), pb_u64(2, r.get('type', 0)),
        pb_dbl(3, r.get('delay', 0)), pb_str(4, r.get('data', '')),
        pb_bool(5, r.get('successful', False))
    ])

def encode_geoip(g):
    ip = g.get('ip') or {}
    ipb = pb_str(1, ip.get('ipv4', '')) + pb_str(2, ip.get('ipv6', ''))
    return b''.join([
        pb_bool(1, g.get('use6', False)),
        _pb_tag(2, 2) + _pb_varint(len(ipb)) + ipb,
        pb_str(3, g.get('country_code', '')),
        pb_u64(4, g.get('dashboard_boot_time', 0))
    ])

def encode_iostream(d):
    return pb_bytes(1, d.get('data', b''))

def decode_uint64_receipt(buf):
    off = 0; data = 0
    while off < len(buf):
        tag, off = _read_varint(buf, off)
        fn = tag >> 3; wt = tag & 7
        if fn == 1 and wt == 0: data, off = _read_varint(buf, off)
        else: off = _skip_field(buf, off, wt)
    return {'data': data}

def decode_receipt(buf):
    off = 0; proced = False
    while off < len(buf):
        tag, off = _read_varint(buf, off)
        fn = tag >> 3; wt = tag & 7
        if fn == 1 and wt == 0: v, off = _read_varint(buf, off); proced = v != 0
        else: off = _skip_field(buf, off, wt)
    return {'proced': proced}

def decode_task(buf):
    off = 0; id_ = 0; type_ = 0; data = ''
    while off < len(buf):
        tag, off = _read_varint(buf, off)
        fn = tag >> 3; wt = tag & 7
        if fn == 1 and wt == 0: id_, off = _read_varint(buf, off)
        elif fn == 2 and wt == 0: type_, off = _read_varint(buf, off)
        elif fn == 3 and wt == 2:
            l, off = _read_varint(buf, off); data = buf[off:off+l].decode('utf-8', errors='replace'); off += l
        else: off = _skip_field(buf, off, wt)
    return {'id': id_, 'type': type_, 'data': data}

def decode_iostream(buf):
    off = 0; d = b''
    while off < len(buf):
        tag, off = _read_varint(buf, off)
        fn = tag >> 3; wt = tag & 7
        if fn == 1 and wt == 2: l, off = _read_varint(buf, off); d = buf[off:off+l]; off += l
        else: off = _skip_field(buf, off, wt)
    return {'data': d}

# ── Minimal HTTP/2 + gRPC Client (zero deps) ──────────────────────────
_H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

def _h2_varint(n):
    b = bytearray()
    while n > 0x7f: b.append((n & 0x7f) | 0x80); n >>= 7
    b.append(n); return bytes(b)

def _h2_frame(typ, flags, sid, payload):
    return struct.pack('!I', len(payload))[1:] + bytes([typ, flags]) + struct.pack('!I', sid)[:4] + payload

def _hpack_string(data):
    l = len(data); r = bytearray()
    if l < 128: r.append(l)
    else:
        r.append(0x7f); l -= 127
        while l >= 128: r.append((l & 0x7f) | 0x80); l >>= 7
        r.append(l)
    return bytes(r) + data

def _hpack_literal(name, value):
    return b'\x00' + _hpack_string(name.encode()) + _hpack_string(value.encode())

def _hpack_indexed(idx):
    if idx < 128: return bytes([0x80 | idx])
    return bytes([0xFF]) + _h2_varint(idx - 127)

class H2Connection:
    def __init__(self, host, port, tls):
        self.host = host; self.port = port; self.tls = tls
        self.r = None; self.w = None; self._sid = 1
        self._connected = False; self._reader_task = None
        self._streams = {}; self._write_lock = asyncio.Lock()

    async def connect(self, timeout=15):
        ctx = None
        if self.tls:
            ctx = _ssl.create_default_context()
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
        self.r, self.w = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, ssl=ctx), timeout=timeout)
        self.w.write(_H2_PREFACE + _h2_frame(4, 0, 0, b''))
        await self.w.drain()
        while True:
            f = await self._read_frame()
            if f is None:
                if self.r.at_eof(): raise ConnectionError('server closed connection')
                raise ConnectionError('h2 connect failed')
            if f['typ'] == 4 and not f['flags']:
                async with self._write_lock:
                    self.w.write(_h2_frame(4, 1, 0, b'')); await self.w.drain()
            if f['typ'] == 4: continue
            break
        self._connected = True
        self._reader_task = asyncio.ensure_future(self._read_loop())

    async def _read_loop(self):
        while self._connected:
            try:
                f = await self._read_frame(60)
            except asyncio.IncompleteReadError:
                break
            except asyncio.TimeoutError:
                continue
            except (ConnectionError, OSError):
                break
            if f is None:
                if self.r and self.r.at_eof(): break
                continue
            if f['sid'] == 0:
                if f['typ'] == 4 and not f['flags']:
                    asyncio.ensure_future(self._send_frame(4, 1, 0, b''))
                elif f['typ'] == 6 and not (f['flags'] & 0x80):
                    asyncio.ensure_future(self._send_frame(6, 0x80, 0, f['payload']))
                elif f['typ'] == 7:
                    break
            elif f['sid'] in self._streams:
                self._streams[f['sid']]._push_frame(f)
        self._connected = False
        for s in list(self._streams.values()):
            s._close()

    async def _read_frame(self, timeout=15):
        head = await asyncio.wait_for(self.r.readexactly(9), timeout=timeout)
        ln = struct.unpack('!I', b'\x00' + head[:3])[0]
        typ, flags, sid = head[3], head[4], struct.unpack('!I', head[5:9])[0]
        payload = await asyncio.wait_for(self.r.readexactly(ln), timeout=timeout) if ln else b''
        return {'typ': typ, 'flags': flags, 'sid': sid, 'payload': payload}

    async def _send_frame(self, typ, flags, sid, payload):
        async with self._write_lock:
            self.w.write(_h2_frame(typ, flags, sid, payload))
            await self.w.drain()

    def _build_hp(self, path, metadata):
        hp = b''
        hp += _hpack_indexed(3)
        hp += _hpack_literal(':path', path)
        hp += _hpack_indexed(7)
        hp += _hpack_literal(':authority', f'{self.host}:{self.port}')
        hp += _hpack_literal('content-type', 'application/grpc')
        hp += _hpack_literal('te', 'trailers')
        hp += _hpack_literal('client_secret', metadata.get('client_secret', ''))
        hp += _hpack_literal('client_uuid', metadata.get('client_uuid', ''))
        return hp

    async def unary(self, path, encode_req, decode_res, req, metadata):
        sid = self._sid; self._sid += 2
        pb = encode_req(req)
        body = b'\x00' + struct.pack('!I', len(pb)) + pb
        hp = self._build_hp(path, metadata)
        s = _UnaryStream(sid, decode_res)
        self._streams[sid] = s
        async with self._write_lock:
            self.w.write(_h2_frame(1, 0x04, sid, hp))
            self.w.write(_h2_frame(0, 0x01, sid, body))
            await self.w.drain()
        result = await s.wait()
        self._streams.pop(sid, None)
        return result

    async def bidi_stream(self, path, encode_req, decode_res, metadata):
        sid = self._sid; self._sid += 2
        hp = self._build_hp(path, metadata)
        stream = BidiStream(self, sid, encode_req, decode_res)
        self._streams[sid] = stream
        async with self._write_lock:
            self.w.write(_h2_frame(1, 0x04, sid, hp))
            await self.w.drain()
        return stream

    def metadata(self, secret, uuid_):
        return {'client_secret': secret, 'client_uuid': uuid_}

    async def close(self):
        self._connected = False
        if self._reader_task:
            self._reader_task.cancel()
            try: await self._reader_task
            except: pass
        for s in list(self._streams.values()):
            s._close()
        self._streams.clear()
        if self.w:
            try:
                async with self._write_lock:
                    self.w.write(_h2_frame(8, 0, 0, struct.pack('!I', 0) + b'\x00'*4))
                    await self.w.drain()
            except: pass
            try: self.w.close(); await self.w.wait_closed()
            except: pass

class _UnaryStream:
    def __init__(self, sid, decode_res):
        self.sid = sid; self.decode_res = decode_res
        self._body = b''; self._fut = asyncio.get_event_loop().create_future()

    def _push_frame(self, f):
        if f['typ'] == 0:
            self._body += f['payload']
            if f['flags'] & 1:
                if not self._fut.done():
                    self._fut.set_result(self.decode_res(self._body[5:] if len(self._body) >= 5 else b''))
        elif f['typ'] == 1 and f['flags'] & 4:
            if not self._fut.done():
                self._fut.set_result(self.decode_res(self._body[5:] if len(self._body) >= 5 else b''))

    def _close(self):
        if not self._fut.done():
            self._fut.set_exception(ConnectionError('stream closed'))

    async def wait(self):
        return await self._fut

class BidiStream:
    def __init__(self, conn, sid, encode_req, decode_res):
        self._conn = conn; self._sid = sid
        self._encode = encode_req; self._decode = decode_res
        self._q = asyncio.Queue()
        self._fut = asyncio.get_event_loop().create_future()

    def _push_frame(self, f):
        if f['typ'] == 0:
            self._q.put_nowait(f['payload'])
        elif f['typ'] == 3 or (f['typ'] == 1 and f['flags'] & 0x01):
            self._close()

    def _close(self):
        self._q.put_nowait(None)
        if not self._fut.done():
            self._fut.set_result(None)

    async def read(self):
        payload = await self._q.get()
        if payload is None: return None
        if len(payload) >= 5:
            return self._decode(payload[5:])
        return None

    async def write(self, msg):
        pb = self._encode(msg)
        async with self._conn._write_lock:
            self._conn.w.write(_h2_frame(0, 0, self._sid, b'\x00' + struct.pack('!I', len(pb)) + pb))
            await self._conn.w.drain()

    @property
    def done(self): return self._fut

    async def close(self):
        async with self._conn._write_lock:
            self._conn.w.write(_h2_frame(3, 0, self._sid, struct.pack('!I', 0)))
            await self._conn.w.drain()
        self._close()

# ── System Monitor (no psutil needed) ──────────────────────────────────
def _read_file(p):
    try:
        with open(p, 'r') as f: return f.read()
    except: return ''

def _parse_proc_meminfo():
    t = _read_file('/proc/meminfo')
    if not t: return {'total': 0, 'avail': 0}
    r = {}
    for line in t.splitlines():
        parts = line.split(':')
        if len(parts) == 2:
            val = parts[1].strip().split()[0] if parts[1].strip() else '0'
            try: r[parts[0].strip()] = int(val) * 1024
            except: r[parts[0].strip()] = 0
    return {'total': r.get('MemTotal', 0), 'avail': r.get('MemAvailable', r.get('MemFree', 0))}

def _parse_proc_stat():
    t = _read_file('/proc/stat')
    if not t: return (0, 0, 0)
    for line in t.splitlines():
        if line.startswith('cpu '):
            parts = line.split()
            if len(parts) >= 5:
                user = int(parts[1]); nice = int(parts[2]); sys = int(parts[3]); idle = int(parts[4]); iowait = int(parts[5]) if len(parts) > 5 else 0
                return (user + nice + sys, idle + iowait, user + nice + sys + idle + iowait)
    return (0, 0, 0)

def _parse_proc_net_dev():
    t = _read_file('/proc/net/dev')
    if not t: return (0, 0)
    rx = 0; tx = 0
    for line in t.splitlines()[2:]:
        parts = line.strip().split()
        if len(parts) > 9:
            try: rx += int(parts[1]); tx += int(parts[9])
            except: pass
    return (rx, tx)

def _disk_usage():
    try:
        s = os.statvfs('/')
        return {'total': s.f_frsize * s.f_blocks, 'used': s.f_frsize * (s.f_blocks - s.f_bfree)}
    except: return {'total': 0, 'used': 0}

def _parse_proc_loadavg():
    t = _read_file('/proc/loadavg')
    if t:
        parts = t.split()
        if len(parts) >= 3:
            try: return (float(parts[0]), float(parts[1]), float(parts[2]))
            except: pass
    return (0.0, 0.0, 0.0)

def _count_procs():
    try:
        c = 0
        for e in os.listdir('/proc'):
            if e.isdigit(): c += 1
        return c
    except: return 0

def _uptime():
    t = _read_file('/proc/uptime')
    if t:
        try: return int(float(t.split()[0]))
        except: pass
    return 0

class SystemMonitor:
    def __init__(self):
        self.boot_time = int(time.time()) if not _uptime() else int(time.time()) - _uptime()
        self.net_rx = 0; self.net_tx = 0; self.last_net = 0
        self.last_cpu = _parse_proc_stat()
        self.last_cpu_time = time.time()

    def collect_host(self):
        mem = _parse_proc_meminfo(); disk = _disk_usage()
        return {
            'platform': platform.system().lower() or sys.platform,
            'platform_version': platform.version() or platform.release(),
            'cpu': [platform.processor() or platform.machine() or 'CPU'],
            'mem_total': mem['total'], 'disk_total': disk['total'], 'swap_total': 0,
            'arch': platform.machine(), 'virtualization': '',
            'boot_time': self.boot_time, 'version': NEZHA_AGENT_VERSION, 'gpu': []
        }

    def collect_state(self):
        now = time.time()
        active, idle, total = _parse_proc_stat()
        cpu_pct = 0
        if self.last_cpu[2] > 0 and total > self.last_cpu[2]:
            total_delta = total - self.last_cpu[2]
            idle_delta = idle - self.last_cpu[1]
            cpu_pct = min(100.0, max(0.0, (total_delta - idle_delta) / total_delta * 100))
        self.last_cpu = (active, idle, total)

        rx, tx = _parse_proc_net_dev()
        nx = rx - self.net_rx; tx_d = tx - self.net_tx
        diff = now - self.last_net
        inspeed = max(0, nx // int(diff)) if self.last_net > 0 and diff > 0 else 0
        outspeed = max(0, tx_d // int(diff)) if self.last_net > 0 and diff > 0 else 0
        self.net_rx = rx; self.net_tx = tx; self.last_net = now

        mem = _parse_proc_meminfo(); disk = _disk_usage(); load = _parse_proc_loadavg()
        return {
            'cpu': cpu_pct, 'mem_used': mem.get('total', 0) - mem.get('avail', 0),
            'swap_used': 0, 'disk_used': disk['used'],
            'net_in_transfer': rx, 'net_out_transfer': tx,
            'net_in_speed': inspeed, 'net_out_speed': outspeed,
            'uptime': int(now - self.boot_time),
            'load1': load[0], 'load5': load[1], 'load15': load[2],
            'tcp_conn_count': 0, 'udp_conn_count': 0,
            'process_count': _count_procs(), 'temperatures': [], 'gpu': []
        }

# ── DoH Resolver ───────────────────────────────────────────────────────
class DohResolver:
    def __init__(self, endpoints):
        self.endpoints = endpoints

    async def resolve(self, host):
        if not self.endpoints or is_ip_address(host): return host
        for rt in ('A', 'AAAA'):
            for ep in self.endpoints:
                r = await self._query(ep, host, rt)
                if r: return r
        return host

    async def _query(self, ep, host, rt):
        try:
            d = await http_get_json(f"{ep}?name={host}&type={rt}", {'Accept': 'application/dns-json', 'User-Agent': 'python-ws/1.0'}, 5)
            if d.get('Status') == 0 and d.get('Answer'):
                et = 1 if rt == 'A' else 28
                for a in d['Answer']:
                    if a.get('type') == et and a.get('data'): return a['data']
        except: pass
        return None

# ── Config Helpers ──────────────────────────────────────────────────────
def env_bool(n, d=False):
    v = os.environ.get(n)
    if v is None: return d
    return v.strip().lower() in ('1', 'true', 'yes', 'on')

def env_int(n, d):
    try: return int(os.environ.get(n, d))
    except: return d

def strip_scheme(v):
    t = (v or '').strip()
    if '://' in t: t = t.split('://', 1)[1]
    return t.strip('/')

def extract_port(v):
    t = strip_scheme(v)
    if not t: return ''
    if t.startswith('['):
        c = t.find(']')
        if c >= 0 and c + 1 < len(t) and t[c+1] == ':': return t[c+2:]
        return ''
    f = t.find(':'); l = t.rfind(':')
    if f >= 0 and f == l and l < len(t) - 1: return t[l+1:]
    return ''

def has_explicit_port(v): return bool(extract_port(v))

def resolve_nezha_target(server, port):
    host = strip_scheme(server)
    if not host: return ''
    if has_explicit_port(host): return host
    rp = (port or '').strip()
    if not rp: return host
    if ':' in host and not host.startswith('['): host = f'[{host}]'
    return f'{host}:{rp}'

def parse_host_port(v):
    t = (v or '').strip()
    if t.startswith('['):
        c = t.find(']')
        if c < 0 or c + 1 >= len(t) or t[c+1] != ':': raise ValueError(f'invalid: {v}')
        return t[1:c], int(t[c+2:])
    s = t.rfind(':')
    if s <= 0 or s == len(t) - 1 or t.count(':') > 1: raise ValueError(f'invalid: {v}')
    return t[:s], int(t[s+1:])

def is_ip_address(v):
    try: ipaddress.ip_address(v); return True
    except: return False

def format_host_port(host, port):
    if ':' in host and not host.startswith('['): return f'[{host}]:{port}'
    return f'{host}:{port}'

def parse_doh_endpoints(v):
    return [e.strip() for e in (v or '').split(',') if e.strip()]

def stream_id_from_task(data):
    try: p = json.loads(data or '{}'); return p.get('StreamID') or p.get('stream_id') or p.get('streamId')
    except: return None

# ── Nezha Client ───────────────────────────────────────────────────────
def create_nezha_config():
    if not NEZHA_SERVER or not NEZHA_KEY: return None
    target = resolve_nezha_target(NEZHA_SERVER, NEZHA_PORT)
    if not target or not has_explicit_port(target): return None
    port = extract_port(target)
    tls = env_bool('NEZHA_TLS', port in TLS_PORTS)
    return {
        'server': target, 'client_secret': NEZHA_KEY, 'client_uuid': UUID,
        'tls': tls, 'report_delay': max(1, min(4, env_int('NEZHA_REPORT_DELAY', 4))),
        'ip_report_period': max(30, env_int('NEZHA_IP_REPORT_PERIOD', 1800)),
        'skip_connection_count': env_bool('NEZHA_SKIP_CONNECTION_COUNT', True),
        'skip_procs_count': env_bool('NEZHA_SKIP_PROCS_COUNT', True),
        'disable_command_execute': env_bool('NEZHA_DISABLE_COMMAND_EXECUTE', False),
        'disable_send_query': env_bool('NEZHA_DISABLE_SEND_QUERY', False),
        'disable_nat': env_bool('NEZHA_DISABLE_NAT', True),
        'use_ipv6_country_code': env_bool('NEZHA_USE_IPV6_COUNTRY_CODE', False),
        'doh_endpoints': tuple(parse_doh_endpoints(NEZHA_DOH)),
        'disable_auto_update': True, 'disable_force_update': True,
    }

class NezhaClient:
    def __init__(self, config):
        self.config = config
        self.monitor = SystemMonitor()
        self.doh = DohResolver(config['doh_endpoints'])
        self.conn = None
        self.running = False
        self.last_geo_ip = ''
        self.last_boot_time = 0
        self.force_geo = False

    async def run_forever(self):
        self.running = True
        while self.running:
            try: await self._run_once()
            except asyncio.CancelledError: self.running = False; raise
            except Exception as e:
                if DEBUG: logger.error(f'[Agent] disconnected: {e}')
            await self._close()
            if self.running: await asyncio.sleep(10)

    def stop(self): self.running = False

    async def _run_once(self):
        oh, op = parse_host_port(self.config['server'])
        ch = await self.doh.resolve(oh)
        target = format_host_port(ch, op)
        self.conn = H2Connection(ch, op, self.config['tls'])
        await self.conn.connect(15)
        md = self.conn.metadata(self.config['client_secret'], self.config['client_uuid'])
        host = self.monitor.collect_host()
        receipt = await self.conn.unary('/proto.NezhaService/ReportSystemInfo2', encode_host, decode_uint64_receipt, host, md)
        bt = receipt.get('data', 0) if receipt else 0
        if bt and self.last_boot_time and bt != self.last_boot_time: self.force_geo = True
        self.last_boot_time = bt or 0
        if DEBUG: logger.debug(f'connected to {self.config["server"]}')
        await self._run_streams(md)

    async def _run_streams(self, md):
        state_stream = await self.conn.bidi_stream('/proto.NezhaService/ReportSystemState', encode_state, decode_receipt, md)
        task_stream = await self.conn.bidi_stream('/proto.NezhaService/RequestTask', encode_task_result, decode_task, md)
        s = self.monitor.collect_state()
        await state_stream.write(s)

        async def _state_writer():
            while self.running:
                await asyncio.sleep(self.config['report_delay'])
                try: s = self.monitor.collect_state(); await state_stream.write(s)
                except Exception as e:
                    if DEBUG: logger.error(f'state write err: {e}')
                    break

        async def _task_reader():
            while self.running:
                try:
                    task = await task_stream.read()
                    if task is None: break
                    result = await self._handle_task(task)
                    if result: await task_stream.write(result)
                except Exception as e:
                    if DEBUG: logger.error(f'task read err: {e}')
                    break

        async def _host_reporter():
            while self.running:
                await asyncio.sleep(600)
                try:
                    h = self.monitor.collect_host()
                    r = await self.conn.unary('/proto.NezhaService/ReportSystemInfo2', encode_host, decode_uint64_receipt, h, md)
                    bt = r.get('data', 0) if r else 0
                    if bt and self.last_boot_time and bt != self.last_boot_time: self.force_geo = True
                    self.last_boot_time = bt or 0
                except Exception as e:
                    if DEBUG: logger.error(f'host report failed: {e}')

        async def _geoip_reporter():
            while self.running:
                try:
                    g = await self._fetch_geoip()
                    if g is not None:
                        await self.conn.unary('/proto.NezhaService/ReportGeoIP', encode_geoip, decode_uint64_receipt, g, md)
                        self.force_geo = False
                except Exception as e:
                    if DEBUG: logger.error(f'geoip failed: {e}')
                await asyncio.sleep(self.config['ip_report_period'])

        state_write_task = asyncio.create_task(_state_writer())
        task_read_task = asyncio.create_task(_task_reader())
        host_task = asyncio.create_task(_host_reporter())
        geo_task = asyncio.create_task(_geoip_reporter())
        done, pending = await asyncio.wait(
            [state_write_task, task_read_task, state_stream.done, task_stream.done],
            return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for t in done:
            e = t.exception()
            if e and not isinstance(e, asyncio.CancelledError): raise e
        raise RuntimeError('stream closed')

    async def _handle_task(self, task):
        t = task.get('type', 0); i = task.get('id', 0); d = task.get('data', '')
        if t == 7:
            return {'id': i, 'type': t, 'delay': 0, 'data': '', 'successful': True}
        if t == 12:
            return {'id': i, 'type': t, 'delay': 0, 'data': json.dumps(self.config), 'successful': True}
        return {'id': i, 'type': t, 'delay': 0, 'data': 'unsupported', 'successful': False}

    async def _fetch_geoip(self):
        eps = ['https://blog.cloudflare.com/cdn-cgi/trace',
               'https://developers.cloudflare.com/cdn-cgi/trace',
               'https://hostinger.com/cdn-cgi/trace',
               'https://ahrefs.com/cdn-cgi/trace']
        ipv4 = ''; ipv6 = ''
        for ep in eps:
            try:
                body = await fetch_text(ep)
                for line in (body or '').splitlines():
                    t = line.strip()
                    if t.startswith('ip='):
                        c = t[3:].strip()
                        try:
                            p = ipaddress.ip_address(c)
                            if p.version == 4 and not ipv4: ipv4 = c
                            elif p.version == 6 and not ipv6: ipv6 = c
                        except: pass
                        if ipv4 and ipv6: break
            except: continue
        selected = ipv6 if self.config.get('use_ipv6_country_code') and ipv6 else ipv4 or ipv6
        if not selected: return None
        self.last_geo_ip = selected
        return {
            'use6': self.config.get('use_ipv6_country_code', False),
            'ip': {'ipv4': ipv4, 'ipv6': ipv6},
            'country_code': '', 'dashboard_boot_time': 0
        }

    async def _close(self):
        if self.conn:
            await self.conn.close()
            self.conn = None

# ── Main ────────────────────────────────────────────────────────────────
def create_nezha():
    config = create_nezha_config()
    if config is None: return None
    return NezhaClient(config)

async def main():
    server = await asyncio.start_server(handle_connection, '0.0.0.0', PORT)
    logger.info(f'✅ Server running on port {PORT}')
    if DEBUG:
        logger.info(f'🌐 Public IP/Domain: {CurrentDomain}')
    nezha = create_nezha()
    nezha_task = None
    if nezha is not None:
        nezha_task = asyncio.create_task(nezha.run_forever())
        if DEBUG:
            logger.info('✅ nz starting')
    asyncio.create_task(_delayed(180, cleanup_files))
    await add_access_task()

    stop_ev = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (getattr(signal, 'SIGINT', None), getattr(signal, 'SIGTERM', None)):
        if sig is None: continue
        try: loop.add_signal_handler(sig, stop_ev.set)
        except: pass
    try: await stop_ev.wait()
    except asyncio.CancelledError: pass
    finally:
        if nezha: nezha.stop()
        if nezha_task: nezha_task.cancel(); await asyncio.gather(nezha_task, return_exceptions=True)
        server.close(); await server.wait_closed()

async def _delayed(sec, fn):
    await asyncio.sleep(sec); fn()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped"); cleanup_files()
