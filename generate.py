#!/usr/bin/env python3
"""Generate Surge-compatible Telegram MTProto DC config JSON.

Data sources (same as SukkaW/Surge, cf76e874):
  1. help.getConfig via MTProto (telethon, unauthenticated, api_id 2040)
  2. Backup endpoints: DNS TXT apv3.stel.com, Firebase RTDB, Firestore,
     AppEngine dns-telegram.appspot.com
  3. Static bootstrap list (DC1-5 v4/v6)

IPv6 is canonicalized to RFC 5952 so expanded help.getConfig spellings merge
with compressed bootstrap spellings (the bug in surge-networks/MTProtoDCConfigGenerator).

Outputs:
  mtproto-dc-config-ipv4.json  — IPv4 only
  mtproto-dc-config.json       — IPv4 + IPv6

Format: Surge "encoded options" string — [N]{flags:int,id:int,ip:string,port:int,secret:string?}
followed by CSV rows. Newer Surge requires this form; plain JSON arrays are rejected.
"""

import asyncio
import base64
import hashlib
import ipaddress
import json
import struct
import subprocess
import sys
import time
import urllib.request

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

FLAG_IPV6 = 1 << 0
FLAG_MEDIA_ONLY = 1 << 1
FLAG_TCPO_ONLY = 1 << 2
FLAG_CDN = 1 << 3
FLAG_STATIC = 1 << 4
FLAG_THIS_PORT_ONLY = 1 << 5
FLAG_SECRET = 1 << 10

BOOTSTRAP = [
    (1, '149.154.175.50', 443, None),
    (1, '2001:b28:f23d:f001::a', 443, None),
    (2, '149.154.167.50', 443, None),
    (2, '149.154.167.51', 443, None),
    (2, '95.161.76.100', 443, None),
    (2, '2001:67c:4e8:f002::a', 443, None),
    (3, '149.154.175.100', 443, None),
    (3, '2001:b28:f23d:f003::a', 443, None),
    (4, '149.154.167.91', 443, None),
    (4, '2001:67c:4e8:f004::a', 443, None),
    (5, '149.154.171.5', 443, None),
    (5, '2001:b28:f23f:f005::a', 443, None),
]

MTP_PUBLIC_RSA = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyr+18Rex2ohtVy8sroGP
BwXD3DOoKCSpjDqYoXgCqB7ioln4eDCFfOBUlfXUEvM/fnKCpF46VkAftlb4VuPD
eQSS/ZxZYEGqHaywlroVnXHIjgqoxiAd192xRGreuXIaUKmkwlM9JID9WS2jUsTp
zQ91L8MEPLJ/4zrBwZua8W5fECwCCh2c9G5IzzBm+otMS/YKwmR1olzRCyEkyAEj
XWqBI9Ftv5eG8m0VkBzOG655WIYdyV0HfDK/NWcvGqa0w/nriMD6mDjKOryamw0O
P9QuYgMN0C9xMW9y8SmP4h92OAWodTYgY1hZCxdv6cs5UnW9+PWvS+WIbkh+GaWY
xwIDAQAB
-----END RSA PUBLIC KEY-----"""

FUNCTIONAL_MASK = FLAG_MEDIA_ONLY | FLAG_TCPO_ONLY | FLAG_CDN


def canon_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))


# ---------- help.getConfig ----------

def derive_flags(o) -> int:
    f = 0
    if o.ipv6: f |= FLAG_IPV6
    if o.media_only: f |= FLAG_MEDIA_ONLY
    if o.tcpo_only: f |= FLAG_TCPO_ONLY
    if o.cdn: f |= FLAG_CDN
    if o.static: f |= FLAG_STATIC
    if o.this_port_only: f |= FLAG_THIS_PORT_ONLY
    if o.secret: f |= FLAG_SECRET
    return f


async def fetch_config(ip: str, port: int, dc_id: int):
    from telethon import TelegramClient
    from telethon.sessions import MemorySession
    from telethon.tl.functions.help import GetConfigRequest

    s = MemorySession()
    s.set_dc(dc_id, ip, port)
    c = TelegramClient(s, 2040, 'not-used-for-unauthenticated-rpc', timeout=15)
    try:
        await c.connect()
        return await c(GetConfigRequest())
    finally:
        await c.disconnect()


async def fetch_config_any():
    last = None
    for dc_id, ip, port, _ in BOOTSTRAP:
        try:
            print(f"[getConfig] trying {ip}:{port}", flush=True)
            return await fetch_config(ip, port, dc_id)
        except Exception as e:
            print(f"[getConfig] {ip}:{port} failed: {e}", flush=True)
            last = e
    raise RuntimeError(f"all bootstrap endpoints failed: {last}")


# ---------- backup endpoints ----------

class Reader:
    def __init__(self, buf, off=0): self.b, self.o = buf, off
    def i32(self):
        v = struct.unpack_from('<i', self.b, self.o)[0]; self.o += 4; return v
    def u32(self): return self.i32() & 0xFFFFFFFF
    def bytes(self, n):
        v = self.b[self.o:self.o + n]; self.o += n; return v
    def tl_bytes(self):
        n = self.b[self.o]; self.o += 1
        if n == 0xFE:
            n = int.from_bytes(self.b[self.o:self.o + 3], 'little'); self.o += 3
            pad = (-n) % 4
        else:
            pad = (-(1 + n)) % 4
        v = self.b[self.o:self.o + n]; self.o += n
        self.o += pad
        return v


def ipv4_to_str(v: int) -> str:
    if v < 0: v += 2 ** 32
    return '.'.join(str((v >> s) & 0xFF) for s in (24, 16, 8, 0))


def rsa_public_decrypt(data: bytes) -> bytes:
    key = RSA.import_key(MTP_PUBLIC_RSA)
    return pow(int.from_bytes(data, 'big'), key.e, key.n).to_bytes(256, 'big')


def decode_backup(b64: str):
    """Returns list of (dc_id, ip, port, secret_bytes|None)."""
    if len(b64) != 344:
        raise ValueError(f"bad base64 length {len(b64)}")
    raw = base64.b64decode(b64)
    if len(raw) != 256:
        raise ValueError("decoded payload not 256 bytes")
    dec = rsa_public_decrypt(raw)
    pt = AES.new(dec[:32], AES.MODE_CBC, dec[16:32]).decrypt(dec[32:])
    if hashlib.sha256(pt[:208]).digest()[:16] != pt[208:224]:
        raise ValueError("sha256 mismatch")

    r = Reader(pt)
    length = r.i32()
    if not (4 <= length <= 204 and length % 4 == 0):
        raise ValueError(f"bad TL length {length}")
    ctor = r.u32()
    date = expires = None
    eps = []

    if ctor == 0x5A592A6C:  # help.configSimple (current, rule-based)
        date, expires = r.i32(), r.i32()
        for _ in range(r.i32()):  # rules: bare vector (count only, no ctor id)
            if r.u32() != 0x4679B65F:  # accessPointRule
                raise ValueError("not an accessPointRule")
            r.tl_bytes()  # phone_prefix_rules
            dc_id = r.i32()
            for _ in range(r.i32()):  # ips: bare vector too
                ip_ctor = r.u32()
                if ip_ctor == 0x37982646:  # ipPort
                    eps.append((dc_id, ipv4_to_str(r.i32()), r.i32(), None))
                elif ip_ctor == 0x7B1516EC:  # ipPortSecret (fixed 16-byte secret here)
                    v4, port = r.i32(), r.i32()
                    if v4 == 0:
                        r.bytes(16); continue
                    eps.append((dc_id, ipv4_to_str(v4), port, r.bytes(16)))
                else:
                    raise ValueError(f"unknown ipPort ctor {ip_ctor:#x}")
    elif ctor == 0xD997C3C5:  # legacy help.configSimple
        date, expires, dc_id = r.i32(), r.i32(), r.i32()
        if r.u32() != 0x1CB5C415:
            raise ValueError("bad legacy vector")
        for _ in range(r.i32()):
            eps.append((dc_id, ipv4_to_str(r.i32()), r.i32(), None))
    else:
        raise ValueError(f"unknown ctor {ctor:#x}")

    now = int(time.time())
    if date is not None and (date >= now + 1200 or expires <= now - 1200):
        raise ValueError(f"backup config outside validity ({date}..{expires}, now {now})")
    return eps


def http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={'Accept': '*/*'})
    with urllib.request.urlopen(req, timeout=15) as f:
        return f.read()


def fetch_backup_dns(domain='apv3.stel.com'):
    eps = []
    for server in ('8.8.8.8', '1.0.0.1'):
        p = subprocess.run(['dig', '+short', 'TXT', domain, f'@{server}'],
                           capture_output=True, text=True, timeout=15)
        strs = [''.join(l.strip().strip('"').split('" "'))
                for l in p.stdout.strip().splitlines() if l.strip()]
        if len(strs) != 2:
            raise ValueError(f"unexpected TXT count: {strs}")
        b64 = strs[0] + strs[1] if len(strs[0]) > len(strs[1]) else strs[1] + strs[0]
        eps += decode_backup(b64)
    return eps


def fetch_backup_endpoints():
    sources = [
        ("DNS TXT", fetch_backup_dns),
        ("Firebase RTDB", lambda: decode_backup(
            json.loads(http_get('https://reserve-5a846.firebaseio.com/ipconfigv3.json')))),
        ("Firestore", lambda: decode_backup(
            json.loads(http_get('https://firestore.googleapis.com/v1/projects/reserve-5a846'
                                '/databases/(default)/documents/ipconfig/v3'))
            ['fields']['data']['stringValue'])),
        ("AppEngine", lambda: decode_backup(
            http_get('https://dns-telegram.appspot.com').decode().strip())),
    ]
    out = []
    for name, fn in sources:
        try:
            eps = fn()
            print(f"[backup] {name}: {[(d, i, p) for d, i, p, _ in eps]}", flush=True)
            out += eps
        except Exception as e:
            print(f"[backup] {name} failed: {e}", flush=True)
    # dedupe
    seen, uniq = set(), []
    for dc, ip, port, sec in out:
        key = (dc, ip, port, sec)
        if key not in seen:
            seen.add(key)
            uniq.append((dc, ip, port, sec))
    return uniq


# ---------- merge ----------

def fallback_flags(ip: str, has_secret: bool) -> int:
    f = FLAG_STATIC
    if ':' in ip: f |= FLAG_IPV6
    if has_secret: f |= FLAG_SECRET
    return f


def merge_endpoint(options, dc_id, ip, port, secret_b64=None):
    """Returns True if a new option was appended."""
    ip = canon_ip(ip)
    for o in options:
        if (o['id'] != dc_id or o['ip'] != ip or o['port'] != port
                or (o['flags'] & FUNCTIONAL_MASK)
                or o.get('secret') != secret_b64):
            continue
        o['flags'] |= fallback_flags(ip, secret_b64 is not None)
        return False
    o = {'id': dc_id, 'ip': ip, 'port': port,
         'flags': fallback_flags(ip, secret_b64 is not None)}
    if secret_b64 is not None:
        o['secret'] = secret_b64
    options.append(o)
    return True


def dedupe(options):
    seen, out = set(), []
    for o in options:
        key = (o['id'], o['ip'], o['port'], o['flags'], o.get('secret'))
        if key not in seen:
            seen.add(key)
            out.append(o)
    return out


# ---------- output ----------

def encode_options(options) -> str:
    lines = [f"[{len(options)}]{{flags:int,id:int,ip:string,port:int,secret:string?}}"]
    for o in options:
        lines.append(f"{o['flags']},{o['id']},{o['ip']},{o['port']},{o.get('secret', '')}")
    return '\n'.join(lines) + '\n'


def write_config(path, date, expires, this_dc, options):
    cfg = {
        'date': date,
        'expires': expires,
        'this_dc': this_dc,
        'version': 1,
        'options': encode_options(options),
    }
    with open(path, 'w') as f:
        json.dump(cfg, f, indent=2)
        f.write('\n')
    print(f"[write] {path}: {len(options)} options", flush=True)


async def main():
    cfg = await fetch_config_any()
    options = [{
        'id': o.id,
        'ip': canon_ip(o.ip_address),
        'port': o.port,
        'flags': derive_flags(o),
        **({'secret': base64.b64encode(o.secret).decode()} if o.secret else {}),
    } for o in cfg.dc_options]
    print(f"[getConfig] this_dc={cfg.this_dc} live options={len(options)}", flush=True)

    backups = fetch_backup_endpoints()
    added_backup = sum(merge_endpoint(options, dc, ip, port,
                                      base64.b64encode(s).decode() if s else None)
                       for dc, ip, port, s in backups)
    added_boot = sum(merge_endpoint(options, dc, ip, port) for dc, ip, port, _ in BOOTSTRAP)
    before = len(options)
    options = dedupe(options)
    print(f"[merge] backup+{added_backup} bootstrap+{added_boot} dupes-{before - len(options)}",
          flush=True)

    date = int(cfg.date.timestamp())
    expires = int(cfg.expires.timestamp())
    v4 = [o for o in options if ':' not in o['ip']]
    write_config('mtproto-dc-config-ipv4.json', date, expires, cfg.this_dc, v4)
    write_config('mtproto-dc-config.json', date, expires, cfg.this_dc, options)


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
