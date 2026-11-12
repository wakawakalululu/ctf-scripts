# -*- coding: utf-8 -*-
"""
pcaplib.py — CTF 流量分析公共库(纯 Python 标准库实现,无需 scapy/pyshark)

能力:
  1. 解析 classic pcap 与 pcapng 两种格式(支持大小端/纳秒时间戳)
  2. 常见链路层:Ethernet / Null / RawIP / Linux SLL / Linux usbmon / USBPcap
  3. IPv4/TCP/UDP 解析与 TCP 流重组(双向,自动去重重传)
  4. HTTP 请求/响应解析(支持 chunked、gzip/deflate 解压)
  5. USB 键盘/鼠标 HID 数据提取(DLT_USB_LINUX=220 与 DLT_USBPCAP=249)
  6. tshark 可选增强(自动探测 Wireshark 安装路径)
  7. flag 正则搜索工具

所有上层脚本(find_scanner.py / usb_keyboard.py / solve.py ...)都 import 本文件。
"""
import os
import re
import io
import gzip
import zlib
import struct
import subprocess
from collections import OrderedDict

# ---------------------------------------------------------------------------
# 链路层类型常量
# ---------------------------------------------------------------------------
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_SLL = 113          # Linux cooked capture
LINKTYPE_USB_LINUX = 220    # Linux usbmon
LINKTYPE_USBPCAP = 249      # USBPcap (Windows)

DLT_NAMES = {
    0: 'NULL/Loopback', 1: 'Ethernet', 101: 'Raw IP', 113: 'Linux SLL',
    220: 'Linux usbmon (USB)', 249: 'USBPcap (USB)',
}

# ---------------------------------------------------------------------------
# 包对象
# ---------------------------------------------------------------------------
class Packet(object):
    __slots__ = ('index', 'ts', 'data')

    def __init__(self, index, ts, data):
        self.index = index      # 包序号(从 1 开始,与 wireshark 一致)
        self.ts = ts            # 浮点时间戳
        self.data = data        # 链路层原始字节

    def __repr__(self):
        return '<Packet #%d ts=%.6f len=%d>' % (self.index, self.ts, len(self.data))


# ---------------------------------------------------------------------------
# pcap / pcapng 读取
# ---------------------------------------------------------------------------
_PCAP_MAGICS = {
    b'\xa1\xb2\xc3\xd4': ('>', False),   # usec, big endian 文件
    b'\xd4\xc3\xb2\xa1': ('<', False),   # usec, little endian 文件(x86 最常见)
    b'\xa1\xb2\x3c\x4d': ('>', True),    # nanosec, big endian
    b'\x4d\x3c\xb2\xa1': ('<', True),    # nanosec, little endian
}


def _is_pcapng(data):
    return data[:4] == b'\x0a\x0d\x0d\x0a'


def read_pcap(path):
    """读取 pcap/pcapng 文件。返回 (linktype, [Packet, ...])。
    文件尾部被截断的残缺包会被忽略(等价于修复流程中的截断处理)。"""
    with open(path, 'rb') as f:
        data = f.read()
    if not data:
        raise ValueError('文件为空: %s' % path)
    if _is_pcapng(data):
        return _read_pcapng(data)
    return _read_classic(data)


def _read_classic(data):
    if len(data) < 24:
        raise ValueError('pcap 全局头不完整(可能损坏,请先用 pcapfix.py 修复)')
    magic = data[:4]
    if magic not in _PCAP_MAGICS:
        # 魔数损坏:尝试从 magic 前缺字节/多字节中恢复
        raise ValueError('pcap 魔数损坏: %r (请先用 pcapfix.py 修复)' % magic)
    endian, nano = _PCAP_MAGICS[magic]
    vmaj, vmin, tz, sig, snap, link = struct.unpack(
        endian + 'HHiIII', data[4:24])
    pkts = []
    off = 24
    n = len(data)
    idx = 1
    while off + 16 <= n:
        ts_sec, ts_sub, caplen, wirelen = struct.unpack(
            endian + 'IIII', data[off:off + 16])
        if caplen > 0x400000 or off + 16 + caplen > n:
            break  # 残缺/超长包:丢弃尾部
        div = 1000000000 if nano else 1000000
        ts = ts_sec + ts_sub / float(div)
        pkts.append(Packet(idx, ts, data[off + 16:off + 16 + caplen]))
        idx += 1
        off += 16 + caplen
    return link, pkts


def _read_pcapng(data):
    """解析 pcapng:提取 SHB/IDB 中的 linktype,EPB 中的数据包。"""
    linktype = None
    pkts = []
    endian = '<'
    off = 0
    n = len(data)
    idx = 1
    while off + 12 <= n:
        btype, blen = struct.unpack(endian + 'II', data[off:off + 8])
        if btype != 0x0A0D0D0A and (blen < 12 or blen % 4 or off + blen > n):
            break  # 长度异常(截断)则停止
        body = data[off:off + blen]
        if btype == 0x0A0D0D0A:                       # Section Header Block
            bom = body[8:12]
            if bom == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            elif bom == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            btype, _blen = struct.unpack(endian + 'II', body[0:8])
        elif btype == 0x00000001:                     # Interface Description
            lt = struct.unpack(endian + 'H', body[8:10])[0]
            if linktype is None:
                linktype = lt
        elif btype == 0x00000006:                     # Enhanced Packet Block
            _iface, hi, lo, caplen, _orig = struct.unpack(
                endian + 'IIIII', body[8:28])
            if caplen <= len(body) - 28:
                ts = ((hi << 32) | lo) / 1e6
                pkts.append(Packet(idx, ts, body[28:28 + caplen]))
                idx += 1
        off += blen
    return (linktype if linktype is not None else LINKTYPE_ETHERNET), pkts


def get_linktype_name(link):
    return DLT_NAMES.get(link, 'linktype %d' % link)


# ---------------------------------------------------------------------------
# 网络层解析
# ---------------------------------------------------------------------------
def parse_ether(data):
    """以太网帧 -> (协议, 载荷)。协议为 'ipv4'/'ipv6'/'arp'/None"""
    if len(data) < 14:
        return None, b''
    ethertype = struct.unpack('>H', data[12:14])[0]
    payload = data[14:]
    while ethertype in (0x8100, 0x88a8):              # VLAN tag
        if len(payload) < 4:
            return None, b''
        ethertype = struct.unpack('>H', payload[2:4])[0]
        payload = payload[4:]
    names = {0x0800: 'ipv4', 0x86dd: 'ipv6', 0x0806: 'arp'}
    return names.get(ethertype), payload


def parse_ipv4(data):
    """IPv4 头 -> dict(src, dst, proto, payload)"""
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0f) * 4
    if len(data) < ihl:
        return None
    proto = data[9]
    src = '.'.join(str(b) for b in data[12:16])
    dst = '.'.join(str(b) for b in data[16:20])
    return {'src': src, 'dst': dst, 'proto': proto, 'payload': data[ihl:]}


def parse_ipv6(data):
    if len(data) < 40 or data[0] >> 4 != 6:
        return None
    nxt = data[6]
    src = _fmt_ipv6(data[8:24])
    dst = _fmt_ipv6(data[24:40])
    return {'src': src, 'dst': dst, 'proto': nxt, 'payload': data[40:]}


def _fmt_ipv6(b):
    parts = ['%x' % struct.unpack('>H', b[i:i + 2])[0] for i in range(0, 16, 2)]
    return ':'.join(parts)


def parse_tcp(data):
    if len(data) < 20:
        return None
    sport, dport, seq, ack = struct.unpack('>HHII', data[:12])
    off = (data[12] >> 4) * 4
    flags = data[13]
    if len(data) < off:
        return None
    return {'sport': sport, 'dport': dport, 'seq': seq, 'ack': ack,
            'flags': flags, 'payload': data[off:]}


def parse_udp(data):
    if len(data) < 8:
        return None
    sport, dport, ln = struct.unpack('>HHH', data[:6])
    return {'sport': sport, 'dport': dport, 'payload': data[8:ln] if ln >= 8 else data[8:]}


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def l4_packets(packets, linktype):
    """把链路层包拆成 (src, sport, dst, dport, proto, seq, flags, payload, ts, index)"""
    out = []
    for p in packets:
        if linktype == LINKTYPE_ETHERNET:
            nl, l4 = parse_ether(p.data)
        elif linktype == LINKTYPE_NULL:               # Loopback: 4字节地址族头
            af = struct.unpack('<I', p.data[:4])[0] if len(p.data) >= 4 else 2
            nl = 'ipv4' if af in (2, 0x02000000) else 'ipv6'
            l4 = p.data[4:]
        elif linktype == LINKTYPE_RAW:
            nl = 'ipv4' if len(p.data) > 0 and p.data[0] >> 4 == 4 else 'ipv6'
            l4 = p.data
        elif linktype == LINKTYPE_SLL:
            if len(p.data) < 16:
                continue
            et = struct.unpack('>H', p.data[14:16])[0]
            nl = {0x0800: 'ipv4', 0x86dd: 'ipv6'}.get(et)
            l4 = p.data[16:] if nl else b''
        else:
            continue
        if nl == 'ipv4':
            ip = parse_ipv4(l4)
        elif nl == 'ipv6':
            ip = parse_ipv6(l4)
        else:
            ip = None
        if not ip or ip['proto'] not in (6, 17):
            continue
        if ip['proto'] == 6:
            t = parse_tcp(ip['payload'])
            if not t:
                continue
            out.append((ip['src'], t['sport'], ip['dst'], t['dport'], 'tcp',
                        t['seq'], t['flags'], t['payload'], p.ts, p.index))
        else:
            u = parse_udp(ip['payload'])
            if not u:
                continue
            out.append((ip['src'], u['sport'], ip['dst'], u['dport'], 'udp',
                        0, 0, u['payload'], p.ts, p.index))
    return out


# ---------------------------------------------------------------------------
# TCP 流重组
# ---------------------------------------------------------------------------
class Stream(object):
    """一条 TCP 连接(双向)。client/server 为 (ip, port)。"""

    def __init__(self, client, server):
        self.client = client        # 先观测到的一侧(SYN 发起方优先)
        self.server = server
        self.packets = []           # (src, dst, seq, flags, payload, ts, idx)
                                    # src/dst 为 (ip, port) 元组

    def add(self, src, dst, seq, flags, payload, ts, idx):
        self.packets.append((src, dst, seq, flags, payload, ts, idx))

    def _stream_between(self, src):
        """重组 src -> 对端 方向的字节流(按 seq 排序、去重重传)。src 为 (ip,port)。"""
        segs = [(seq, payload) for (s, _d, seq, _f, payload, _ts, _i)
                in self.packets if s == src and payload]
        segs.sort(key=lambda x: x[0])
        buf = bytearray()
        expect = None
        for seq, payload in segs:
            if expect is None:
                expect = seq
            if seq < expect:                        # 重传/重叠
                skip = expect - seq
                if skip < len(payload):
                    buf += payload[skip:]
                    expect = seq + len(payload)
                continue
            if seq - expect > 0x100000:             # 序列号断裂过大
                buf += b'\n[?? gap ??]\n'
            elif seq > expect:
                buf += b'\x00' * (seq - expect)
            buf += payload
            expect = seq + len(payload)
        return bytes(buf)

    def client_stream(self):
        return self._stream_between(self.client)

    def server_stream(self):
        return self._stream_between(self.server)


def build_streams(packets, linktype):
    """返回 [Stream]。有 SYN 的连接以 SYN 发起方为 client,否则以观测到的第一侧。"""
    l4 = l4_packets(packets, linktype)
    streams = OrderedDict()
    for (src, sport, dst, dport, proto, seq, flags, payload, ts, idx) in l4:
        if proto != 'tcp':
            continue
        ck, sk = (src, sport), (dst, dport)
        skey = tuple(sorted([ck, sk]))
        st = streams.get(skey)
        if st is None:
            st = Stream(ck, sk)
            streams[skey] = st
        st.add(ck, sk, seq, flags, payload, ts, idx)
    for st in streams.values():
        syn_src = None
        for (src, _dst, _seq, flags, _payload, _ts, _i) in st.packets:
            if flags & SYN and not flags & ACK:
                syn_src = src
                break
        if syn_src and syn_src != st.client:
            st.client, st.server = st.server, st.client
    return list(streams.values())


# ---------------------------------------------------------------------------
# HTTP 解析
# ---------------------------------------------------------------------------
class HttpRequest(object):
    def __init__(self, method, path, headers, body, raw, ts=None, pkt=0):
        self.method, self.path = method, path
        self.headers = headers          # OrderedDict 小写key
        self.body = body
        self.raw = raw
        self.ts = ts
        self.pkt = pkt

    def header(self, name, default=''):
        return self.headers.get(name.lower(), default)

    def form(self):
        """解析 application/x-www-form-urlencoded 或 JSON -> dict"""
        try:
            from urllib.parse import parse_qs
            ct = self.header('content-type')
            if 'json' in ct:
                import json
                d = json.loads(self.body.decode('utf-8', 'replace'))
                return {k: str(v) for k, v in d.items()} if isinstance(d, dict) else {}
            d = {}
            for k, v in parse_qs(self.body.decode('utf-8', 'replace')).items():
                d[k] = v[0] if len(v) == 1 else v
            return d
        except Exception:
            return {}


class HttpResponse(object):
    def __init__(self, status, headers, body, raw, ts=None, pkt=0):
        self.status, self.headers = status, headers
        self.body = body
        self.raw = raw
        self.ts = ts
        self.pkt = pkt

    def header(self, name, default=''):
        return self.headers.get(name.lower(), default)


def _parse_headers(block):
    headers = OrderedDict()
    for line in block.split(b'\r\n'):
        if b':' in line:
            k, v = line.split(b':', 1)
            headers[k.decode('latin1').strip().lower()] = v.decode('latin1').strip()
    return headers


def _decode_body(body, headers):
    enc = headers.get('transfer-encoding', '').lower()
    if 'chunked' in enc:
        out = bytearray()
        rest = body
        while True:
            i = rest.find(b'\r\n')
            if i < 0:
                break
            try:
                size = int(rest[:i].split(b';')[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out += rest[i + 2:i + 2 + size]
            rest = rest[i + 2 + size + 2:]
        body = bytes(out)
    ce = headers.get('content-encoding', '').lower()
    if 'gzip' in ce:
        try:
            body = gzip.decompress(body)
        except Exception:
            pass
    elif 'deflate' in ce:
        try:
            body = zlib.decompress(body)
        except zlib.error:
            try:
                body = zlib.decompress(body, -zlib.MAX_WBITS)
            except Exception:
                pass
    return body


def parse_http_stream(data, is_request=None):
    """在字节流中迭代解析多个 HTTP 报文。
    返回 [HttpRequest|HttpResponse]。解析失败时尽力返回已解析部分。"""
    out = []
    pos = 0
    n = len(data)
    while pos < n:
        eol = data.find(b'\r\n', pos)
        if eol < 0:
            break
        line = data[pos:eol]
        if not line:
            pos = eol + 2
            continue
        parts = line.split(b' ')
        is_req = is_request
        if is_req is None:
            is_req = parts[0] in (b'GET', b'POST', b'PUT', b'DELETE', b'HEAD',
                                  b'OPTIONS', b'PATCH', b'CONNECT', b'TRACE')
        try:
            if is_req:
                method, path = parts[0].decode('latin1'), parts[1].decode('latin1')
                he = data.find(b'\r\n\r\n', pos)
                if he < 0:
                    break
                headers = _parse_headers(data[eol + 2:he])
                body_start = he + 4
                clen = headers.get('content-length')
                if 'chunked' in headers.get('transfer-encoding', '').lower():
                    body, nxt = _chunked_slice(data[body_start:])
                elif clen and clen.isdigit():
                    body_end = min(body_start + int(clen), n)
                    body, nxt = data[body_start:body_end], body_end
                else:
                    body, nxt = b'', body_start
                body = _decode_body(body, headers)
                out.append(HttpRequest(method, path, headers, body,
                                       data[pos:nxt], None))
                pos = nxt
            else:
                code = parts[1].decode('latin1') if len(parts) > 1 else ''
                he = data.find(b'\r\n\r\n', pos)
                if he < 0:
                    break
                headers = _parse_headers(data[eol + 2:he])
                body_start = he + 4
                clen = headers.get('content-length')
                if 'chunked' in headers.get('transfer-encoding', '').lower():
                    body, nxt = _chunked_slice(data[body_start:])
                elif clen and clen.isdigit():
                    body_end = min(body_start + int(clen), n)
                    body, nxt = data[body_start:body_end], body_end
                else:
                    # 无 Content-Length:到下一个 HTTP 响应或流结束
                    nxt = _find_next_response(data, body_start)
                    body = data[body_start:nxt]
                body = _decode_body(body, headers)
                out.append(HttpResponse(code, headers, body, data[pos:nxt], None))
                pos = nxt
        except Exception:
            pos = eol + 2
    return out


def _chunked_slice(data):
    """chunked 编码:返回 (解码后 body, 结束位置)"""
    out = bytearray()
    pos = 0
    while True:
        i = data.find(b'\r\n', pos)
        if i < 0:
            break
        try:
            size = int(data[pos:i].split(b';')[0], 16)
        except ValueError:
            break
        if size == 0:
            pos = i + 2
            break
        out += data[i + 2:i + 2 + size]
        pos = i + 2 + size + 2
    return bytes(out), pos


def _find_next_response(data, start):
    """无 Content-Length 时猜测响应体结束位置。"""
    for pat in (b'\r\nHTTP/1.1 ', b'\r\nHTTP/1.0 ', b'\r\nGET ', b'\r\nPOST '):
        i = data.find(pat, start)
        if i >= 0:
            return i + 2
    return len(data)


def iter_http(packets, linktype, ports=(80, 8080, 8000, 8081, 4430)):
    """yields (stream_no, HttpRequest|HttpResponse, stream)"""
    for i, st in enumerate(build_streams(packets, linktype)):
        cport, sport = st.client[1], st.server[1]
        if not (cport in ports or sport in ports):
            continue
        for m in parse_http_stream(st.client_stream(), is_request=True):
            yield i, m, st
        for r in parse_http_stream(st.server_stream(), is_request=False):
            if isinstance(r, HttpResponse):
                yield i, r, st


# ---------------------------------------------------------------------------
# USB(HID) 数据提取
# ---------------------------------------------------------------------------
class USBRec(object):
    __slots__ = ('ts', 'index', 'dev', 'ep', 'xfer', 'dir_in', 'data')

    def __init__(self, ts, index, dev, ep, xfer, dir_in, data):
        self.ts, self.index, self.dev, self.ep = ts, index, dev, ep
        self.xfer, self.dir_in, self.data = xfer, dir_in, data

    def __repr__(self):
        return '<USBRec pkt=%d dev=%d ep=0x%02x xfer=%d dir=%s data=%s>' % (
            self.index, self.dev, self.ep, self.xfer, 'IN' if self.dir_in else 'OUT',
            self.data.hex())


def iter_usb(packets, linktype):
    """从 usbmon(220)/USBPcap(249) 流量中提取带数据的 USB 记录。"""
    for p in packets:
        if linktype == LINKTYPE_USB_LINUX:
            r = _parse_usb_linux(p)
        elif linktype == LINKTYPE_USBPCAP:
            r = _parse_usbpcap(p)
        else:
            return
        if r is not None:
            yield r


def _parse_usb_linux(p):
    """Linux usbmon 64 字节头(前 40 字节为固定字段)。"""
    if len(p.data) < 64:
        return None
    (urb_id, pkt_type, xfer_type, epnum, devnum, busnum,
     flag_setup, flag_data, ts_sec, ts_usec, status,
     length, len_cap) = struct.unpack('<QBBBbHBBqiiII', p.data[:40])
    # usbmon 数据标志: 0x00/0x3d('=')完整数据 0x3c('<')截断数据 0x3e('>')无数据
    if len_cap == 0 or flag_data == 0x3e:
        return None
    data = p.data[64:64 + len_cap]
    return USBRec(ts_sec + ts_usec / 1e6, p.index, devnum, epnum,
                  xfer_type, bool(epnum & 0x80), data)


def _parse_usbpcap(p):
    """USBPcap 27 字节头(+可选 ISO 头)。"""
    if len(p.data) < 27:
        return None
    hdr_len, = struct.unpack('<H', p.data[:2])
    if hdr_len < 27 or hdr_len > len(p.data):
        return None
    info, = struct.unpack('<B', p.data[16:17])
    endpoint, = struct.unpack('<B', p.data[21:22])
    xfer, = struct.unpack('<B', p.data[22:23])
    dlen, = struct.unpack('<I', p.data[23:27])
    devnum = struct.unpack('<H', p.data[19:21])[0]
    if dlen == 0 or len(p.data) < hdr_len + dlen:
        return None
    data = p.data[hdr_len:hdr_len + dlen]
    dir_in = bool(endpoint & 0x80)
    return USBRec(p.ts, p.index, devnum, endpoint, xfer, dir_in, data)


# ---------------------------------------------------------------------------
# HID 键位表
# ---------------------------------------------------------------------------
HID_KEYMAP = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f',
    0x0a: 'g', 0x0b: 'h', 0x0c: 'i', 0x0d: 'j', 0x0e: 'k', 0x0f: 'l',
    0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r',
    0x16: 's', 0x17: 't', 0x18: 'u', 0x19: 'v', 0x1a: 'w', 0x1b: 'x',
    0x1c: 'y', 0x1d: 'z',
    0x1e: '1', 0x1f: '2', 0x20: '3', 0x21: '4', 0x22: '5', 0x23: '6',
    0x24: '7', 0x25: '8', 0x26: '9', 0x27: '0',
    0x28: '\n', 0x29: '[ESC]', 0x2a: '[BKSP]', 0x2b: '\t', 0x2c: ' ',
    0x2d: '-', 0x2e: '=', 0x2f: '[', 0x30: ']', 0x31: '\\',
    0x33: ';', 0x34: "'", 0x35: '`', 0x36: ',', 0x37: '.', 0x38: '/',
    0x4f: '[RIGHT]', 0x50: '[LEFT]', 0x51: '[DOWN]', 0x52: '[UP]',
}
HID_SHIFTMAP = {
    0x04: 'A', 0x05: 'B', 0x06: 'C', 0x07: 'D', 0x08: 'E', 0x09: 'F',
    0x0a: 'G', 0x0b: 'H', 0x0c: 'I', 0x0d: 'J', 0x0e: 'K', 0x0f: 'L',
    0x10: 'M', 0x11: 'N', 0x12: 'O', 0x13: 'P', 0x14: 'Q', 0x15: 'R',
    0x16: 'S', 0x17: 'T', 0x18: 'U', 0x19: 'V', 0x1a: 'W', 0x1b: 'X',
    0x1c: 'Y', 0x1d: 'Z',
    0x1e: '!', 0x1f: '@', 0x20: '#', 0x21: '$', 0x22: '%', 0x23: '^',
    0x24: '&', 0x25: '*', 0x26: '(', 0x27: ')',
    0x2d: '_', 0x2e: '+', 0x2f: '{', 0x30: '}', 0x31: '|',
    0x33: ':', 0x34: '"', 0x35: '~', 0x36: '<', 0x37: '>', 0x38: '?',
}


def decode_hid_keyboard(data):
    """8 字节键盘报告 -> (字符 或 None)。兼容 1 字节 Report ID 前缀。"""
    if len(data) < 8:
        return None
    if len(data) > 8:
        data = data[:8]
    mod = data[0]
    keys = data[2:8]
    shift = bool(mod & 0x22)          # 左Shift(0x02) 或 右Shift(0x20)
    out = []
    for k in keys:
        if k == 0:
            continue
        if shift:
            out.append(HID_SHIFTMAP.get(k, HID_KEYMAP.get(k, '')))
        else:
            out.append(HID_KEYMAP.get(k, ''))
    return ''.join(out) if out else None


# ---------------------------------------------------------------------------
# tshark 可选增强
# ---------------------------------------------------------------------------
_TSHARK_CANDIDATES = [
    r'C:\Program Files\Wireshark\tshark.exe',
    r'C:\Program Files (x86)\Wireshark\tshark.exe',
    '/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark',
]


def find_tshark():
    for p in _TSHARK_CANDIDATES:
        if os.path.exists(p):
            return p
    from shutil import which
    return which('tshark')


def tshark_fields(pcap, fields, display_filter='', opts=()):
    """调用 tshark 提取字段。返回 [tuple(str,...)];tshark 不可用返回 None。"""
    exe = find_tshark()
    if not exe:
        return None
    cmd = [exe, '-r', pcap, '-Y', display_filter] if display_filter else [exe, '-r', pcap]
    for f in fields:
        cmd += ['-e', f]
    cmd += ['-T', 'fields'] + list(opts)
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=300)
        rows = []
        for line in out.stdout.decode('utf-8', 'replace').splitlines():
            rows.append(tuple(line.split('\t')))
        return rows
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 工具:flag 搜索 / 打印
# ---------------------------------------------------------------------------
FLAG_RE = re.compile(
    r'(?:flag|ctf|FLAG|CTF|key)\{[^}\n]{1,80}\}|[fF][lL1][aA@][gG]\{[^}\n]{1,80}\}')


def find_flags(text):
    """在任意 bytes/str 中搜 flag。返回去重列表。"""
    if isinstance(text, bytes):
        text = text.decode('latin1', 'replace')
    seen, out = set(), []
    for m in FLAG_RE.finditer(text):
        if m.group(0) not in seen:
            seen.add(m.group(0))
            out.append(m.group(0))
    return out


def printable(data, keep_newline=True):
    """bytes -> 可读字符串(不可见字符用 . 表示)"""
    out = []
    for b in data:
        if 32 <= b < 127:
            out.append(chr(b))
        elif b in (0x0a, 0x0d) and keep_newline:
            out.append('\n' if b == 0x0a else '')
        elif b == 0x09:
            out.append('\t')
        else:
            out.append('.')
    return ''.join(out)


def shorten(s, n=100):
    s = s if isinstance(s, str) else printable(s)
    s = s.replace('\n', '\\n').replace('\r', '')
    return s if len(s) <= n else s[:n] + '...'


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('用法: python pcaplib.py <pcap>   # 快速查看流量概况')
        sys.exit(0)
    lt, pkts = read_pcap(sys.argv[1])
    print('文件: %s' % sys.argv[1])
    print('链路层: %s, 包数: %d' % (get_linktype_name(lt), len(pkts)))
    if lt in (LINKTYPE_USB_LINUX, LINKTYPE_USBPCAP):
        usb = list(iter_usb(pkts, lt))
        print('USB 数据记录: %d 条' % len(usb))
    else:
        ss = build_streams(pkts, lt)
        print('TCP 流: %d 条' % len(ss))
