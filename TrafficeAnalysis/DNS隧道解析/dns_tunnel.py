# -*- coding: utf-8 -*-
"""dns_tunnel.py — DNS 隧道数据提取(流量分析高频题型)

用途: 从 pcap 提取 DNS 查询子域名/TXT 应答并拼接解码:
      1. 收集所有 UDP:53 查询的 qname 标签(剥离常规域名后缀);
      2. TXT 应答文本一并提取(应答常回传解码后的 flag);
      3. 拼接结果自动尝试 hex/base32/base64/raw 解码输出。
      本地 pcaplib 解析(免 tshark), 与 solve.py 各脚本同一套接口。

依赖:
    仅标准库 + 本目录 pcaplib

用法:
    python dns_tunnel.py tunnel.pcap                 # 提取+自动解码
    python dns_tunnel.py tunnel.pcap --suffix data.com   # 指定剥离后缀
    python dns_tunnel.py tunnel.pcap --raw           # 只打印原始查询
    python dns_tunnel.py --selftest                  # 内置自测
"""
import argparse
import base64
import binascii
import io
import os
import re
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pcaplib


def _skip_name(data, off):
    """跳过 DNS 报文中的域名(支持压缩指针), 返回(标签列表, 新偏移)。"""
    labels = []
    while off < len(data):
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if (ln & 0xC0) == 0xC0:        # 压缩指针
            off += 2
            return labels, off
        labels.append(data[off + 1:off + 1 + ln])
        off += 1 + ln
    return labels, off


def parse_dns(payload):
    """解析 DNS 报文 -> (queries[qname], txts[文本])。"""
    if len(payload) < 12:
        return [], []
    qd, an = int.from_bytes(payload[4:6], 'big'), int.from_bytes(payload[6:8], 'big')
    queries, txts = [], []
    off = 12
    for _ in range(qd):
        labels, off = _skip_name(payload, off)
        queries.append('.'.join(l.decode('latin1') for l in labels))
        if off + 4 > len(payload):                # 报文被截断: 保留已解析部分
            return queries, txts
        off += 4                                  # qtype + qclass
    for _ in range(an):
        _, off = _skip_name(payload, off)
        if off + 10 > len(payload):
            return queries, txts
        rtype = int.from_bytes(payload[off:off + 2], 'big')
        rdlen = int.from_bytes(payload[off + 8:off + 10], 'big')
        rdata = payload[off + 10:off + 10 + rdlen]
        off += 10 + rdlen
        if rtype == 16 and rdlen >= 1:            # TXT 记录
            p = 0
            while p < len(rdata):
                tl = rdata[p]
                txts.append(rdata[p + 1:p + 1 + tl].decode('latin1', 'replace'))
                p += 1 + tl
    return queries, txts


def collect(path):
    linktype, packets = pcaplib.read_pcap(path)
    queries, txts = [], []
    for src, sport, dst, dport, proto, seq, flags, payload, ts, idx in \
            pcaplib.l4_packets(packets, linktype):
        if dport == 53 or sport == 53:
            q, t = parse_dns(payload)
            queries.extend(q)
            txts.extend(t)
    return queries, txts


def strip_suffix(labels, suffix):
    """剥离域名后缀, 返回数据标签列表。"""
    out = []
    for q in labels:
        parts = q.split('.')
        if suffix:
            if q.endswith(suffix):
                parts = parts[:len(parts) - suffix.count('.') - 1]
            else:
                continue
        else:
            parts = parts[:-2] if len(parts) > 2 else parts  # 默认剥最后两段
        s = ''.join(parts)
        if s:
            out.append(s)
    return out


def try_decode(s):
    """对拼接字符串尝试 hex/base32/base64/raw 多种解码。"""
    cands = []
    body = ''.join(s.split())
    if body and re.fullmatch(r'[0-9a-fA-F]+', body) and len(body) % 2 == 0:
        try:
            cands.append(('hex', binascii.unhexlify(body).decode('utf-8', 'replace')))
        except ValueError:
            pass
    for name, fn, unit in (('base32', base64.b32decode, 8),
                           ('base64', base64.b64decode, 4)):
        try:
            dec = fn(body + '=' * (-len(body) % unit))
            if dec:
                cands.append((name, dec.decode('utf-8', 'replace')))
        except (binascii.Error, ValueError):
            pass
    cands.append(('raw', s))
    return cands


def selftest():
    """内存构造含 base32 隧道标签的 DNS 查询 pcap, 走完整提取/解码链。"""
    data_label = base64.b32encode(b'flag{dns_ok}').decode().rstrip('=').lower()
    qname = b''
    for label in (data_label.encode(), b'data', b'ctf', b'local'):
        qname += bytes([len(label)]) + label
    qname += b'\x00'                              # 域名终止符
    dns = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack('>HH', 16, 1)
    udp = struct.pack('>HHHH', 40000, 53, 8 + len(dns), 0) + dns
    ip = (struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0)
          + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2]))
    eth = bytes.fromhex('001122334455') + bytes.fromhex('66778899aabb') + b'\x08\x00'
    pkt = eth + ip + udp
    fd, path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))   # 全局头
        f.write(struct.pack('<IIII', 1, 0, len(pkt), len(pkt)))              # 记录头
        f.write(pkt)
    queries, txts = collect(path)
    os.unlink(path)
    labels = strip_suffix(queries, 'data.ctf.local')
    cands = dict(try_decode(''.join(labels).upper()))
    ok = 'flag{dns_ok}' in cands.get('base32', '') or 'flag{dns_ok}' in cands.get('raw', '')
    print('DNS 隧道子域名提取/解码:', 'OK' if ok else 'FAIL (%r %r)' % (labels, cands))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='DNS 隧道数据提取')
    ap.add_argument('pcap', nargs='?', help='pcap 文件')
    ap.add_argument('--suffix', help='剥离的域名后缀(如 data.example.com)')
    ap.add_argument('--raw', action='store_true', help='只打印原始查询')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.pcap:
        ap.error('需要 pcap 文件(或 --selftest)')
    queries, txts = collect(args.pcap)
    print('共 %d 个 DNS 查询, %d 条 TXT 应答' % (len(queries), len(txts)))
    if txts:
        print('== TXT 应答 ==')
        for t in txts[:20]:
            print('  %r' % t)
    labels = strip_suffix(queries, args.suffix)
    if args.raw or not labels:
        for q in queries[:40]:
            print('  %s' % q)
        if len(queries) > 40:
            print('  ... 共 %d 条' % len(queries))
        return
    joined = ''.join(labels)
    print('== 拼接标签(%d 个) ==\n%s' % (len(labels), joined[:200]))
    for name, text in try_decode(joined):
        print('-- %s 解码: %r' % (name, text[:300]))


if __name__ == '__main__':
    main()
