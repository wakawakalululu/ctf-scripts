# -*- coding: utf-8 -*-
"""icmp_data.py — 提取 ICMP echo 数据(纯标准库, 不依赖 scapy/tshark)

用途: ICMP 隐写/传 flag 题型: echo request/reply 的 payload 里藏数据。
      逐包打印 (序号, 方向, 源->目的, type, id, seq, payload);
      自动拼接全部 payload 并正则搜索 flag; --save 导出拼接二进制。
      与 TrafficeAnalysis/流量数据提取脚本/1.py(scapy 版)互补: 本脚本零依赖,
      支持链路层 Ethernet/Loopback/Raw/SLL(含 VLAN)。

用法:
    python icmp_data.py x.pcap                  # 逐包 + 拼接 + flag 搜索
    python icmp_data.py x.pcap --save out.bin   # 拼接 payload 落盘(常为 zip/图片)
    python icmp_data.py x.pcap --hex            # 额外打印 payload hexdump
    python icmp_data.py --selftest              # 内置构造流量自测
"""
import os
import struct
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pcaplib

ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST = 0, 8
TYPE_NAME = {0: 'echo-reply', 3: 'dest-unreach', 8: 'echo-request',
             9: 'router-adv', 11: 'time-exceeded', 13: 'timestamp'}


def strip_link(data, linktype):
    """链路层剥头 -> (网络层协议名, 载荷)。与 pcaplib.l4_packets 的分支保持一致。"""
    if linktype == pcaplib.LINKTYPE_ETHERNET:
        return pcaplib.parse_ether(data)
    if linktype == pcaplib.LINKTYPE_NULL:                    # loopback 4 字节族头
        af = struct.unpack('<I', data[:4])[0] if len(data) >= 4 else 2
        return ('ipv4' if af in (2, 0x02000000) else 'ipv6'), data[4:]
    if linktype == pcaplib.LINKTYPE_RAW:
        return ('ipv4' if data and data[0] >> 4 == 4 else 'ipv6'), data
    if linktype == pcaplib.LINKTYPE_SLL:
        if len(data) < 16:
            return None, b''
        et = struct.unpack('>H', data[14:16])[0]
        return {0x0800: 'ipv4', 0x86dd: 'ipv6'}.get(et), (data[16:] if et in (0x0800, 0x86dd) else b'')
    return None, b''


def extract(path):
    """返回 [(index, ts, src, dst, icmp_type, ident, seq, payload_bytes), ...]"""
    lt, pkts = pcaplib.read_pcap(path)
    rows = []
    for p in pkts:
        nl, l4 = strip_link(p.data, lt)
        if nl != 'ipv4':
            continue
        ip = pcaplib.parse_ipv4(l4)
        if not ip or ip['proto'] != 1:                       # IPPROTO_ICMP
            continue
        body = ip['payload']
        if len(body) < 8:
            continue
        itype, code = body[0], body[1]
        ident, seq = struct.unpack('>HH', body[4:8])
        # echo request/reply 的 payload 在 8 字节 ICMP 头之后; 其他类型 header 长度不同
        payload = body[8:] if itype in (ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY) else b''
        rows.append((p.index, p.ts, ip['src'], ip['dst'], itype, ident, seq, payload))
    return rows


def hexdump(b, limit=64):
    out = []
    for i in range(0, min(len(b), limit), 16):
        chunk = b[i:i + 16]
        out.append('    %04x  %-47s  %s' % (
            i, ' '.join('%02x' % c for c in chunk),
            ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)))
    if len(b) > limit:
        out.append('    ...(共 %d 字节)' % len(b))
    return '\n'.join(out)


def run(path, save, show_hex):
    rows = extract(path)
    if not rows:
        print('[!] 未发现 ICMP echo 包(可用 wireshark 过滤 icmp 确认)')
        return []
    print('[*] ICMP echo 包: %d 个' % len(rows))
    blob = b''
    for idx, ts, src, dst, itype, ident, seq, payload in rows:
        arrow = '%s -> %s' % (src, dst)
        print('  #%-5d %-34s %-12s id=%-5d seq=%-5d len=%d' % (
            idx, arrow, TYPE_NAME.get(itype, 'type-%d' % itype), ident, seq, len(payload)))
        if payload:
            txt = pcaplib.printable(payload).rstrip()
            if txt:
                print('        | %s' % pcaplib.shorten(txt, 100))
            if show_hex:
                print(hexdump(payload))
        blob += payload
    flags = pcaplib.find_flags(blob)
    for f in flags:
        print('[+] flag: %s' % f)
    if save:
        with open(save, 'wb') as f:
            f.write(blob)
        print('[+] 已保存拼接 payload %d 字节 -> %s' % (len(blob), save))
    return flags


# ---------------- selftest: 内存构造 pcap 再解析 ----------------
def _mk_ip_icmp(src, dst, itype, ident, seq, payload):
    total = 20 + 8 + len(payload)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, total, 0, 0, 64, 1, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    icmp = struct.pack('>BBHHH', itype, 0, 0, ident, seq) + payload
    return ip + icmp


def _wrap_link(lt, l3):
    """按链路层类型给 L3 包加头。"""
    if lt == pcaplib.LINKTYPE_ETHERNET:
        return b'\x00' * 6 + b'\x11' * 6 + struct.pack('>H', 0x0800) + l3
    if lt == pcaplib.LINKTYPE_NULL:
        return struct.pack('<I', 2) + l3                      # AF_INET
    if lt == pcaplib.LINKTYPE_RAW:
        return l3
    if lt == pcaplib.LINKTYPE_SLL:                            # 16 字节头: type/arphrd/halen/addr/proto
        return struct.pack('>HHH', 0, 1, 6) + b'\x00' * 8 + struct.pack('>H', 0x0800) + l3
    raise ValueError(lt)


def _mk_pcap(linktype, pkts):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
    for i, pkt in enumerate(pkts):
        out += struct.pack('<IIII', 1700000000 + i, 0, len(pkt), len(pkt)) + pkt
    return out


def selftest():
    import tempfile
    flag = b'flag{icmp_hidden_data_123}'
    data = flag + b'PART2:' + b'\x50\x4b\x03\x04ziphead'
    req = _mk_ip_icmp('10.0.0.1', '10.0.0.2', ICMP_ECHO_REQUEST, 0x1234, 1,
                      data[:len(data) // 2])
    rep = _mk_ip_icmp('10.0.0.2', '10.0.0.1', ICMP_ECHO_REPLY, 0x1234, 1,
                      data[len(data) // 2:])
    for lt in (pcaplib.LINKTYPE_ETHERNET, pcaplib.LINKTYPE_NULL,
               pcaplib.LINKTYPE_RAW, pcaplib.LINKTYPE_SLL):
        path = os.path.join(tempfile.gettempdir(), 'icmp_selftest.pcap')
        with open(path, 'wb') as f:
            f.write(_mk_pcap(lt, [_wrap_link(lt, req), _wrap_link(lt, rep)]))
        rows = extract(path)
        blob = b''.join(r[7] for r in rows)
        assert len(rows) == 2, '解析包数错误 linktype=%d' % lt
        assert blob == data, 'payload 拼接不一致 linktype=%d: %r' % (lt, blob)
        assert pcaplib.find_flags(blob) == ['flag{icmp_hidden_data_123}']
        os.remove(path)
    print('[OK] icmp_data.py 自测: 4 种链路层类型构造/解析/拼接/flag 全部一致')
    return 0


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, 'samples', 'icmp_flag.pcap'),
                 os.path.join(here, '..', 'files', 'capture.pcap')):
        if os.path.exists(cand):
            return cand
    return None


def main():
    ap = argparse.ArgumentParser(description='ICMP echo 数据提取(纯标准库)')
    ap.add_argument('pcap', nargs='?', default=None, help='pcap/cap 文件')
    ap.add_argument('--save', help='拼接 payload 保存为文件')
    ap.add_argument('--hex', action='store_true', help='打印 payload hexdump')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    path = args.pcap or default_sample()
    if not path or not os.path.exists(path):
        print('用法: python icmp_data.py <icmp.pcap> [--save out.bin --hex]')
        return 1
    run(path, args.save, args.hex)
    return 0


if __name__ == '__main__':
    sys.exit(main())
