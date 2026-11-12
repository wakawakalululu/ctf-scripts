# -*- coding: utf-8 -*-
"""
pcapfix.py — CTF 流量包修复(对应题型:流量包修复)

解决 wireshark 打开报"包异常/文件损坏"的问题,常见原因:
  1. 全局头魔数被破坏(如 find the flag 题)
  2. 文件尾部最后一个包被截断
  3. 字节序/分辨率字段异常

用法:
  python pcapfix.py broken.cap            # 输出 broken_fixed.pcap
  python pcapfix.py broken.cap fixed.cap  # 指定输出文件

原理:校验全局头 -> 逐包校验(长度字段超界即视为截断) -> 丢弃残缺尾包 -> 重写合法头。
"""
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

GOOD_MAGICS = (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1',
               b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1')


def fix_pcap(src, dst):
    with open(src, 'rb') as f:
        data = f.read()

    problems = []

    # ---- 1. 恢复全局头 ----
    if len(data) >= 4 and data[:4] in GOOD_MAGICS:
        magic = data[:4]
    else:
        problems.append('全局头魔数损坏 (%s...), 已重建' % data[:4].hex())
        magic = b'\xd4\xc3\xb2\xa1'          # 小端 usec,最常见

    # 从原文件里尽量保留 snaplen / linktype
    if len(data) >= 24 and data[:4] in GOOD_MAGICS:
        _m, vmaj, vmin, _tz, _sig, snap, link = struct.unpack('<4sHHiIII', data[:24])
    else:
        # 魔数坏了,后面的字段也可能错位:扫描前 64 字节找像 linktype 的值
        vmaj, vmin, snap, link = 2, 4, 262144, _guess_linktype(data)
        problems.append('链路层类型按启发式判定为 %s' % pcaplib.get_linktype_name(link))

    if snap == 0 or snap > 0x400000:
        snap = 262144
        problems.append('snaplen 异常, 已改为 262144')

    # ---- 2. 逐包扫描,丢弃残缺尾包 ----
    off = 24
    kept = 0
    dropped = 0
    body = bytearray()
    n = len(data)
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    while off + 16 <= n:
        ts_sec, ts_sub, caplen, wirelen = struct.unpack(endian + 'IIII', data[off:off + 16])
        ok = (caplen <= 0x400000 and caplen > 0 and
              wirelen <= 0x400000 and off + 16 + caplen <= n)
        if not ok:
            dropped += 1
            problems.append('第 %d 个包数据不完整(caplen=%d, 文件仅剩 %d 字节), 已丢弃截断部分'
                            % (kept + 1, caplen, n - off - 16))
            break
        body += data[off:off + 16 + caplen]
        kept += 1
        off += 16 + caplen

    if dropped == 0 and off < n and n - off > 0:
        dropped += 1
        problems.append('尾部残留 %d 字节垃圾数据, 已丢弃' % (n - off))

    # ---- 3. 重写全局头(统一为小端 usec) ----
    header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, link)
    with open(dst, 'wb') as f:
        f.write(header + bytes(body))

    return kept, problems, link


def _guess_linktype(data):
    """魔数损坏时,在文件头部寻找像 linktype 的小整数。"""
    if len(data) < 24:
        return pcaplib.LINKTYPE_ETHERNET
    for endian in ('<', '>'):
        lt = struct.unpack(endian + 'I', data[20:24])[0]
        if lt in pcaplib.DLT_NAMES:
            return lt
    return pcaplib.LINKTYPE_ETHERNET


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.splitext(src)[0] + '_fixed.pcap'

    print('[*] 修复前尝试解析: ', end='')
    try:
        lt, pkts = pcaplib.read_pcap(src)
        print('居然能直接读出 %d 个包(可能只是头部小问题)' % len(pkts))
    except Exception as e:
        print('失败 -> %s' % e)

    kept, problems, link = fix_pcap(src, dst)
    print('[*] 修复结果: 保留 %d 个包, 链路层 %s' % (kept, pcaplib.get_linktype_name(link)))
    if problems:
        print('[*] 修复动作:')
        for p in problems:
            print('    - %s' % p)
    else:
        print('[*] 未发现明显损坏, 已规范化重写')

    # 验证
    try:
        lt, pkts = pcaplib.read_pcap(dst)
        print('[+] 验证通过: %s 可正常解析, 共 %d 个包' % (dst, len(pkts)))
    except Exception as e:
        print('[-] 验证失败: %s' % e)
        sys.exit(1)

    print('[*] 请用 wireshark 打开 %s 继续分析' % dst)
    # 顺手做一次 flag 搜索
    with open(dst, 'rb') as f:
        raw = f.read()
    flags = pcaplib.find_flags(raw)
    if flags:
        print('[+] 修复后的文件里直接搜到 flag: %s' % ', '.join(flags))


if __name__ == '__main__':
    main()
