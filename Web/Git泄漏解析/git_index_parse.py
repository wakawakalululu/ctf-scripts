# -*- coding: utf-8 -*-
"""git index(.git/index) 解析 — Git 泄露恢复辅助(py3 完善版)

来源: https://github.com/wilesanGH/ctf-web (md_docs/Git工具大全.md 内嵌脚本, 已完善:
     修正条目 NUL 填充计算、支持 SHA 展示与校验和验证)
用途: Misc/Web 题 —— .git 泄露只剩 index 文件时, 恢复被跟踪的文件路径与对象哈希,
     指导后续按 sha 从 objects/ 恢复源码。

依赖:
    无(纯标准库)

用法:
    python git_index_parse.py --selftest               # 自测(构造最小 index)
    python git_index_parse.py .git/index               # 列出路径
    python git_index_parse.py .git/index --sha         # 同时显示对象 SHA
    python git_index_parse.py .git/index --check       # 校验 SHA1 校验和
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys

ENTRY_FIXED = 62   # ctime8 + mtime8 + dev4 + ino4 + mode4 + uid4 + gid4 + size4 + sha20 + flags2


def parse_index(data: bytes, check: bool = False):
    """解析 index, 返回 (版本, [(path, sha_hex), ...]); check=True 时校验 SHA1 校验和。"""
    if len(data) < 12 + 20:
        raise ValueError('文件太小, 不像 git index')
    if data[:4] != b'DIRC':
        raise ValueError('魔数不是 DIRC, 不是 git index 文件')
    version = struct.unpack('>I', data[4:8])[0]
    count = struct.unpack('>I', data[8:12])[0]
    if version not in (2, 3):
        raise ValueError(f'不支持的 index 版本: {version}(本工具支持 2/3)')

    if check:
        body, checksum = data[:-20], data[-20:]
        if hashlib.sha1(body).digest() != checksum:
            raise ValueError('SHA1 校验和不匹配(文件被截断或损坏)')

    entries = []
    off = 12
    for _ in range(count):
        fixed = data[off:off + ENTRY_FIXED]
        if len(fixed) < ENTRY_FIXED:
            raise ValueError(f'条目在 offset {off} 处被截断')
        flags = struct.unpack('>H', fixed[60:62])[0]
        path_len = flags & 0xFFF
        sha_hex = fixed[40:60].hex()
        # 路径紧跟 62 字节定长区(flags 低 12 位为路径长度)
        consumed = ENTRY_FIXED + path_len
        path = data[off + ENTRY_FIXED: off + consumed].decode('utf-8', errors='replace')
        entries.append((path, sha_hex))
        # NUL 终止 + 填充到 8 字节边界(至少 1 个 NUL) —— 修正原版 pad=0 时漂移
        pad = 8 - (consumed % 8)
        if pad == 0:
            pad = 8
        off += consumed + pad
    return version, entries


def make_test_index(paths):
    """构造最小 v2 index(自测用)。"""
    body = b'DIRC' + struct.pack('>II', 2, len(paths))
    for p in paths:
        pb = p.encode()
        flags = min(len(pb), 0xFFF)
        entry = (b'\x00' * 40                      # ctime/mtime/dev/ino/mode/uid/gid/size
                 + hashlib.sha1(p.encode()).digest()  # sha
                 + struct.pack('>H', flags)
                 + pb)
        pad = 8 - (len(entry) % 8)
        if pad == 0:
            pad = 8
        entry += b'\x00' * pad
        body += entry
    return body + hashlib.sha1(body).digest()


def main():
    ap = argparse.ArgumentParser(description='.git/index 解析')
    ap.add_argument('file', nargs='?')
    ap.add_argument('--sha', action='store_true', help='显示对象 SHA')
    ap.add_argument('--check', action='store_true', help='验证 SHA1 校验和')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        paths = ['a', 'ab', 'flag.php', 'src/app/index.html', 'x' * 100]
        data = make_test_index(paths)
        version, entries = parse_index(data, check=True)
        got = [p for p, _ in entries]
        good = got == paths and version == 2
        ok = good
        print(f"[{'OK' if good else 'FAIL'}] 版本={version} 条目: {got}")
        good2 = all(len(s) == 40 for _, s in entries)
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] SHA 长度: {[s[:8] + '..' for _, s in entries]}")
        # 损坏检测: 改动最后一个字节后校验应失败
        corrupted = data[:-1] + bytes([data[-1] ^ 0xFF])
        try:
            parse_index(corrupted, check=True)
            bad_detected = False
        except ValueError:
            bad_detected = True
        ok &= bad_detected
        print(f"[{'OK' if bad_detected else 'FAIL'}] 校验和损坏检测")
        sys.exit(0 if ok else 1)

    if not args.file:
        ap.error('需要 index 文件路径(或 --selftest)')
    with open(args.file, 'rb') as f:
        data = f.read()
    version, entries = parse_index(data, check=args.check)
    print(f'版本: {version}  条目: {len(entries)}')
    for path, sha in entries:
        print(f'  {sha[:12] if args.sha else "":14s}{path}')


if __name__ == '__main__':
    main()
