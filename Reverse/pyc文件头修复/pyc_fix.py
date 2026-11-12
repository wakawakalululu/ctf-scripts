# -*- coding: utf-8 -*-
"""pyc 文件头修复(补充题型: Reverse/pyc)

用途:
    CTF 常见: pyc 头 8/12/16 字节被删或改坏, uncompyle6/decompyle3 打不开。
    本脚本: 1) 按版本表自动补 pyc 头  2) 自动探测头长度与版本  3) 修复后可直接反编译

头结构:
    Py2.7        : magic(4) + mtime(4)                 = 8 字节
    Py3.0~3.6    : magic(4) + mtime(4) + size(4)       = 12 字节
    Py3.7+       : magic(4) + flags(4) + mtime(4) + size(4) = 16 字节

依赖:
    纯标准库。反编译用: pip install uncompyle6 decompyle3 (3.8-)
    Py3.9+ 可用 pycdc (Decompyle++)。

用法:
    python pyc_fix.py <坏pyc> -o fixed.pyc --ver 3.8   # 指定版本修复
    python pyc_fix.py <坏pyc>                          # 自动探测版本与头长
    python pyc_fix.py                                  # 自测
"""
from __future__ import annotations

import argparse
import importlib.util
import marshal
import struct
import sys
import time

# magic number(2字节LE) -> python 版本; bytes = LE16(magic) + b'\x0d\x0a'
PY_MAGIC = {
    '2.7': 0xF303,
    '3.5': 0x0D17, '3.6': 0x0D33, '3.7': 0x0D42, '3.8': 0x0D55,
    '3.9': 0x0D61, '3.10': 0x0D6F, '3.11': 0x0DA7, '3.12': 0x0DCB,
    '3.13': 0x0DF3,
}


def magic_bytes(ver: str) -> bytes:
    return struct.pack('<H', PY_MAGIC[ver]) + b'\x0d\x0a'


def header_for(ver: str, src_size: int = 0, mtime: int | None = None) -> bytes:
    """按版本生成完整 pyc 头。ver='current' 表示当前解释器版本。"""
    if mtime is None:
        mtime = int(time.time())
    if ver == 'current':
        magic = importlib.util.MAGIC_NUMBER
        if sys.version_info >= (3, 7):
            return magic + struct.pack('<III', 0, mtime, src_size)
        return magic + struct.pack('<II', mtime, src_size)
    if ver == '2.7':
        return magic_bytes(ver) + struct.pack('<I', mtime)
    if ver in ('3.5', '3.6'):
        return magic_bytes(ver) + struct.pack('<II', mtime, src_size)
    return magic_bytes(ver) + struct.pack('<III', 0, mtime, src_size)  # 3.7+


def detect(data: bytes):
    """自动探测: 对每个候选头长(含 0=无头)尝试 marshal.loads, 返回 (ver, header_size, obj)。"""
    cur_magic = importlib.util.MAGIC_NUMBER          # 当前解释器版本
    candidates = [(0, cur_magic), (16, cur_magic), (12, cur_magic), (8, cur_magic)]
    for ver, m in PY_MAGIC.items():
        candidates += [(16, magic_bytes(ver)), (12, magic_bytes(ver)), (8, magic_bytes(ver))]
    tried = set()
    for size, mg in candidates:
        key = (size, mg)
        if key in tried:
            continue
        tried.add(key)
        body = data[size:]
        try:
            obj = marshal.loads(body)
            # 版本与当前解释器不一致时 marshal 可能解出垃圾, 校验类型
            if hasattr(obj, 'co_code') or hasattr(obj, 'co_consts'):
                ver = next((v for v, mv in PY_MAGIC.items()
                            if magic_bytes(v) == mg or mv == struct.unpack('<H', mg[:2])[0]),
                           None)
                return ver or 'current', size, obj
        except (ValueError, EOFError, TypeError):
            continue
    raise ValueError('无法探测 pyc 结构: 数据可能损坏或版本过新')


def fix(data: bytes, ver: str | None = None) -> bytes:
    """补头。ver 指定时用固定版本(其余字段置 0); 否则自动探测。"""
    if ver:
        body = data
        for size in (8, 12, 16):
            try:
                marshal.loads(body[size:])
                body = data[size:]
                break
            except (ValueError, EOFError, TypeError):
                body = data  # 探不出就当整段是 body, 用 16 头重试
        else:
            body = data
        return header_for(ver, len(body)) + body
    _, size, _ = detect(data)
    return header_for('current', len(data) - size) + data[size:]


def main():
    ap = argparse.ArgumentParser(description='pyc 文件头修复')
    ap.add_argument('file', nargs='?')
    ap.add_argument('-o', '--out', default='fixed.pyc')
    ap.add_argument('--ver', choices=sorted(PY_MAGIC), help='指定 python 版本')
    args = ap.parse_args()

    if args.file:
        with open(args.file, 'rb') as f:
            data = f.read()
        try:
            ver, size, code = detect(data)
            print(f'探测: 头长={size} 版本≈{ver} 顶层对象={type(code).__name__}')
        except ValueError as e:
            if not args.ver:
                print(f'自动探测失败({e}); 请用 --ver 指定版本重试')
                sys.exit(1)
        fixed = fix(data, args.ver)
        with open(args.out, 'wb') as f:
            f.write(fixed)
        print('已写出:', args.out, '(可用 uncompyle6/decompyle3/pycdc 反编译)')
    else:
        # 自测: py_compile 生成 pyc -> 删头 -> 修复 -> marshal 验证
        import os
        import py_compile
        import tempfile
        ok = True
        tmpdir = tempfile.mkdtemp()
        src = os.path.join(tmpdir, 'flagmod.py')
        with open(src, 'w', encoding='utf-8') as f:
            f.write('FLAG = "flag{pyc_h34d_r3st0red}"\n'
                    'def check(s):\n    return s == FLAG\n')
        pyc = py_compile.compile(src, doraise=True)
        with open(pyc, 'rb') as f:
            raw = f.read()
        header_size = 16
        body = raw[header_size:]
        # 用本工具按当前版本补头
        rebuilt = header_for('current', len(body)) + body
        try:
            code = marshal.loads(rebuilt[header_size:])
            good = getattr(code, 'co_filename', '').endswith('flagmod.py') or True
            good = 'FLAG' in str(code.co_names) or 'FLAG' in str(getattr(code, 'co_consts', ''))
        except Exception as e:
            good = False
            print('   marshal 异常:', e)
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 删头{header_size}字节 -> 补头 -> marshal 可读")
        # 头长探测: 完整 pyc 应探出 16; 无头 body 应探出 0
        ver, size, _ = detect(raw)
        good2 = size == header_size
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] 完整pyc头长探测: {size} (版本 {ver})")
        ver2, size2, _ = detect(body)
        good3 = size2 == 0
        ok &= good3
        print(f"[{'OK' if good3 else 'FAIL'}] 无头pyc探测: header_size={size2} (版本 {ver2})")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
