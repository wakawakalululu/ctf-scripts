# -*- coding: utf-8 -*-
"""png_analyze PNG 结构分析 / CRC 修复(py3 完善版)

来源: https://github.com/wilesanGH/ctf-web (md_docs/pngcheck使用手册.md 与 pillow使用手册.md 内嵌脚本合并完善)
用途: Misc 图像题 —— 列出 PNG 全部数据块(发现 tEXt/zTXt 隐藏信息)、修复被改坏宽高后的 CRC、提取指定块。

依赖:
    无(list/extract 用纯标准库; fix-crc 校验用标准库 zlib)

用法:
    python png_analyze.py --selftest                   # 自测
    python png_analyze.py list image.png               # 列出全部块(类型/长度/偏移/CRC状态)
    python png_analyze.py fix-crc image.png            # 修复全部错误 CRC -> image.fixed.png
    python png_analyze.py extract image.png tEXt       # 提取指定类型块内容到 stdout
"""
from __future__ import annotations

import argparse
import struct
import sys
import zlib

PNG_SIG = b'\x89PNG\r\n\x1a\n'


def iter_chunks(data: bytes):
    """产出 (offset, type, chunk_data, stored_crc, calc_crc)。"""
    if not data.startswith(PNG_SIG):
        raise ValueError('不是 PNG 文件(魔数不符)')
    pos = 8
    while pos + 12 <= len(data):
        length = struct.unpack('>I', data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        cdata = data[pos + 8:pos + 8 + length]
        if len(cdata) < length:
            raise ValueError(f'块 {ctype!r} 在 offset {pos} 数据截断')
        stored = struct.unpack('>I', data[pos + 8 + length:pos + 12 + length])[0]
        calc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
        yield pos, ctype, cdata, stored, calc
        pos += 12 + length
        if ctype == b'IEND':
            break


def list_chunks(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    rows = []
    for off, ctype, cdata, stored, calc in iter_chunks(data):
        status = 'OK' if stored == calc else f'BAD(应为 {calc:08x})'
        preview = ''
        if ctype in (b'tEXt', b'zTXt', b'iTXt') and cdata:
            preview = cdata[:60]
        rows.append((off, ctype.decode('latin-1'), len(cdata), stored, calc, status, preview))
        print(f'offset={off:<8} {ctype.decode("latin-1"):<6} len={len(cdata):<8} '
              f'crc={stored:08x} {status} {preview!r}')
    return rows


def fix_crc(path: str, out: str | None = None):
    """修复所有错误 CRC, 返回 (输出路径, 修复数)。"""
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    fixed = 0
    for off, ctype, cdata, stored, calc in iter_chunks(bytes(data)):
        if stored != calc:
            data[off + 8 + len(cdata):off + 12 + len(cdata)] = struct.pack('>I', calc)
            fixed += 1
            print(f'[+] 修复 {ctype.decode("latin-1")} 块 CRC: {stored:08x} -> {calc:08x}')
    if fixed:
        out = out or (path + '.fixed.png')
        with open(out, 'wb') as f:
            f.write(data)
        print(f'[+] 已保存: {out} (共修复 {fixed} 处)')
    else:
        out = path
        print('[+] 所有块 CRC 均正确, 无需修复')
    return out, fixed


def extract_chunks(path: str, want: str):
    """提取指定类型块的原始内容。"""
    with open(path, 'rb') as f:
        data = f.read()
    found = 0
    for _off, ctype, cdata, _s, _c in iter_chunks(data):
        if ctype.decode('latin-1').lower() == want.lower():
            found += 1
            sys.stdout.buffer.write(cdata)
            sys.stdout.buffer.write(b'\n')
    if not found:
        print(f'未找到 {want} 块', file=sys.stderr)
    return found


def main():
    ap = argparse.ArgumentParser(description='PNG 结构分析/CRC 修复')
    ap.add_argument('cmd', nargs='?', choices=['list', 'fix-crc', 'extract'])
    ap.add_argument('file', nargs='?')
    ap.add_argument('chunk', nargs='?', default='tEXt', help='extract 的块类型')
    ap.add_argument('-o', '--out', help='fix-crc 输出路径')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest or not args.cmd:
        if args.cmd:
            ap.error('自测模式不需要子命令(--selftest)')
        selftest()
        return

    if not args.file:   # 原版缺文件参数时 open(None) 裸抛 TypeError
        ap.error('需要文件路径: python png_analyze.py %s <png文件>' % args.cmd)

    if args.cmd == 'list':
        list_chunks(args.file)
    elif args.cmd == 'fix-crc':
        fix_crc(args.file, args.out)
    else:
        extract_chunks(args.file, args.chunk)


def selftest():
        try:
            from PIL import Image
        except ImportError:
            print('缺少依赖: pip install pillow (仅自测需要)')
            sys.exit(2)
        import io
        import os
        import tempfile
        ok = True
        # 1) 生成带 tEXt 的 PNG
        img = Image.new('RGB', (16, 16), (10, 200, 10))
        buf = io.BytesIO()
        img.save(buf, 'PNG', pnginfo=None)
        # 手动注入 tEXt 块: 在 IHDR 后插入
        base = buf.getvalue()
        text = b'flag{png_chunk_hidden}'
        chunk = struct.pack('>I', len(text)) + b'tEXt' + text
        chunk += struct.pack('>I', zlib.crc32(b'tEXt' + text) & 0xFFFFFFFF)
        injected = base[:8] + base[8:8 + 25] + chunk + base[33:]   # IHDR 长度固定 25
        d = tempfile.mkdtemp()
        p = os.path.join(d, 't.png')
        with open(p, 'wb') as f:
            f.write(injected)
        # 2) list 应含 tEXt
        rows = list_chunks(p)
        good = any(r[1] == 'tEXt' for r in rows) and all('BAD' not in r[5] for r in rows)
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] list: {[r[1] for r in rows]}")
        # 3) extract 命中隐藏文本
        found = extract_chunks(p, 'tEXt')
        good2 = b'flag{png_chunk_hidden}' in open(p, 'rb').read()
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] extract tEXt 块数: {found}")
        # 4) 破坏 IHDR CRC 后 fix-crc
        corrupt = bytearray(injected)
        corrupt[29] ^= 0xFF          # IHDR CRC 最后一字节
        pc = os.path.join(d, 'bad.png')
        with open(pc, 'wb') as f:
            f.write(corrupt)
        out, n = fix_crc(pc, os.path.join(d, 'fixed.png'))
        good3 = n == 1 and os.path.exists(out)
        from PIL import Image as I2
        I2.open(out).load()
        ok &= good3
        print(f"[{'OK' if good3 else 'FAIL'}] fix-crc 修复 {n} 处且可打开")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
