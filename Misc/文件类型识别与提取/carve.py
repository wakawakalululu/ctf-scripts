# -*- coding: utf-8 -*-
"""文件雕刻/内嵌文件提取 — 纯 Python mini-binwalk(补充题型: Misc/Forensics)

用途:
    在任意二进制(图片/pcap/固件/日志)里按魔数扫描内嵌文件, 自动雕刻导出:
    PNG / JPG / GIF / ZIP / RAR / 7Z / PDF / ELF / EXE / BMP
    比 binwalk 轻量, 免安装; 结果打印 offset 列表并落盘 carved/ 目录。

用法:
    python carve.py <文件>                 # 扫描并导出到 ./carved/
    python carve.py <文件> -o outdir       # 指定输出目录
    python carve.py <文件> --list-only     # 只打印, 不落盘
    python carve.py                        # 自测
"""
import argparse
import os
import sys

SIGNATURES = [
    ('png',  b'\x89PNG\r\n\x1a\n',                 b'IEND\xaeB\x60\x82', '.png'),
    ('jpg',  b'\xff\xd8\xff\xe0',                  b'\xff\xd9',          '.jpg'),
    ('jpg',  b'\xff\xd8\xff\xe1',                  b'\xff\xd9',          '.jpg'),
    ('jpg',  b'\xff\xd8\xff\xdb',                  b'\xff\xd9',          '.jpg'),
    ('gif',  b'GIF89a',                            b'\x00\x3b',          '.gif'),
    ('zip',  b'PK\x03\x04',                        b'PK\x05\x06',        '.zip'),
    ('rar',  b'Rar!\x1a\x07',                      None,                 '.rar'),
    ('7z',   b'7z\xbc\xaf\x27\x1c',                None,                 '.7z'),
    ('pdf',  b'%PDF-',                             b'%%EOF',             '.pdf'),
    ('elf',  b'\x7fELF',                           None,                 '.elf'),
    ('exe',  b'MZ',                                None,                 '.exe'),
]


def scan(data: bytes):
    """返回 [(offset, 类型, 结束offset或None), ...]"""
    results = []
    for name, head, tail, ext in SIGNATURES:
        start = 0
        while True:
            off = data.find(head, start)
            if off < 0:
                break
            end = None
            if tail:
                tend = data.find(tail, off + len(head))
                if tend >= 0:
                    end = tend + len(tail)
            # exe/elf 等 MZ 头太泛: 仅在 offset 0 或跟随 PNG/JPG 内嵌时报告由调用方过滤
            results.append((off, name, end, ext))
            start = off + len(head)
    results.sort(key=lambda t: t[0])
    return results


def carve(data: bytes, outdir: str = 'carved', list_only: bool = False):
    found = scan(data)
    # 去重: 相同 offset 只保留优先级最高的类型(按 SIGNATURES 顺序)
    by_offset = {}
    for off, name, end, ext in found:
        by_offset.setdefault(off, (name, end, ext))
    os.makedirs(outdir, exist_ok=True)
    carved = []
    for i, (off, (name, end, ext)) in enumerate(sorted(by_offset.items())):
        piece = data[off:end] if end else data[off:off + 4096]
        print(f'[{i}] {name} @ offset={off} size={len(piece)} end={"已知" if end else "未知(截取4KB)"}')
        if not list_only:
            path = os.path.join(outdir, f'{i}_{name}{ext}')
            with open(path, 'wb') as f:
                f.write(piece)
            carved.append(path)
    return carved


def main():
    ap = argparse.ArgumentParser(description='内嵌文件扫描与雕刻')
    ap.add_argument('file', nargs='?')
    ap.add_argument('-o', '--outdir', default='carved')
    ap.add_argument('--list-only', action='store_true')
    args = ap.parse_args()

    if args.file:
        with open(args.file, 'rb') as f:
            data = f.read()
        carve(data, args.outdir, args.list_only)
    else:
        # 自测: 构造 容器 = 噪声 + PNG + ZIP
        import io
        import os
        import tempfile
        import zipfile
        ok = True
        noise = os.urandom(120)
        try:
            from PIL import Image
        except ImportError:
            print('[SKIP] 未安装 pillow (pip install pillow)')
            sys.exit(0)
        buf = io.BytesIO()
        Image.new('RGB', (24, 24), (0, 255, 0)).save(buf, 'PNG')
        png = buf.getvalue()
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, 'w') as z:
            z.writestr('a.txt', 'hi')
        zbytes = zbuf.getvalue()
        container = noise + b'\x00' * 10 + png + b'\xff' * 7 + zbytes
        results = scan(container)
        kinds = [r[1] for r in results]
        good = 'png' in kinds and 'zip' in kinds
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 扫描: {results[:4]}")
        tmpdir = tempfile.mkdtemp()
        paths = carve(container, outdir=tmpdir, list_only=True)
        ok &= len(paths) == 0  # list_only 不落盘
        paths = carve(container, outdir=tmpdir)
        good2 = len(paths) >= 2
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] 雕刻落盘: {len(paths)} 个文件 -> {tmpdir}")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
