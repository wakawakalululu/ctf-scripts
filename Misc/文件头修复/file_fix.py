# -*- coding: utf-8 -*-
"""常见文件头/尾修复 与 文件类型识别(补充题型: Misc/Forensics)

用途:
    CTF 常见"文件头损坏": PNG 缺 8 字节魔数、JPG 缺 FF D8、后缀错误等。
    本脚本: 1) 按魔数识别真实类型  2) --fix 修复缺失的头/尾
    支持: PNG/JPG/GIF/BMP/ZIP/RAR/PDF/7Z/ELF/EXE

用法:
    python file_fix.py <文件>              # 识别
    python file_fix.py <文件> --fix out.png  # 修复并输出
    python file_fix.py                     # 自测
"""
import argparse
import os
import sys

MAGICS = [
    # (类型, 头字节, 尾字节或 None, 典型后缀)
    ('PNG',  b'\x89PNG\r\n\x1a\n', b'\x00\x00\x00\x00IEND\xaeB\x60\x82', '.png'),
    ('JPG',  b'\xff\xd8\xff',      b'\xff\xd9',                          '.jpg'),
    ('GIF',  b'GIF89a',            b'\x3b',                              '.gif'),
    ('GIF',  b'GIF87a',            b'\x3b',                              '.gif'),
    ('BMP',  b'BM',                None,                                 '.bmp'),
    ('ZIP',  b'PK\x03\x04',        b'PK\x05\x06',                        '.zip'),
    ('RAR',  b'Rar!\x1a\x07',      None,                                 '.rar'),
    ('7Z',   b'7z\xbc\xaf\x27\x1c', None,                                '.7z'),
    ('PDF',  b'%PDF-',             b'%%EOF',                             '.pdf'),
    ('ELF',  b'\x7fELF',           None,                                 '.elf'),
    ('EXE',  b'MZ',                None,                                 '.exe'),
]


def identify(data: bytes):
    """返回 [(类型, 匹配的魔数), ...]; 空 head 时按"缺头但有尾"给修复建议。"""
    hits = []
    for name, head, tail, ext in MAGICS:
        if data.startswith(head):
            hits.append((name, head))
    if not hits:
        for name, head, tail, ext in MAGICS:
            if tail and data.endswith(tail):
                hits.append((name, f'仅尾部匹配 {tail!r}(头部可能损坏)'))
    return hits


def fix_file(data: bytes):
    """补齐缺失的头/尾, 返回 (修复后bytes, 修改说明列表)。"""
    notes = []
    out = data
    for name, head, tail, ext in MAGICS:
        if out.startswith(head):
            if tail and tail not in out:
                out += tail
                notes.append(f'{name}: 已补尾部 {tail!r}')
            if name == 'PNG' and b'IHDR' not in out[:32]:
                # 标准 PNG 头后紧跟 IHDR 长度+类型
                ihdr = b'\x00\x00\x00\x0dIHDR'
                if not out[8:16].startswith(b'\x00\x00\x00\x0dIHDR'):
                    out = head + ihdr + out[8:] if len(out) > 8 else head + ihdr
                    notes.append('PNG: 已补 IHDR 块头(请核对宽高字节)')
            return out, notes
    # 无头: 按尾部猜类型并补头
    for name, head, tail, ext in MAGICS:
        if tail and data.endswith(tail):
            if name == 'JPG' and data.startswith(b'\xff'):
                # JPG 通常只缺 SOI 两字节: 数据已以下一个标记(\xff\xe0 等)开头时,
                # 补 3 字节头会多出一个 \xff(FF D8 FF FF E0), 补 2 字节才字节级还原
                out = b'\xff\xd8' + data
                notes.append('JPG: 数据已以 \\xff 标记开头, 仅补 SOI 头 FF D8')
            else:
                out = head + data
                notes.append(f'{name}: 按尾部补头 {head!r}')
            return out, notes
    notes.append('无法识别, 未做修复')
    return out, notes


def main():
    ap = argparse.ArgumentParser(description='文件类型识别与头尾修复')
    ap.add_argument('file', nargs='?')
    ap.add_argument('--fix', metavar='OUT', help='修复结果输出路径')
    args = ap.parse_args()

    if args.file:
        with open(args.file, 'rb') as f:
            data = f.read()
        hits = identify(data)
        print('识别结果:', hits if hits else '未知')
        if args.fix:
            fixed, notes = fix_file(data)
            with open(args.fix, 'wb') as f:
                f.write(fixed)
            for n in notes:
                print('[fix]', n)
            print('已写出:', args.fix)
    else:
        # 自测: PIL 生成 PNG -> 剥头 -> 修复 -> 验证可开
        import io
        import tempfile
        ok = True
        try:
            from PIL import Image
        except ImportError:
            print('[SKIP] 未安装 pillow')
            sys.exit(0)
        img = Image.new('RGB', (32, 32), (255, 0, 0))
        buf = io.BytesIO()
        img.save(buf, 'PNG')
        png = buf.getvalue()
        # 识别
        hits = identify(png)
        good = hits and hits[0][0] == 'PNG'
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] PNG 识别: {hits}")
        # 剥头修复
        stripped = png[8:]
        fixed, notes = fix_file(stripped)
        good2 = fixed.startswith(png[:8]) or fixed == png
        try:
            img2 = Image.open(io.BytesIO(fixed))
            img2.load()
            opened = True
        except Exception:
            opened = False
        ok &= opened
        print(f"[{'OK' if opened else 'FAIL'}] 剥头PNG修复后可打开: notes={notes}")
        # JPG 剥头
        buf2 = io.BytesIO()
        img.save(buf2, 'JPEG')
        jpg = buf2.getvalue()
        fixed2, _ = fix_file(jpg[2:])
        opened2 = False
        try:
            Image.open(io.BytesIO(fixed2)).load()
            opened2 = True
        except Exception:
            pass
        ok &= opened2
        print(f"[{'OK' if opened2 else 'FAIL'}] 剥头JPG修复后可打开")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
