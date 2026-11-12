# -*- coding: utf-8 -*-
"""图片 EXIF/元信息提取(补充题型: Misc/Forensics)

用途:
    dump 图片元数据( EXIF / PNG text chunk / JPEG comment )。
    CTF flag 常藏在: ImageDescription(0x010e), Software(0x0131),
    Comment(0x9286), Artist(0x013b), PNG tEXt chunk。

依赖:
    pip install pillow

用法:
    python exif_dump.py <图片>         # 打印全部元信息
    python exif_dump.py                # 自测
"""
import argparse
import sys


def dump(path: str):
    from PIL import Image
    img = Image.open(path)
    print('格式:', img.format, '尺寸:', img.size, '模式:', img.mode)
    print('info 键:', {k: (v[:80] if isinstance(v, (str, bytes)) else v) for k, v in img.info.items()})
    exif = img.getexif()
    if not exif:
        print('(无 EXIF)')
        return
    tag_names = {
        0x010e: 'ImageDescription', 0x013b: 'Artist', 0x0131: 'Software',
        0x8298: 'Copyright', 0x9286: 'UserComment', 0x010f: 'Make',
        0x0110: 'Model', 0x0132: 'DateTime', 0x9285: 'ExposureBias',
    }
    for tag, value in exif.items():
        name = tag_names.get(tag, f'Tag{tag:#06x}')
        if isinstance(value, bytes):
            value = value[:120]
        print(f'EXIF {name}({tag:#06x}): {value}')
    # 子 IFD(Exif/ GPS) 常规 tag 也抓一遍
    for ifd_id in (0x8769, 0x8825):  # ExifIFD / GPSIFD
        try:
            ifd = exif.get_ifd(ifd_id)
            for tag, value in ifd.items():
                v = value[:120] if isinstance(value, bytes) else value
                print(f'IFD{ifd_id:#06x} Tag{tag:#06x}: {v}')
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description='图片 EXIF/元信息提取')
    ap.add_argument('file', nargs='?')
    args = ap.parse_args()

    if args.file:
        dump(args.file)
    else:
        # 自测: 造一张带 exif 的图再读回
        import io
        import os
        import tempfile
        try:
            from PIL import Image
        except ImportError:
            print('[SKIP] 未安装 pillow (pip install pillow)')
            sys.exit(0)
        ok = True
        img = Image.new('RGB', (16, 16), (0, 0, 255))
        exif = img.getexif()
        exif[0x010e] = 'flag{ex1f_h1dd3n}'       # ImageDescription
        exif[0x0131] = 'CTFTool 1.0'             # Software
        buf = io.BytesIO()
        img.save(buf, 'JPEG', exif=exif.tobytes())
        buf.seek(0)
        img2 = Image.open(buf)
        got = img2.getexif().get(0x010e)
        good = got == 'flag{ex1f_h1dd3n}'
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] JPEG EXIF 回环: ImageDescription={got!r}")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
