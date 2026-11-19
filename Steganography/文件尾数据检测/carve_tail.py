# -*- coding: utf-8 -*-
"""carve_tail.py — 图片/文件尾部追加数据检测与剥离(隐写经典套路)

用途: 题目给一张能正常打开的图, binwalk/stegsolve 没收获时,
      先查"格式正常结束标记之后还挂了什么": JPG 尾藏 zip、PNG IEND 后
      藏文本/压缩包、PDF %%EOF 后藏文件都是高频考点。
      本脚本识别 6 类格式的标准 EOF 位置, dump 出尾部数据并:
      自动 flag 搜索 / hexdump / --save 导出 / --strip 生成剥离后干净文件。

用法:
    python carve_tail.py x.png                  # 检测并打印尾部数据
    python carve_tail.py x.jpg --save tail.bin  # 尾部数据导出(常为 zip, 直接改后缀)
    python carve_tail.py x.jpg --strip clean.jpg# 剥离尾部生成干净文件
    python carve_tail.py any.bin --offset 1234  # 手动指定正常结束偏移
    python carve_tail.py --selftest             # 内置构造自测
"""
import argparse
import os
import re
import sys

FLAG_RE = re.compile(rb'flag\{[^}\s]{1,80}\}', re.I)

# (格式名, 结束标记定位函数) -> 返回"文件应在此结束"的偏移(不含尾部)
def _eof_png(b):
    i = b.rfind(b'IEND')
    return i + 8 if i != -1 else None          # IEND(4) + CRC(4)

def _eof_jpg(b):
    i = b.rfind(b'\xff\xd9')
    return i + 2 if i != -1 else None

def _eof_gif(b):
    i = b.rfind(b'\x3b')
    return i + 1 if i != -1 else None          # trailer 0x3b

def _eof_zip(b):
    i = b.rfind(b'PK\x05\x06')                  # EOCD
    if i == -1:
        return None
    if len(b) < i + 22:
        return None
    import struct
    (comment_len,) = struct.unpack('<H', b[i + 20:i + 22])
    end = i + 22 + comment_len
    return end if end <= len(b) else None

def _eof_pdf(b):
    i = b.rfind(b'%%EOF')
    return i + 5 if i != -1 else None

def _eof_bmp(b):
    return None                                 # BMP 无可靠结束标记, 交给 --offset

EOF_MARKERS = [(b'\x89PNG', _eof_png), (b'\xff\xd8', _eof_jpg),
               (b'GIF8', _eof_gif), (b'PK\x03\x04', _eof_zip),
               (b'%PDF', _eof_pdf), (b'BM', _eof_bmp)]


def detect(data):
    """返回 (格式名, 正常结束偏移)。按魔数识别; 无法识别返回 (None, None)。"""
    for magic, fn in EOF_MARKERS:
        if data.startswith(magic):
            off = fn(data)
            if off is not None:
                return magic.decode('latin1').strip('\x00'), off
    return None, None


def hexdump(b, limit=96):
    out = []
    for i in range(0, min(len(b), limit), 16):
        chunk = b[i:i + 16]
        out.append('  %06x  %-47s  %s' % (
            i, ' '.join('%02x' % c for c in chunk),
            ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)))
    if len(b) > limit:
        out.append('  ...(共 %d 字节)' % len(b))
    return '\n'.join(out)


def run(path, save, strip, manual_offset):
    with open(path, 'rb') as f:
        data = f.read()
    fmt, eof = detect(data)
    if manual_offset is not None:
        fmt, eof = '手动指定', manual_offset
    elif fmt is None:
        print('[!] 无法识别文件格式(魔数不是 PNG/JPG/GIF/ZIP/PDF/BMP)。')
        print('    可用 --offset <字节> 手动指定"正常结束位置"。')
        return 1
    tail = data[eof:]
    print('[*] 文件: %s' % path)
    print('    格式: %s   正常结束偏移: %d   总大小: %d' % (fmt, eof, len(data)))
    if not tail:
        print('[OK] EOF 标记后没有附加数据')
        return 0
    print('[!] 尾部附加数据: %d 字节' % len(tail))
    print(hexdump(tail))
    flags = FLAG_RE.findall(tail)
    for f in flags:
        print('[+] flag: %s' % f.decode('latin1'))
    if tail.startswith(b'PK'):
        print('[i] 尾部像 ZIP 文件, 直接改后缀为 .zip 解压即可')
    elif tail.startswith(b'\x89PNG') or tail[:3] in (b'\xff\xd8', b'GIF'):
        print('[i] 尾部像另一张图片, --save 后改对应后缀查看')
    if save:
        with open(save, 'wb') as f:
            f.write(tail)
        print('[+] 尾部数据已导出 -> %s' % save)
    if strip:
        root, _ = os.path.splitext(path)
        out = '%s_clean%s' % (root, os.path.splitext(path)[1])
        with open(out, 'wb') as f:
            f.write(data[:eof])
        print('[+] 剥离尾部干净文件 -> %s' % out)
    return 0


def selftest():
    png = (b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\x0dIHDR' + b'\x00' * 13 +
           b'\x00\x00\x00\x00IEND\xaeB`\x82')
    tail = b'PK\x03\x04' + b'flag{tail_stego_ok} rest-of-zip'
    data = png + tail
    fmt, off = detect(data)
    ok = fmt == '\x89PNG' and off == len(png) and data[off:] == tail
    ok &= bool(FLAG_RE.findall(data[off:]))
    # JPG / GIF / ZIP / PDF
    jpg = b'\xff\xd8\xff\xe0junk' + b'\xff\xd9' + b'flag{jpg_tail}'
    ok &= detect(jpg) == ('\xff\xd8', 10)
    gif = b'GIF89a...\x3b' + b'trailing'
    ok &= detect(gif)[1] == len(b'GIF89a...\x3b')
    import struct
    cd = b'PK\x01\x02\x14\x03' + b'\x00' * 30
    z = (b'PK\x03\x04local\x00' + cd +
         b'PK\x05\x06' + b'\x00' * 16 + struct.pack('<H', 9) + b'mycomment')
    ok &= detect(z)[1] == len(z)          # EOCD+注释之后无尾巴
    ok &= detect(z + b'EXTRA')[1] == len(z)
    pdf = b'%PDF-1.7 body %%EOF' + b'hidden'
    ok &= detect(pdf) == ('%PDF', 19)
    print('[%s] carve_tail.py 自测: PNG/JPG/GIF/ZIP/PDF 尾部检测' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='文件尾部追加数据检测')
    ap.add_argument('file', nargs='?', help='目标文件')
    ap.add_argument('--save', help='尾部数据导出路径')
    ap.add_argument('--strip', action='store_true', help='生成剥离尾部后的干净文件')
    ap.add_argument('--offset', type=int, help='手动指定正常结束偏移')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    if not args.file or not os.path.exists(args.file):
        print('用法: python carve_tail.py <file> [--save tail.bin --strip --offset N]')
        print('      python carve_tail.py --selftest')
        return 1
    return run(args.file, args.save, args.strip, args.offset)


if __name__ == '__main__':
    sys.exit(main())
