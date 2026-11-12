# -*- coding: utf-8 -*-
"""ZIP 伪加密检测与修复(补充题型: Misc/压缩包)

用途:
    CTF 常见手法: 把 ZIP 的"加密标志位"改 1 但没真正加密, 导致解压软件要求密码。
    本脚本: 1) 扫描全部 Local File Header / Central Directory, 报告标志位
           2) --fix 一键清除加密位(只清 0x0001, 保留 UTF-8 位等其他标志)

用法:
    python zip_fix.py <file.zip>            # 检测(只读)
    python zip_fix.py <file.zip> --fix      # 修复并覆盖(先自动备份 .bak)
    python zip_fix.py                       # 自测
"""
import argparse
import shutil
import struct
import sys

LOCAL_SIG = b'PK\x03\x04'
CENTRAL_SIG = b'PK\x01\x02'
ENCRYPT_FLAG = 0x0001


def scan(data: bytes):
    """返回 [(位置, 'local'/'central', flags), ...]"""
    found = []
    for sig, kind, flags_off in ((LOCAL_SIG, 'local', 6), (CENTRAL_SIG, 'central', 8)):
        start = 0
        while True:
            off = data.find(sig, start)
            if off < 0:
                break
            flags = struct.unpack_from('<H', data, off + flags_off)[0]
            found.append((off, kind, flags))
            start = off + 4
    return found


def fix(data: bytes) -> bytes:
    """清除所有头的加密位(只清 bit0)。"""
    out = bytearray(data)
    for off, kind, flags in scan(data):
        if flags & ENCRYPT_FLAG:
            flags_off = 6 if kind == 'local' else 8
            new = flags & ~ENCRYPT_FLAG
            struct.pack_into('<H', out, off + flags_off, new)
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description='ZIP 伪加密检测/修复')
    ap.add_argument('file', nargs='?', help='.zip 文件')
    ap.add_argument('--fix', action='store_true', help='清除加密位并覆盖(自动备份 .bak)')
    args = ap.parse_args()

    if args.file:
        with open(args.file, 'rb') as f:
            data = f.read()
        items = scan(data)
        if not items:
            print('未找到 ZIP 头, 确认文件格式(可能需要先修文件头)')
        encrypted = False
        for off, kind, flags in items:
            enc = flags & ENCRYPT_FLAG
            encrypted |= bool(enc)
            print(f'[{kind}] offset={off} flags=0x{flags:04x} '
                  f'{"伪加密/已加密" if enc else "未加密"}'
                  f'{" (UTF-8)" if flags & 0x800 else ""}')
        if args.fix:
            if encrypted:
                shutil.copy2(args.file, args.file + '.bak')
                with open(args.file, 'wb') as f:
                    f.write(fix(data))
                print('已修复(备份: %s.bak)' % args.file)
            else:
                print('无需修复')
    else:
        # 自测: 构造正常 zip -> 制造伪加密 -> 检测 -> 修复 -> 验证可读
        import io
        import os
        import tempfile
        import zipfile
        ok = True
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('flag.txt', 'flag{zip_fake_enc}')
        data = buf.getvalue()
        # 制造伪加密: local(6) + central(8) 标志位置 1
        bad = bytearray(data)
        off_local = bad.find(LOCAL_SIG)
        struct.pack_into('<H', bad, off_local + 6, 0x0001)
        off_central = bad.find(CENTRAL_SIG)
        struct.pack_into('<H', bad, off_central + 8, 0x0001)
        bad = bytes(bad)
        items = scan(bad)
        detected = all(fl & ENCRYPT_FLAG for _, _, fl in items) and len(items) == 2
        ok &= detected
        print(f"[{'OK' if detected else 'FAIL'}] 伪加密检测: {items}")
        fixed = fix(bad)
        content = ''   # 原版 except 后 print 引用未定义的 content 会 NameError 掩盖真实异常
        try:
            with zipfile.ZipFile(io.BytesIO(fixed)) as z:
                content = z.read('flag.txt').decode()
            good = content == 'flag{zip_fake_enc}'
        except Exception as e:
            good = False
            print('   解压异常:', e)
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 修复后可读: {content!r}")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
