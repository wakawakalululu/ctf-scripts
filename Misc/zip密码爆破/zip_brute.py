# -*- coding: utf-8 -*-
"""ZIP 密码爆破(补充题型: Misc/压缩包)

用途:
    字典爆破 / 纯数字爆破 / 自定义字符集全排列。
    ZipCrypto(传统加密)用标准 zipfile; AES 加密(ziper 加密包)自动切 pyzipper。

依赖:
    标准库即可运行; AES 压缩包需: pip install pyzipper

用法:
    python zip_brute.py <file.zip> --digits 4            # 0000-9999
    python zip_brute.py <file.zip> -w rockyou.txt        # 字典
    python zip_brute.py <file.zip> --charset abc123 -L 3 # 字符集全排列(长3)
    python zip_brute.py                                  # 自测
"""
import argparse
import itertools
import sys


def _open_zip(path):
    """优先 pyzipper(兼容 AES 与 ZipCrypto), 失败回退 zipfile。"""
    try:
        import pyzipper
        return pyzipper.AESZipFile(path), 'pyzipper(AES+ZipCrypto)'
    except ImportError:
        import zipfile
        return zipfile.ZipFile(path), 'zipfile(仅ZipCrypto)'


def try_password(zf, names, pwd: bytes) -> bool:
    try:
        zf.read(names[0], pwd=pwd)
        return True
    except (RuntimeError, Exception):
        # zipfile: RuntimeError("Bad password"); pyzipper 可能抛 BadZipFile 等
        return False


def gen_candidates(args):
    if args.wordlist:
        with open(args.wordlist, 'rb') as f:   # 按原始字节取行: 原版 utf-8 解码再 latin-1
            for line in f:                     # 编码, 中文等密码会被静默截改成错误字节
                yield line.rstrip(b'\r\n')
    elif args.digits:
        for tup in itertools.product('0123456789', repeat=args.digits):
            yield ''.join(tup).encode()
    elif args.charset and args.length:
        for tup in itertools.product(args.charset, repeat=args.length):
            yield ''.join(tup).encode()
    else:
        raise SystemExit('必须提供 -w / --digits / --charset+--L 之一')


def main():
    ap = argparse.ArgumentParser(description='ZIP 密码爆破')
    ap.add_argument('file', nargs='?', help='.zip 路径')
    ap.add_argument('-w', '--wordlist')
    ap.add_argument('--digits', type=int, help='纯数字密码位数, 如 4 => 0000-9999')
    ap.add_argument('--charset', help='自定义字符集')
    ap.add_argument('-L', '--length', type=int, help='自定义字符集时的排列长度')
    ap.add_argument('--index', type=int, default=0, help='尝试第 N 个文件(默认0)')
    args = ap.parse_args()

    if args.file:
        zf, backend = _open_zip(args.file)
        names = zf.namelist()
        if not names:
            raise SystemExit('压缩包为空')
        print(f'后端: {backend}, 目标文件: {names[0]}')
        tried = 0
        for cand in gen_candidates(args):
            tried += 1
            if tried % 2000 == 0:
                print(f'  已尝试 {tried} ...', end='\r')
            if try_password(zf, names, cand):
                print(f'\n[+] 密码命中: {cand.decode(errors="replace")} (共尝试 {tried})')
                return
        print(f'\n[-] 未命中, 共尝试 {tried}')
    else:
        # 自测: 用 pyzipper 建一个加密 zip 再爆破; 无 pyzipper 时构造 ZipCrypto 失败则跳过
        import io
        import os
        import tempfile
        ok = True
        pwd = '9527'
        tmpdir = tempfile.mkdtemp()
        zpath = os.path.join(tmpdir, 'enc.zip')
        try:
            import pyzipper
            with pyzipper.AESZipFile(zpath, 'w', compression=pyzipper.ZIP_DEFLATED,
                                     encryption=pyzipper.WZ_AES) as z:
                z.setpassword(pwd.encode())
                z.writestr('secret.txt', 'flag{zip_brute_ok}')
        except ImportError:
            print('[SKIP] 未安装 pyzipper, 无法创建测试用加密 zip (pip install pyzipper)')
            sys.exit(0)
        zf, backend = _open_zip(zpath)
        names = zf.namelist()
        found = None
        tried = 0
        for i in range(10000):
            cand = f'{i:04d}'.encode()
            tried += 1
            if try_password(zf, names, cand):
                found = cand.decode()
                break
        ok = found == pwd
        print(f"[{'OK' if ok else 'FAIL'}] 爆破 {backend}: 密码={found} 尝试={tried}")
        content = zf.read(names[0], pwd=pwd.encode()).decode()
        ok &= content == 'flag{zip_brute_ok}'
        print(f"[{'OK' if ok else 'FAIL'}] 命中后读取内容: {content!r}")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
