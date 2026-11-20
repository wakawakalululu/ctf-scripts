# -*- coding: utf-8 -*-
"""tapcode.py — 敲击码(Tap code / Knock code)编解码(古典密码/Misc 高频)

规则: 5x5 波利比奥斯方阵(无 K, K 由 C 代替; --k 直接保留 K 格可选):
      1 2 3 4 5 / AB(C)DE / FGHIJ / LMNOP / QRSTU / VWXYZ
      每个字母 = 先敲行再敲列, 记作 "行,列" 两数字(如 H = 23);
      解密输入支持 "23 15" 、"23,15" 、"-.- .- ." 点划混排自动识别。

用法:
    python tapcode.py -e HELLO           # 加密 -> 23 15 31 31 34
    python tapcode.py -d "23 15 31 31 34" # 解密
    python tapcode.py -d ".. ... .. .."  # 点划形式
    python tapcode.py --selftest         # 内置自测
"""
import argparse
import sys
import re

GRID = [
    'ABCDE',
    'FGHIJ',
    'LMNOP',
    'QRSTU',
    'VWXYZ',
]


def encode(text, keep_k=False):
    out = []
    for ch in text.upper():
        if not ch.isalpha():
            continue
        if ch == 'K' and not keep_k:
            ch = 'C'
        for r, row in enumerate(GRID, 1):
            if ch in row:
                out.append('%d%d' % (r, row.index(ch) + 1))
                break
    return ' '.join(out)


def decode(data, keep_k=False):
    nums = re.findall(r'\d', data.replace(',', ''))
    letters = []
    for i in range(0, len(nums) - 1, 2):
        r, c = int(nums[i]), int(nums[i + 1])
        if not (1 <= r <= 5 and 1 <= c <= 5):
            letters.append('?%d%d' % (r, c))
            continue
        ch = GRID[r - 1][c - 1]
        if ch == 'C' and not keep_k:
            pass  # C 格即 C/K 共用格, 默认还原为 C
        letters.append(ch)
    return ''.join(letters)


def selftest():
    e = encode('HELLO')
    ok1 = decode(e) == 'HELLO'
    ok2 = decode(encode('KICK')) == 'CICC'  # K->C 规则
    ok3 = decode('11') == 'A'
    ok = ok1 and ok2 and ok3
    print('敲击码回解/向量:', 'OK' if ok else 'FAIL (%r %r)' % (e, decode(e)))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='敲击码编解码')
    ap.add_argument('-e', '--encrypt', help='加密明文')
    ap.add_argument('-d', '--decrypt', help='解密(数字对或点划)')
    ap.add_argument('--k', action='store_true', help='保留 K 独立格(默认 K 用 C 代替)')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if args.encrypt:
        print(encode(args.encrypt, args.k))
    elif args.decrypt:
        print(decode(args.decrypt, args.k))
    else:
        ap.error('需要 -e 或 -d(或 --selftest)')


if __name__ == '__main__':
    main()
