# -*- coding: utf-8 -*-
"""affine_brute.py — 仿射密码(Affine)全密钥空间爆破(无密钥自动破译)

规则: E(x) = (a·x + b) mod 26, a 与 26 互质(12 个取值), b 取 0-25,
      共 312 个密钥。本脚本穷举全部密钥, 按英文字母频率(卡方)打分,
      按"疑似度"排序输出最可能的明文; 找到 flag 前缀时直接置顶标记。

用法:
    python affine_brute.py "FMJXYU..."            # 爆破密文(自动输出 Top10)
    python affine_brute.py -f cipher.txt          # 从文件读密文
    python affine_brute.py "...提示词" -w FLAG     # 额外命中提示词加权
    python affine_brute.py --selftest             # 内置自测(含真实爆破还原)
"""
import argparse
import sys
from math import gcd

EN = ('ETAOINSHRDLCUMWFGYPBVKJXQZ')            # 英文字母频率序
FREQ = {c: f for f, c in enumerate(EN[::-1])}  # 分数: 高频字母得分高


def encrypt(text, a, b):
    out = []
    for c in text.upper():
        if 'A' <= c <= 'Z':
            out.append(chr((a * (ord(c) - 65) + b) % 26 + 65))
        else:
            out.append(c)
    return ''.join(out)


def decrypt(cipher, a, b):
    a_inv = next(k for k in range(26) if a * k % 26 == 1)
    out = []
    for c in cipher.upper():
        if 'A' <= c <= 'Z':
            out.append(chr(a_inv * (ord(c) - 65 - b) % 26 + 65))
        else:
            out.append(c)
    return ''.join(out)


def score(text):
    return sum(FREQ.get(c, 0) for c in text.upper())


def brute(cipher, hint=''):
    cand = []
    for a in range(26):
        if gcd(a, 26) != 1:
            continue
        for b in range(26):
            pt = decrypt(cipher, a, b)
            s = score(pt)
            if hint.upper() in pt.upper():
                s += 10000          # 命中提示词直接置顶
            if 'FLAG' in pt.upper() or 'CTF' in pt.upper():
                s += 5000           # flag 特征加权
            cand.append((s, a, b, pt))
    cand.sort(reverse=True)
    return cand


def selftest():
    plain = 'ATTACKATDAWNWHENTHEFLAGISREADY'
    ct = encrypt(plain, 5, 8)
    top = brute(ct)[:3]
    hit = any(a == 5 and b == 8 and pt == plain for _, a, b, pt in top)
    print('仿射爆破还原(a=5,b=8):', 'OK' if hit else 'FAIL, top=%r' % top[:1])
    return 0 if hit else 1


def main():
    ap = argparse.ArgumentParser(description='仿射密码爆破')
    ap.add_argument('cipher', nargs='?', help='密文')
    ap.add_argument('-f', '--file', help='从文件读密文')
    ap.add_argument('-w', '--hint', default='FLAG', help='明文提示词加权(默认 FLAG)')
    ap.add_argument('-n', '--top', type=int, default=10, help='输出候选数')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    cipher = open(args.file, encoding='utf-8', errors='replace').read() if args.file else args.cipher
    if not cipher:
        ap.error('需要密文参数或 -f 文件(或 --selftest)')
    result = brute(cipher, args.hint)
    for i, (s, a, b, pt) in enumerate(result[:args.top], 1):
        print('%2d. a=%2d b=%2d score=%-6d %s' % (i, a, b, s, pt))


if __name__ == '__main__':
    main()
