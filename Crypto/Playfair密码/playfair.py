# -*- coding: utf-8 -*-
"""playfair.py — Playfair 普莱费尔密码加解密(古典密码高频题)

规则: 5x5 密钥表(去重填充, I/J 合并为一格);
      明文按两字母分组: 相同字母对中间插 X, 末尾奇数补 X;
      加密: 同行->右移一格, 同列->下移一格, 矩形->换列对角;
      解密: 同行->左移一格, 同列->上移一格, 矩形->换列对角。
      经典向量(维基百科): key=PLAYFAIREXAMPLE,
      明文 HIDETHEGOLDINTHETREESTUMP -> 密文 BMODZBXDNABEKUDMUIXMMOUVIF。

用法:
    python playfair.py -e "HIDETHEGOLD" -k "playfair example"   # 加密
    python playfair.py -d BMODZBXDNABEKUDMUIXMMOUVIF -k "playfair example"
    python playfair.py --selftest                               # 内置自测
"""
import argparse
import sys


def build_grid(key):
    key = key.upper().replace('J', 'I')
    seen, seq = set(), []
    for ch in key:
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            seq.append(ch)
    for ch in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':  # 无 J
        if ch not in seen:
            seq.append(ch)
    return [seq[i * 5:i * 5 + 5] for i in range(5)]


def find_pos(grid, ch):
    for r, row in enumerate(grid):
        if ch in row:
            return r, row.index(ch)
    raise ValueError('字符不在密钥表: %r' % ch)


def prep_text(text):
    text = ''.join(c for c in text.upper() if c.isalpha()).replace('J', 'I')
    out = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else None
        if b is None:
            out.append(a + 'X')
            i += 1
        elif a == b:
            out.append(a + 'X')
            i += 1
        else:
            out.append(a + b)
            i += 2
    return out


def transform(pairs, grid, sign):
    res = []
    for a, b in pairs:
        r1, c1 = find_pos(grid, a)
        r2, c2 = find_pos(grid, b)
        if r1 == r2:
            res.append(grid[r1][(c1 + sign) % 5] + grid[r2][(c2 + sign) % 5])
        elif c1 == c2:
            res.append(grid[(r1 + sign) % 5][c1] + grid[(r2 + sign) % 5][c2])
        else:
            res.append(grid[r1][c2] + grid[r2][c1])
    return ''.join(res)


def encrypt(text, key):
    return transform(prep_text(text), build_grid(key), 1)


def decrypt(text, key):
    pairs = [''.join(c for c in text.upper() if c.isalpha())[i:i + 2]
             for i in range(0, len(text), 2)]
    return transform([p for p in pairs if len(p) == 2], build_grid(key), -1)


def selftest():
    ct = encrypt('HIDETHEGOLDINTHETREESTUMP', 'playfair example')
    ok = ct == 'BMODZBXDNABEKUDMUIXMMOUVIF'
    back = decrypt(ct, 'playfair example')
    ok = ok and back.startswith('HIDETHEGOLDINTHETREXESTUMP')
    print('Playfair 经典向量/回解:', 'OK' if ok else 'FAIL (%r -> %r)' % (ct, back))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='Playfair 加解密')
    ap.add_argument('-e', '--encrypt', help='加密明文')
    ap.add_argument('-d', '--decrypt', help='解密密文')
    ap.add_argument('-k', '--key', required=False, help='密钥')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not (args.encrypt or args.decrypt) or not args.key:
        ap.error('需要 -e/-d 明文或密文, 以及 -k 密钥(或 --selftest)')
    if args.encrypt:
        print(encrypt(args.encrypt, args.key))
    else:
        print(decrypt(args.decrypt, args.key))


if __name__ == '__main__':
    main()
