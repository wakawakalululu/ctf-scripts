# -*- coding: utf-8 -*-
"""hill.py — Hill 希尔密码加解密(n 阶矩阵 mod 26, 古典密码高频题)

规则: 明文按 n 个字母一组写成列向量, 密文 C = K·P mod 26;
      解密 P = K^-1·C mod 26, K^-1 用伴随矩阵/行列式逆元求出。
      经典向量(维基百科): K = [[6,24,1],[13,16,10],[20,17,15]],
      明文 ACT -> 密文 POH;  明文 CAT -> 密文 FIN。

用法:
    python hill.py -e "ACT" -k "6,24,1;13,16,10;20,17,15"   # 加密
    python hill.py -d POH -k "6,24,1;13,16,10;20,17,15"     # 解密
    python hill.py -e CAT -k "9,4;5,7"                      # 2 阶同样支持
    python hill.py --selftest                               # 内置自测
"""
import argparse
import sys


def parse_key(s):
    rows = []
    for part in s.split(';'):
        rows.append([int(x) % 26 for x in part.replace(',', ' ').split()])
    n = len(rows)
    if any(len(r) != n for r in rows):
        raise ValueError('密钥必须是 n×n 方阵')
    return rows


def mat_mul(a, b):
    n, m = len(a), len(b[0])
    return [[sum(a[i][k] * b[k][j] for k in range(len(b))) % 26
             for j in range(m)] for i in range(n)]


def minor(mat, i, j):
    return [[v for ci, v in enumerate(row) if ci != j]
            for ri, row in enumerate(mat) if ri != i]


def det_mod(mat):
    n = len(mat)
    if n == 1:
        return mat[0][0] % 26
    if n == 2:
        return (mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]) % 26
    total = 0
    for j in range(n):
        cof = mat[0][j] * det_mod(minor(mat, 0, j)) * (1 if j % 2 == 0 else -1)
        total += cof
    return total % 26


def inv_mod26(x):
    for y in range(26):
        if x * y % 26 == 1:
            return y
    raise ValueError('行列式 %d 在 mod 26 下不可逆(gcd!=1)' % x)


def inverse_matrix(mat):
    """通用 n 阶伴随矩阵法求 K^-1 mod 26。"""
    n = len(mat)
    d = det_mod(mat)
    inv = [[((-1) ** (i + j)) * det_mod(minor(mat, j, i)) % 26
            for j in range(n)] for i in range(n)]  # 伴随(已转置)
    k = inv_mod26(d)
    return [[k * v % 26 for v in row] for row in inv]


def to_matrix(text, n):
    text = ''.join(c for c in text.upper() if c.isalpha())
    if len(text) % n:
        text += 'X' * (n - len(text) % n)
    return [[ord(c) - 65 for c in text[i:i + n]]
            for i in range(0, len(text), n)]  # 每行一个列向量


def from_matrix(blocks):
    return ''.join(chr(v % 26 + 65) for blk in blocks for v in blk)


def encrypt(text, key):
    k = parse_key(key)
    return from_matrix(mat_mul(to_matrix(text, len(k)), [list(c) for c in zip(*k)]))


def decrypt(text, key):
    k = parse_key(key)
    ki = inverse_matrix(k)
    return from_matrix(mat_mul(to_matrix(text, len(ki)), [list(c) for c in zip(*ki)]))


def selftest():
    k3 = '6,24,1;13,16,10;20,17,15'
    k2 = '9,4;5,7'
    ok1 = encrypt('ACT', k3) == 'POH'
    ok2 = encrypt('CAT', k3) == 'FIN'
    back = decrypt(encrypt('ATTACKATDAWN', k2), k2) == 'ATTACKATDAWN'  # 12 字母偶数无填充
    ok = ok1 and ok2 and back
    print('Hill 3阶/2阶经典向量+回解:',
          'OK' if ok else 'FAIL (ACT=%r CAT=%r back=%r)' % (encrypt('ACT', k3), encrypt('CAT', k3), back))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='Hill 密码加解密')
    ap.add_argument('-e', '--encrypt', help='加密明文')
    ap.add_argument('-d', '--decrypt', help='解密密文')
    ap.add_argument('-k', '--key',
                    help='密钥矩阵, 行用 ; 分隔, 列用 , 或空格分隔')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.key or not (args.encrypt or args.decrypt):
        ap.error('需要 -k 密钥矩阵与 -e/-d 明文或密文(或 --selftest)')
    if args.encrypt:
        print(encrypt(args.encrypt, args.key))
    else:
        print(decrypt(args.decrypt, args.key))


if __name__ == '__main__':
    main()
