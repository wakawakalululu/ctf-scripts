# -*- coding: utf-8 -*-
"""hill_cipher.py 希尔密码(Hill Cipher)模 26 加解密

来源: WP 汇总/希尔密码类题目
用途: 密钥为 n×n 矩阵 a(模 26 可逆), 明文按列分块 m, 密文 c=a*m+b%26;
      解密需先求 a 的模 26 逆矩阵(行列式逆 + 伴随矩阵)。
      脚本内置示例: 加密 → 求逆 → 还原明文, 用于验证与套改参数。

依赖:
    pip install numpy

用法:
    python hill_cipher.py --selftest    # 自测(往返一致)
    python hill_cipher.py               # 跑脚本内示例(改 a/b/m 后复用)
"""
import argparse
import sys

import numpy as np
from numpy.linalg import det


def my_int_inv(mat, n=26):
    """矩阵各元素四舍五入取整后 mod n。"""
    x = np.zeros(mat.shape, dtype=np.int16)
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            x[i, j] = int(round(mat[i, j])) % n
    return x


def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


def exgcd(a, m):
    """扩展欧几里得求 a 模 m 的乘法逆元; 不互质返回 None。"""
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (
            u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def hill_encrypt(a, b, m):
    """c = a*m + b (mod 26)。"""
    return my_int_inv(a * m + b)


def hill_decrypt(a, b, c):
    """m = a^-1*(c - b) (mod 26), a^-1 通过行列式逆×伴随矩阵构造。"""
    a_inv = a.I
    a_det = det(a)
    a_adju = my_int_inv(a_det * a_inv)
    a_det_inv = exgcd(int(round((det(a) % 26))), 26)
    aa_inv = my_int_inv(a_det_inv * a_adju)
    return (aa_inv * (c - b)) % 26


def selftest():
    ok = True
    # 3x3 密钥矩阵(行列式为 1, 模 26 可逆), 与 3 行明文矩阵维度对齐
    a = np.asmatrix([[1, 2, 3], [0, 1, 4], [5, 6, 0]])
    b = np.asmatrix([[0], [0], [0]])
    m = np.asmatrix([[24, 17, 13, 8, 14], [14, 15, 13, 18, 20], [20, 8, 14, 5, 17]])
    c = hill_encrypt(a, b, m)
    rec = hill_decrypt(a, b, c)
    ok &= (my_int_inv(rec) == my_int_inv(m)).all()
    print('密文矩阵:\n%s\n还原明文矩阵:\n%s' % (c, rec))
    print('[%s] hill_cipher.py 自测' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='希尔密码模 26 加解密示例')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()

    # 示例(套题时改 a/b/m 即可; 注意 a 行数须等于 m 行数, 且 det(a) 与 26 互质)
    a = np.asmatrix([[1, 2, 3], [0, 1, 4], [5, 6, 0]])
    b = np.asmatrix([[0], [0], [0]])
    m = np.asmatrix([[24, 17, 13, 8, 14], [14, 15, 13, 18, 20], [20, 8, 14, 5, 17]])
    c = hill_encrypt(a, b, m)
    print('密文矩阵:\n%s' % c)
    print('还原明文矩阵:\n%s' % hill_decrypt(a, b, c))
    return 0


if __name__ == '__main__':
    sys.exit(main())
