# -*- coding: utf-8 -*-
"""factordb 在线分解 n + 本地试除兜底(补充题型: Crypto/RSA)

用途:
    RSA 题目拿到 n 先查 factordb.com; 已完全分解(状态 FF)时直接取 p/q。
    网络不通时, 对小 n (<= 1e7 或可被 1e6 内素数整除) 本地试除兜底。

依赖:
    pip install requests  (离线兜底不需要)

用法:
    python factordb.py                         # 自测
    python factordb.py -n 3229076...           # 在线查询
    python factordb.py -n 1234567 --local      # 强制本地试除
"""
import argparse
import math
import sys

SMALL_PRIMES = []


def _sieve(limit: int):
    is_p = bytearray([1]) * (limit + 1)
    is_p[0:2] = b'\x00\x00'
    for i in range(2, int(limit ** 0.5) + 1):
        if is_p[i]:
            is_p[i * i::i] = bytearray(len(is_p[i * i::i]))
    return [i for i in range(2, limit + 1) if is_p[i]]


def local_factor_small(n: int, prime_limit: int = 1_000_000):
    """本地小素数试除 + Pollard rho 兜底, 适合 CTF 常见弱 n。"""
    global SMALL_PRIMES
    if not SMALL_PRIMES:
        SMALL_PRIMES = _sieve(min(prime_limit, 100_000))
    factors = []
    for p in SMALL_PRIMES:
        if p * p > n:
            break
        while n % p == 0:
            factors.append(p)
            n //= p
    if n > 1:
        # Pollard rho 找非平凡因子(对中等规模 n 有效)
        d = _pollard_rho(n)
        if d:
            factors.extend(sorted([d, n // d]))
        else:
            factors.append(n)
    return factors


def _pollard_rho(n: int):
    if n % 2 == 0:
        return 2
    import random
    for _ in range(20):
        x = random.randrange(2, n - 1)
        y, c, d = x, random.randrange(1, n - 1), 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d
    return None


def factordb_query(n: int, timeout: int = 15):
    """在线查询 factordb。返回 (status, [因子...]); status: FF=完全分解。

    API 返回格式: {"status":"FF","factors":[["73","1"],["137","1"]]} -> 73^1 * 137^1
    """
    import requests
    r = requests.get('https://factordb.com/api', params={'query': str(n)}, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    status = data.get('status', '')
    factors = []
    for item in data.get('factors', []):
        if isinstance(item, (list, tuple)) and len(item) == 2:
            factors.append(int(item[0]) ** int(item[1]))
        else:
            factors.append(int(item))
    return status, factors


def split_pq(factors):
    """把因子列表合并成两个大数 p, q(假设 n = p*q, 且 factordb 已完全分解)。"""
    if len(factors) < 2:
        return None
    factors = sorted(factors)
    if len(factors) == 2:
        return factors[0], factors[1]
    # >2 个因子: 取其余全部乘积作为 q
    return factors[0], math.prod(factors[1:])


def main():
    ap = argparse.ArgumentParser(description='factordb 查询分解 n')
    ap.add_argument('-n', type=int, help='要分解的 n')
    ap.add_argument('--local', action='store_true', help='强制本地分解(不联网)')
    args = ap.parse_args()

    if args.n:
        n = args.n
        if args.local:
            fs = local_factor_small(n)
            print('本地分解:', ' * '.join(map(str, fs)))
        else:
            try:
                status, factors = factordb_query(n)
                print(f'factordb status={status} factors={factors}')
                if status == 'F':
                    print('状态 F: 因子已知但未验完; FF: 完全分解')
                if status == 'FF':   # 只有完全分解才能拆出 p/q, 否则因子里可能还有合数
                    pq = split_pq(factors)
                    if pq:
                        print(f'p = {pq[0]}\nq = {pq[1]}')
                else:
                    print('状态非 FF, 跳过 p/q 输出(因子可能含合数)')
            except Exception as e:
                print(f'在线查询失败({e}), 尝试本地兜底...')
                fs = local_factor_small(n)
                print('本地分解:', ' * '.join(map(str, fs)))
    else:
        # 自测
        ok = True
        p, q = 1000000007, 998244353   # 两个已验证素数
        n = p * q
        fs = local_factor_small(n)
        good = math.prod(fs) == n and set(fs) == {p, q}
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] Pollard rho: n 的因子 = {fs}")
        n2 = 10001  # 小数试除: 73 * 137
        fs2 = local_factor_small(n2)
        good2 = set(fs2) == {73, 137}
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] 试除: 10001 = {' * '.join(map(str, fs2))}")
        try:
            status, factors = factordb_query(n2)
            pq = split_pq(factors)
            good3 = pq == (73, 137)
            ok &= good3
            print(f"[{'OK' if good3 else 'FAIL'}] factordb 在线: status={status} p,q={pq}")
        except Exception as e:
            print(f'[SKIP] factordb 在线不可达: {e}')
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
