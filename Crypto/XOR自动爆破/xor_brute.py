# -*- coding: utf-8 -*-
"""XOR 爆破工具(补充题型: Crypto/Reverse 通用)

用途:
    1) 单字节 XOR 爆破: 256 个 key 全试, 按可打印比例排序, 优先显示含 flag 的结果
    2) 已知明文 crib 推导重复密钥: 已知明文前缀(如 "flag{")直接推出 key
    3) 重复密钥 XOR 解密: 用推导出的 key 解整段密文

输入格式:
    hex 字符串(如 3a2f...) 或 逗号分隔的十进制字节(如 58,47,...) 或 直接字节串

用法:
    python xor_brute.py                 # 自测(内置用例)
    python xor_brute.py -c 3a2f5e...    # 单字节爆破(hex)
    python xor_brute.py -c "..." --flag flag  # 指定标记
    python xor_brute.py -c "..." --crib "flag{" --repeat  # 明文推导重复密钥并解密
"""
import argparse
import re
import sys

FLAG_RE = re.compile(rb'(flag|ctf|key|FLAG|CTF|KEY|F1ag)[\{\-_0-9a-zA-Z]*')


def parse_cipher(s: str) -> bytes:
    s = s.strip()
    if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0 and len(s) >= 8:
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    if ',' in s:
        return bytes(int(x, 0) for x in s.split(','))
    return s.encode('latin-1')


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    good = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return good / len(b)


def single_byte_brute(cipher: bytes, marker: str = 'flag') -> list:
    """返回 [(score, key, plain), ...] 按分数降序。"""
    results = []
    pat = re.compile(re.escape(marker.encode())) if marker else None
    for k in range(256):
        plain = bytes(c ^ k for c in cipher)
        score = printable_ratio(plain)
        if pat and pat.search(plain):
            score += 10.0
        m = FLAG_RE.search(plain)
        if m:
            score += 5.0
        if score >= 0.9:
            results.append((score, k, plain))
    results.sort(reverse=True, key=lambda t: (round(t[0], 3), t[1]))
    return results


def derive_repeating_key(cipher: bytes, crib: bytes, keylen: int = 0) -> bytes:
    """已知明文前缀推出重复密钥。keylen 缺省 = len(crib) 但至少 1。"""
    keylen = max(keylen, 1) if keylen else max(len(crib), 1)
    key = bytearray(keylen)
    for i, pc in enumerate(crib):
        key[i % keylen] = cipher[i] ^ pc
    return bytes(key)


def xor_repeating(cipher: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(cipher))


def main():
    ap = argparse.ArgumentParser(description='XOR 爆破')
    ap.add_argument('-c', '--cipher', help='密文: hex / 逗号分隔十进制 / 原始串')
    ap.add_argument('--flag', default='flag', help='标记关键字(默认 flag)')
    ap.add_argument('--crib', help='已知明文前缀(如 flag{)')
    ap.add_argument('--repeat', action='store_true', help='使用重复密钥解密')
    ap.add_argument('--keylen', type=int, default=0, help='重复密钥长度')
    args = ap.parse_args()

    if args.cipher:
        cipher = parse_cipher(args.cipher)
        if args.crib:
            key = derive_repeating_key(cipher, args.crib.encode(), args.keylen)
            print(f'推导密钥: {key.hex()} ({key!r})')
            print('解密结果:', xor_repeating(cipher, key).decode('latin-1'))
        else:
            results = single_byte_brute(cipher, marker=args.flag)
            if not results:
                print('无可打印候选, 可尝试 --crib 重复密钥模式')
            for score, k, plain in results[:10]:
                print(f'score={score:6.2f} key=0x{k:02x} ({k})  {plain.decode("latin-1")}')
    else:
        # 自测
        ok = True
        secret = b'flag{x0r_1s_e4sy}'
        # 用例1: 单字节
        ct1 = bytes(c ^ 0x37 for c in secret)
        res = single_byte_brute(ct1)
        hit = any(plain == secret for _, _, plain in res[:3])
        ok &= hit
        print(f"[{'OK' if hit else 'FAIL'}] 单字节爆破 0x37: {res[:1]}")
        # 用例2: 重复密钥 crib 推导
        key = b'KEY!'
        ct2 = xor_repeating(secret, key)
        got = derive_repeating_key(ct2, b'flag{', keylen=len(key))
        good = got == key
        ok &= good
        back = xor_repeating(ct2, got)
        good2 = back == secret
        ok &= good2
        print(f"[{'OK' if good and good2 else 'FAIL'}] 重复密钥推导: key={got!r} -> {back!r}")
        # 用例3: 十进制逗号输入
        ct3 = ','.join(str(c ^ 0x11) for c in b'flag{dec_input}')
        res3 = single_byte_brute(parse_cipher(ct3))
        hit3 = any(b'flag{dec_input}' in p for _, _, p in res3[:3])
        ok &= hit3
        print(f"[{'OK' if hit3 else 'FAIL'}] 逗号十进制输入解析")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
