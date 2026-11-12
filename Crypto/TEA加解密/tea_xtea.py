# -*- coding: utf-8 -*-
"""tea_xtea TEA / XTEA 加解密(64位块, 128位密钥)

用途: Crypto/Reverse 题常见 TEA 系算法, 直接加解密或对照逆向出来的轮函数。
      输入输出均为 hex, 多块按 ECB 顺序处理。

用法:
    python tea_xtea.py --selftest                        # 自测
    python tea_xtea.py --algo xtea -a d -k 0123456789abcdef0123456789abcdef -c <hex密文>
    python tea_xtea.py --algo tea  -a e -k <32位hex密钥> -p <8的倍数hex明文>
    python tea_xtea.py --algo tea -a e -k ... -p ... --delta 0x9e3779b9 --rounds 32
"""
import argparse
import struct
import sys

DELTA = 0x9E3779B9
SUM0 = 0
M32 = 0xFFFFFFFF


def _enc(v0, v1, key, rounds, delta):
    s = 0
    k0, k1, k2, k3 = key
    for _ in range(rounds):
        s = (s + delta) & M32
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & M32
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & M32
    return v0, v1


def _dec(v0, v1, key, rounds, delta):
    s = (delta * rounds) & M32
    k0, k1, k2, k3 = key
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & M32
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & M32
        s = (s - delta) & M32
    return v0, v1


def _xenc(v0, v1, key, rounds, delta):
    s = 0
    k = list(key)
    for _ in range(rounds):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M32
        s = (s + delta) & M32
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M32
    return v0, v1


def _xdec(v0, v1, key, rounds, delta):
    k = list(key)
    s = (delta * rounds) & M32
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M32
        s = (s - delta) & M32
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M32
    return v0, v1


ALGOS = {
    'tea': (_enc, _dec, 32),
    'xtea': (_xenc, _xdec, 32),
}


def crypt_blocks(data: bytes, key: bytes, algo: str, enc: bool,
                 delta: int = DELTA, rounds: int = 32) -> bytes:
    if len(data) % 8:
        raise ValueError('数据长度需为 8 的倍数(TEA 系按 64 位块)')
    e, d, _def_rounds = ALGOS[algo]
    rounds = rounds or _def_rounds
    words = list(struct.unpack('>%dI' % (len(data) // 4), data))
    keyw = struct.unpack('>4I', key)
    out = []
    for i in range(0, len(words), 2):
        v0, v1 = words[i], words[i + 1]
        v0, v1 = (e if enc else d)(v0, v1, keyw, rounds, delta)
        out += [v0, v1]
    return struct.pack('>%dI' % len(out), *out)


def _parse_key(s):
    if len(s) == 32:
        return bytes.fromhex(s)
    raw = s.encode('utf-8')
    if len(raw) <= 16:
        return raw.ljust(16, b'\x00')
    raise ValueError('密钥需 32 位 hex 或 <=16 字节字符串')


def main():
    ap = argparse.ArgumentParser(description='TEA/XTEA 加解密')
    ap.add_argument('--algo', choices=['tea', 'xtea'], default='xtea')
    ap.add_argument('-a', '--action', choices=['e', 'd'], default='d')
    ap.add_argument('-k', '--key', default='', help='16字节: 32位hex或短字符串')
    ap.add_argument('-c', '--cipher', default='', help='hex 密文(解密)')
    ap.add_argument('-p', '--plain', default='', help='hex 明文(加密)')
    ap.add_argument('--delta', type=lambda x: int(x, 0), default=DELTA)
    ap.add_argument('--rounds', type=int, default=0, help='轮数(默认 32)')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        ok = True
        key = bytes(range(16))
        for algo in ('tea', 'xtea'):
            for rounds in (16, 32, 64):
                for data in (b'flag{te}', b'ABCDEFGH' * 3, b'\x00' * 8):
                    ct = crypt_blocks(data, key, algo, True, rounds=rounds)
                    back = crypt_blocks(ct, key, algo, False, rounds=rounds)
                    good = back == data and ct != data
                    ok &= good
                    if not good:
                        print(f"[FAIL] {algo} rounds={rounds} data={data!r}")
            ct = crypt_blocks(b'flag{tea_xtea_roundtrip}', key, algo, True)
            back = crypt_blocks(ct, key, algo, False)
            good = back == b'flag{tea_xtea_roundtrip}'
            ok &= good
            print(f"[{'OK' if good else 'FAIL'}] {algo} 32轮回环: {ct.hex()[:32]}...")
        # 非默认 delta/rounds 回环
        ct = crypt_blocks(b'\x01\x02\x03\x04\x05\x06\x07\x08', key, 'tea', True,
                          delta=0x11111111, rounds=16)
        back = crypt_blocks(ct, key, 'tea', False, delta=0x11111111, rounds=16)
        good = back == b'\x01\x02\x03\x04\x05\x06\x07\x08'
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 自定义 delta/rounds 回环")
        sys.exit(0 if ok else 1)

    key = _parse_key(args.key)
    if args.action == 'e':
        if not args.plain:
            ap.error('加密需要 -p hex明文')
        data = bytes.fromhex(args.plain)
        print(crypt_blocks(data, key, args.algo, True, args.delta, args.rounds).hex())
    else:
        if not args.cipher:
            ap.error('解密需要 -c hex密文')
        data = bytes.fromhex(args.cipher)
        print(crypt_blocks(data, key, args.algo, False, args.delta, args.rounds).hex())

if __name__ == '__main__':
    main()
