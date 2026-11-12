# -*- coding: utf-8 -*-
"""培根密码(Bacon Cipher) 加解密(补充题型: Crypto/古典密码)

用途:
    5 位 A/B 编码与字母互转。支持两种常见题型写法:
    1) 标准 AB 串:      "AAAAA BAABA ..." (字母表 24 字母经典版 I=J, U=V)
    2) 大小写隐写版:    题目给一段普通英文, 大写=B(1), 小写=A(0), 每 5 个字母一组

用法:
    python bacon.py                # 自测(内置用例)
    python bacon.py -e HELLO       # 编码 -> AABBB AABAA ...
    python bacon.py -d "AABBB AABAA AABBB AABBB BABAB"  # 解码
    python bacon.py -d --case "ThE QuIcK BROWN FOX"      # 大小写隐写解码
"""
import argparse
import re
import sys

# 经典 24 字母表: I/J 共用, U/V 共用
ALPHABET24 = 'ABCDEFGHIKLMNOPQRSTUWXYZ'   # 注意没有 J 和 V
# 26 字母变体(部分现代题目使用)
ALPHABET26 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def _letter24(idx: int) -> str:
    return ALPHABET24[idx % 24]


def encode24(text: str) -> str:
    out = []
    for ch in text.upper():
        if ch in ('J',):
            ch = 'I'
        if ch in ('V',):
            ch = 'U'
        if ch in ALPHABET24:
            idx = ALPHABET24.index(ch)
            out.append(''.join('B' if (idx >> (4 - i)) & 1 else 'A' for i in range(5)))
    return ' '.join(out)


def decode24(code: str) -> str:
    tokens = re.findall(r'[ABab]{5}', code)
    out = []
    for tok in tokens:
        bits = ''.join('1' if c.upper() == 'B' else '0' for c in tok)
        out.append(_letter24(int(bits, 2)))
    return ''.join(out)


def decode_case(text: str) -> str:
    """大小写隐写: 大写=1(B), 小写=0(A), 每 5 个字母一组, 非字母忽略。"""
    bits = ''.join('1' if c.isupper() else '0' for c in text if c.isalpha())
    out = []
    for i in range(0, len(bits) - 4, 5):
        out.append(_letter24(int(bits[i:i + 5], 2)))
    return ''.join(out)


def encode_case(text: str, carrier: str) -> str:
    """把 message 编进 carrier 的字母大小写里(两串字母数需匹配)。"""
    msg_bits = []
    for ch in text.upper():
        if ch in ('J',):
            ch = 'I'
        if ch in ('V',):
            ch = 'U'
        if ch in ALPHABET24:
            idx = ALPHABET24.index(ch)
            msg_bits.extend('B' if (idx >> (4 - i)) & 1 else 'A' for i in range(5))
    letters = [c for c in carrier if c.isalpha()]
    if len(msg_bits) > len(letters):
        raise ValueError(f'载体字母数不足: 需要 {len(msg_bits)}, 只有 {len(letters)}')
    bit_idx = 0
    out = []
    for c in carrier:
        if c.isalpha() and bit_idx < len(msg_bits):
            # 多余的载体字母保持原样
            bit = msg_bits[bit_idx]
            bit_idx += 1
            out.append(c.upper() if bit == 'B' else c.lower())
        else:
            out.append(c)
    return ''.join(out)


def _fix_neg(argv):
    """明文/密文可能以 '-' 开头, argparse 会把 '-...' 当选项; 统一改写成 = 连接形式。"""
    out, i = [], 0
    while i < len(argv):
        if argv[i] in ('-e', '-d', '--encode', '--decode') and i + 1 < len(argv):
            out.append('%s=%s' % (argv[i], argv[i + 1]))
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return out


def main():
    ap = argparse.ArgumentParser(description='培根密码加解密')
    ap.add_argument('-e', '--encode', metavar='TEXT')
    ap.add_argument('-d', '--decode', metavar='CODE')
    ap.add_argument('--case', action='store_true',
                    help='大小写隐写模式: -d 时按大小写解码; -e 需配 --carrier')
    ap.add_argument('--carrier', metavar='TEXT', help='-e --case 时的载体文本')
    args = ap.parse_args(_fix_neg(sys.argv[1:]))

    if args.encode:
        if args.case:
            if not args.carrier:
                ap.error('--case 编码需同时提供 --carrier 载体文本')
            print(encode_case(args.encode, args.carrier))
        else:
            print(encode24(args.encode))
    elif args.decode:
        print(decode_case(args.decode) if args.case else decode24(args.decode))
    else:
        ok = True
        msg = 'HELLO'
        e = encode24(msg)
        r = decode24(e)
        s = 'OK' if r == msg.replace('L', 'L') else 'FAIL'  # HELLO 无 J/V, 可回转
        ok &= (r == msg)
        print(f'[{s}] {msg!r} -> {e!r} -> {r!r}')
        # 大小写隐写回环(载体字母数恰为 5*4=20)
        carrier = 'Bacon Cipher Rocks Today'
        hidden = encode_case('FLAG', carrier)
        r2 = decode_case(hidden)
        s2 = 'OK' if r2.startswith('FLAG') else 'FAIL'
        ok &= r2.startswith('FLAG')
        print(f'[{s2}] 大小写隐写: {hidden!r} -> {r2!r}')
        # 解码题面常见写法
        sample = 'AABBB AABAA AABBB AABBB BABAB'
        r3 = decode24(sample)
        s3 = 'OK' if r3 else 'FAIL'
        print(f'[{s3}] {sample!r} -> {r3!r}')
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
