# -*- coding: utf-8 -*-
"""yunying.py — 云影密码(0/8 密码)编解码(攻防世界等平台高频 misc)

规则: 密文是一串数字, 以 0 为分隔符; 每段内**数字求和**得到字母序号
      (1=A, 2=B, ..., 26=Z)。段内一般由 8/4/2/1 组成(即把序号按二进制权重
      拆开, 如 22 -> "8884 2"? 不, 22 = 8+8+4+2 -> "88842")。
      例: "881" -> 8+8+1 = 17 -> Q; "8" -> 8 -> H。
      解密: split('0') 后逐段求和 + 64 转字母(序号 >26 时报出位置)。

用法:
    python yunying.py -d "8842101226885448"     # 解密(字符串里有 0 即可)
    python yunying.py -e HELLOCTF               # 加密
    python yunying.py -d "$(cat cipher.txt)"    # 从文件来先 cat
    python yunying.py --selftest                # 内置自测
"""
import argparse
import sys


def decode(cipher):
    """0 分隔逐段求和 -> 字母。返回 (明文, 异常段列表)。"""
    plain, bad = [], []
    for seg in cipher.strip().split('0'):
        if not seg:
            continue
        try:
            total = sum(int(c) for c in seg if c.isdigit())
        except ValueError:
            bad.append(seg)
            continue
        if 1 <= total <= 26:
            plain.append(chr(total + 64))
        elif total == 0:
            continue
        else:
            bad.append('%s(和=%d)' % (seg, total))
    return ''.join(plain), bad


def encode(text):
    """字母 -> 数字段(贪心: 8/4/2/1), 用 0 连接, 末尾补 0。"""
    out = []
    for ch in text.upper():
        if ch == '_':
            out.append('0')
            continue
        if not ('A' <= ch <= 'Z'):
            continue
        n = ord(ch) - 64
        seg = ''
        for w in (8, 4, 2, 1):
            while n >= w:
                seg += str(w)
                n -= w
        out.append(seg)
    return '0'.join(out) + '0'


def selftest():
    ok = True
    # 手算样例: 811=10->J, 88=16->P, 8=8->H, 8842=22->V
    p1, bad1 = decode('8110880808842')
    ok &= (p1 == 'JPHV')
    ok &= not bad1
    ok &= decode('8')[0] == 'H' and decode('11')[0] == 'B' and decode('8842')[0] == 'V'
    # 越界检测: 段和 72 > 26
    _, bad2 = decode('8888888880')
    ok &= len(bad2) == 1
    # 加解密 roundtrip
    for word in ('HELLOCTF', 'YUNYING', 'FLAGISHERE'):
        ok &= decode(encode(word))[0] == word
    print('decode("8110880808842") -> %r  bad=%r' % (p1, bad1))
    print('encode("HELLOCTF")    -> %r' % encode('HELLOCTF'))
    print('[%s] yunying.py 自测' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='云影密码(0/8)编解码')
    ap.add_argument('-d', '--decode', help='解密密文(数字串)')
    ap.add_argument('-e', '--encode', dest='enc', help='加密明文(字母)')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    if args.decode:
        plain, bad = decode(args.decode)
        print('明文: %s' % plain)
        if bad:
            print('[!] 异常段(和>26): %s' % bad)
        return 0
    if args.enc:
        print('密文: %s' % encode(args.enc))
        return 0
    print('用法: python yunying.py -d "8842101226885448" | -e HELLOCTF | --selftest')
    return 1


if __name__ == '__main__':
    sys.exit(main())
