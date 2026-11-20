# -*- coding: utf-8 -*-
"""cyclic_offset.py — 栈溢出偏移定位(De Bruijn 模式, pwn 高频辅助)

用途: 与 pwntools cyclic 同源的 De Bruijn 序列生成/偏移定位:
      1. --gen N 生成 N 字节循环模式喂给溢出点;
      2. 程序崩溃后取 RSP/EIP 处覆盖值(如 0x62616164 或 'daaa'),
         --find 直接算出精确偏移, 免调试数 padding;
      3. 默认字母表 a-z、子序列长 4, 与 pwnlib cyclic/cyclic_find 通用。

用法:
    python cyclic_offset.py --gen 200                 # 生成 200 字节模式
    python cyclic_offset.py --find daaa               # 由字符串定偏移
    python cyclic_offset.py --find 0x62616164         # 由十六进制值定偏移
    python cyclic_offset.py --find b'aaba' --n 4      # 任意子序列长
    python cyclic_offset.py --selftest                # 内置自测
"""
import argparse
import struct
import sys

ALPHABET = 'abcdefghijklmnopqrstuvwxyz'


def de_bruijn(alphabet, n):
    """字典序最小的 de Bruijn 序列(与 pwnlib cyclic 同构)。"""
    k = len(alphabet)
    a = [0] * (k * n + 1)
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return ''.join(alphabet[i] for i in seq)


class Finder(object):
    def __init__(self, n=4, alphabet=ALPHABET):
        self.n = n
        self.seq = de_bruijn(alphabet, n)

    def gen(self, length):
        return (self.seq * ((length // len(self.seq)) + 1))[:length]

    def find(self, value):
        if isinstance(value, int):
            width = 8 if value > 0xFFFFFFFF else 4
            value = struct.pack('<Q' if width == 8 else '<I', value)
            value = value.decode('latin1')
        value = value.rstrip('\x00')
        if len(value) < 2:
            raise ValueError('定位串太短')
        idx = self.seq.find(value)
        if idx < 0:
            # 崩溃值可能被寄存器截断/大小端相反, 再试一次倒序
            idx = self.seq.find(value[::-1])
        return idx


def selftest():
    f = Finder(4)
    ok1 = f.seq.startswith('aaaabaaacaaadaaa')       # 与 pwnlib cyclic(16) 同前缀
    pat = f.gen(500)
    ok2 = f.find(pat[137:137 + 4]) == 137            # 任意位置自洽
    ok3 = f.find(0x62616164) == f.find('daab')       # hex 小端等价于字符串
    ok4 = f.find(0x61616161) == 0                    # 模式开头即 0
    ok = ok1 and ok2 and ok3 and ok4
    print('De Bruijn 生成/偏移定位(4字节):',
          'OK' if ok else 'FAIL (%r %r %r %r)' % (ok1, ok2, ok3, ok4))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='栈溢出偏移定位')
    ap.add_argument('--gen', type=int, metavar='N', help='生成 N 字节循环模式')
    ap.add_argument('--find', metavar='V', help='崩溃覆盖值(字符串或 0x 十六进制)')
    ap.add_argument('--n', type=int, default=4, help='子序列长度(默认 4, 与 pwn cyclic 一致)')
    ap.add_argument('--save', help='模式写入文件(供脚本发送)')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    f = Finder(args.n)
    if args.gen:
        pat = f.gen(args.gen)
        if args.save:
            with open(args.save, 'wb') as fh:
                fh.write(pat.encode('latin1'))
            print('模式已写入 %s (%d 字节)' % (args.save, len(pat)))
        else:
            print(pat)
    elif args.find:
        v = args.find
        if v.startswith('0x'):
            v = int(v, 16)
        off = f.find(v)
        if off < 0:
            print('[-] 未命中: %r 不在模式中(检查 n 是否一致)' % v)
            sys.exit(1)
        print('[+] 偏移 = %d' % off)
    else:
        ap.error('需要 --gen/--find(或 --selftest)')


if __name__ == '__main__':
    main()
