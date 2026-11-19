# -*- coding: utf-8 -*-
"""xor.py 相邻字符异或链还原 flag(逆向题常见编码)

来源: Des-CTF-Knowledge/CTF常用脚本及工具/reverse/xor
用途: 逆向题把 flag 编码成 s[0]=flag[0]、s[i]=flag[i]^s[i-1](每位与前一
      **编码值**异或的累积链)。解码: flag[i] = s[i] ^ s[i-1]。
      数字元素按字符处理;核心性质 a^b=c 等价于 a^c=b。

用法:
    python xor.py --selftest                # 自测(对已知 flag 编码后还原比对)
    python xor.py                           # 解脚本内内置数据(原题 flag)
    # 实战: 把逆向出的数组替换 S 后运行
"""
import argparse
import sys

# 逆向 dump 出来的异或链数据(混合字符与数字)
S = ['f', 0xA, 'k', 0xC, 'w', '&', 'O', '.', '@', 0x11, 'x', 0xD,
     'Z', ';', 'U', 0x11, 'p', 0x19, 'F', 0x1F, 'v', '"', 'M', '#',
     'D', 0xE, 'g', 6, 'h', 0xF, 'G', '2', 'O']


def encode(flag):
    """编码: s[0]=flag[0], s[i]=flag[i]^s[i-1](累积异或链)。"""
    s = [flag[0]]
    prev = ord(flag[0])
    for i in range(1, len(flag)):
        prev = ord(flag[i]) ^ prev
        s.append(prev)
    return s


def decode(s):
    """解码: 首字符不变, 其后 flag[i] = s[i] ^ s[i-1](数字先转字符)。"""
    chars = list(s)
    flag = chars[0]
    # 将数字元素转为字符
    for i in range(1, len(chars)):
        if isinstance(chars[i], int):
            chars[i] = chr(chars[i])
    for i in range(1, len(chars)):
        flag += chr(ord(chars[i]) ^ ord(chars[i - 1]))
    return flag


def selftest():
    ok = True
    # 用已知明文构造异或链, 再还原比对
    target = 'flag{xor_chain_1}'
    got = decode(encode(target))
    ok &= (got == target)
    print('builtin : %r' % decode(S))
    print('roundtrip: %r' % got)
    print('[%s] xor.py 自测' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='相邻字符异或链还原')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    print(decode(S))
    return 0


if __name__ == '__main__':
    sys.exit(main())
