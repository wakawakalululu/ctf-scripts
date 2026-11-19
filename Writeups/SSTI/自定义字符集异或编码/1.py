# -*- coding: utf-8 -*-
"""1.py SSTI 自定义字符集异或编码还原([pasecactf_2019]flask_ssti)

来源: WP 汇总/pasecactf 2019 flask_ssti 编码绕过
用途: 题目 payload 被两套自定义字符集 + 下标异或编码时, 用同一函数逆运算还原明文。
      encode 为自逆运算: 对编码结果再套一次同参数 encode 即得原文。

用法:
    python 1.py              # 还原脚本内置密文
    python 1.py --selftest   # 内置自测(断言自逆性 + 密文可解为可打印 ASCII)
    python 1.py -c <密文> -k <key1> -k2 <key2>
"""
import argparse
import sys

KEY1 = 'GQIS5EmzfZA1Ci8NslaoMxPXqrvFB7hYOkbg9y20W3'
KEY2 = 'xwdFqMck1vA0pl7B8WO3DrGLma4sZ2Y6ouCPEHSQVT'

# 题目原始密文(源码里的 \@ 即字符 '@')
CIPHER = ('-M7\x10wI`7k\x07!5r\x0eF\x0enS(D\x10\x1d\x0c\x17x?\x01c\x02\\'
          '@\x0cqW"{A<@\x0f\x19G')


def encode(line, key, key2):
    """编码/解码共用: 每位与(下标 ^ key倒序 ^ key2)异或, 自逆。"""
    return ''.join(chr(x ^ ord(line[x]) ^ ord(key[::-1][x]) ^ ord(key2[x]))
                   for x in range(len(line)))


def selftest():
    ok = True
    # 1) 自逆性: encode(encode(m)) == m
    m = '{{ [].__class__ }}'
    ok &= (encode(encode(m, KEY1, KEY2), KEY1, KEY2) == m)
    # 2) 内置密文可解出可打印 ASCII(即原题 flag)
    plain = encode(CIPHER, KEY1, KEY2)
    ok &= all(32 <= ord(c) < 127 for c in plain)
    print('decoded : %r' % plain)
    print('[%s] 1.py 自测' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='SSTI 自定义字符集异或编码还原')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    ap.add_argument('-c', '--cipher', default=CIPHER, help='待还原的密文')
    ap.add_argument('-k', '--key', default=KEY1, help='key1(原顺序)')
    ap.add_argument('-k2', '--key2', default=KEY2, help='key2')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    print(encode(args.cipher, args.key, args.key2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
