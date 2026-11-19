# -*- coding: utf-8 -*-
"""affine_cipher.py 仿射密码加密与爆破(带模 26 逆元表)

来源: WP 汇总/仿射密码类题目(Affine Cipher)
用途: 仿射密码 E(x)=(a*x+b)%26, a 与 26 互质才有解。提供:
      1) 指定 a、b 加密; 2) 密文 a、b 全组合爆破, 按 flag 前缀特征筛选明文。

用法:
    python affine_cipher.py --selftest                       # 自测(加密后爆破还原)
    python affine_cipher.py -e -m "flag{hello}" -a 5 -b 8    # 加密
    python affine_cipher.py -c "密文" --marker flag          # 爆破, 筛出含 marker 前缀的
"""
import argparse
import sys

# a 与 26 的模逆: a -> a^-1 mod 26(仅列互质的 a)
MOD_INV = {1: 1, 3: 9, 5: 21, 7: 15, 9: 3, 11: 19, 15: 7,
           17: 23, 19: 11, 21: 5, 23: 17, 25: 25}


def encrypt(clear_content, key_a, key_b):
    """仿射加密 E(x)=(a*x+b)%26, 非字母原样保留。"""
    result = ""
    for i in clear_content:
        if 65 <= ord(i) <= 90:
            result += chr(((key_a * (ord(i) - 65) + key_b) % 26) + 65)
        elif 97 <= ord(i) <= 122:
            result += chr(((key_a * (ord(i) - 97) + key_b) % 26) + 97)
        else:
            result += i
    return result


def blasting(cipher, markers=('key', 'ctf', 'fla'), verbose=False):
    """对(逆元 a, b)全组合解密, 返回前缀命中 markers 的明文列表。"""
    lis, flag = [], []
    result = ""
    a = 1
    for i in MOD_INV.keys():
        for j in range(0, 26):
            for s in cipher:
                if 65 <= ord(s) <= 90:
                    result += chr(((MOD_INV.get(i) * (ord(s) - 65)
                                    - (MOD_INV.get(i) * j) % 26) % 26) + 65)
                elif 97 <= ord(s) <= 122:
                    result += chr(((MOD_INV.get(i) * (ord(s) - 97)
                                    - (MOD_INV.get(i) * j) % 26) % 26) + 97)
                else:
                    result += s
            if verbose:
                print('明文' + str(a) + ' : ' + result)
                a += 1
            if result[:3].lower() in markers:
                flag.append(result)
            result = ""
    return flag


def selftest():
    ok = True
    cipher = encrypt('flag{affine}', 5, 8)  # 5 与 26 互质
    found = blasting(cipher, markers=('fla',))
    ok &= any(f == 'flag{affine}' for f in found)
    print('[%s] affine_cipher.py 自测(密文 %r -> 还原 %s)'
          % ('OK' if ok else 'FAIL', cipher, found[:3]))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='仿射密码加密/爆破')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    ap.add_argument('-e', action='store_true', help='加密模式(默认爆破)')
    ap.add_argument('-m', '--msg', help='加密明文')
    ap.add_argument('-a', type=int, default=5, help='加密密钥 a(须与 26 互质)')
    ap.add_argument('-b', type=int, default=8, help='加密密钥 b')
    ap.add_argument('-c', '--cipher', help='待爆破密文')
    ap.add_argument('--marker', action='append', default=['key', 'ctf', 'fla'],
                    help='明文前缀特征, 可多次指定')
    ap.add_argument('-v', '--verbose', action='store_true', help='打印全部候选')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    if args.e:
        if not args.msg:
            ap.error('加密模式需要 -m 明文')
        print('密文为:%s' % encrypt(args.msg, args.a, args.b))
        return 0
    if not args.cipher:
        ap.error('爆破模式需要 -c 密文')
    hits = blasting(args.cipher, tuple(m.lower() for m in args.marker),
                    args.verbose)
    print('程序判定flag为:')
    for h in hits:
        print(h)
    return 0


if __name__ == '__main__':
    sys.exit(main())
