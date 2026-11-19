# -*- coding: utf-8 -*-
"""EasySearch.py MD5 前缀爆破([BJDCTF2020]EasySearch)

来源: WP 汇总/[BJDCTF2020]EasySearch
用途: 题目要求提供 md5(附加串) 前缀满足条件的字符串(如以 deadbeef 开头),
      纯数字枚举还原。也常用于 md5 截断碰撞类小题。

用法:
    python EasySearch.py --selftest                        # 自测(小范围找 'ab' 前缀)
    python EasySearch.py                                   # 默认: 找 md5 以 deadbeef 开头的数(0~10^7)
    python EasySearch.py --prefix deadbeef --max 10000000  # 显式指定
    python EasySearch.py --all                             # 找出范围内所有命中而不是首个
"""
import argparse
import hashlib
import sys


def md5(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def brute(prefix, limit, find_all=False):
    """枚举 0~limit 的十进制数, 返回 md5 以 prefix 开头的命中列表。"""
    hits = []
    for i in range(limit):
        if md5(str(i)).startswith(prefix):
            print(i)
            hits.append(i)
            if not find_all:
                break
    return hits


def selftest():
    ok = True
    hits = brute('ab', 100000)
    # 0~10^5 内必有 md5 以 'ab' 开头的数
    ok &= bool(hits)
    for h in hits:  # 验证命中确实满足前缀
        ok &= md5(str(h)).startswith('ab')
    print('[%s] EasySearch.py 自测(命中: %s)' % ('OK' if ok else 'FAIL', hits))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='MD5 前缀纯数字爆破')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    ap.add_argument('-p', '--prefix', default='deadbeef',
                    help='要求的 md5 十六进制前缀(默认 deadbeef)')
    ap.add_argument('-m', '--max', type=int, default=10000000,
                    help='枚举上限(默认 10^7)')
    ap.add_argument('--all', action='store_true', help='列出范围内全部命中')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()

    hits = brute(args.prefix.lower(), args.max, args.all)
    print('[*] 命中: %s' % (hits or '范围内未找到, 可加大 --max'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
