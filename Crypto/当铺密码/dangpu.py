# -*- coding: utf-8 -*-
"""dangpu.py — 当铺密码编解码(Misc/Crypto 高频: 汉字笔画出头数对应数字)

规则: 汉字"出头"的数量对应数字, 常见对照(出题方可能有变体):
      田=0  由=1  中=2  人=3  工=4  大=5  天=6  夫=7  井=8  春=9
      遇到不认识的字用 --map 自定义(每行"字=数字"), 或 --show 查看内置表。

用法:
    python dangpu.py -d "中人工大"          # 解码 -> 2345
    python dangpu.py -e 2345                # 编码 -> 中人工大
    python dangpu.py --map my.txt -d "..."  # 自定义对照表
    python dangpu.py --selftest             # 内置自测
"""
import argparse
import sys

TABLE = {'田': 0, '由': 1, '中': 2, '人': 3,
         '工': 4, '大': 5, '天': 6, '夫': 7, '井': 8, '春': 9}


def load_map(path):
    tbl = {}
    for line in open(path, encoding='utf-8', errors='replace'):
        line = line.strip()
        if '=' in line:
            ch, num = line.split('=', 1)
            tbl[ch.strip()] = int(num.strip())
    return tbl


def decode(text, tbl):
    out = []
    for ch in text:
        if ch in tbl:
            out.append(str(tbl[ch]))
        elif ch.strip():
            out.append('?')
    return ''.join(out)


def encode(text, tbl):
    rev = {v: k for k, v in tbl.items()}
    return ''.join(rev.get(int(c), '?') for c in text if c.isdigit())


def selftest():
    d = decode('田由中人工大天夫井春', TABLE)
    ok = d == '0123456789' and encode(d, TABLE) == '田由中人工大天夫井春'
    print('当铺密码对照表回环:', 'OK' if ok else 'FAIL (%r)' % d)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='当铺密码编解码')
    ap.add_argument('-d', '--decode', help='解码汉字串')
    ap.add_argument('-e', '--encode', help='编码数字串')
    ap.add_argument('--map', help='自定义对照表文件(每行 字=数字)')
    ap.add_argument('--show', action='store_true', help='打印内置对照表')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    tbl = load_map(args.map) if args.map else dict(TABLE)
    if args.show:
        for ch, num in sorted(tbl.items(), key=lambda kv: kv[1]):
            print('%s = %d' % (ch, num))
    elif args.decode:
        print(decode(args.decode, tbl))
    elif args.encode:
        print(encode(args.encode, tbl))
    else:
        ap.error('需要 -d/-e/--show(或 --selftest)')


if __name__ == '__main__':
    main()
