# -*- coding: utf-8 -*-
"""tpupload2.py uniqid 文件名前后缀定位辅助([RoarCTF 2019]Simple Upload)

来源: WP 汇总/[RoarCTF 2019]Simple Upload
用途: 上传 txt 响应里泄露的文件名片段(如末字符 e/前字符 4)在
      "1234567890abcdef1234567890abcdef" 上切片, 快速算出
      剩余待爆破的中间字符集, 配合 tpupload.py 使用。

用法:
    python tpupload2.py --selftest                        # 自测
    python tpupload2.py -s "1234567890abcdef1234567890abcdef" -a 4 -b e
"""
import argparse
import sys

DEFAULT_S = '1234567890abcdef1234567890abcdef'


def locate(s, start, end):
    """返回 (start 索引, end 索引, 两索引之间的子串)。"""
    i, j = s.find(start), s.find(end)
    return i, j, s[i:j]


def selftest():
    ok = True
    i, j, mid = locate(DEFAULT_S, '4', 'e')
    ok &= (i == 3 and j == 14)  # '4' 在索引 3, 'e' 在索引 14
    ok &= (mid == '4567890abcd')
    print('start=%s end=%s -> mid=%r' % (i, j, mid))
    print('[%s] tpupload2.py 自测' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='uniqid 候选字符集切片定位')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    ap.add_argument('-s', '--string', default=DEFAULT_S, help='全字符集串')
    ap.add_argument('-a', '--start', default='4', help='泄露的起始字符')
    ap.add_argument('-b', '--end', default='e', help='泄露的结束字符')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    i, j, mid = locate(args.string, args.start, args.end)
    print('start=%s end=%s -> mid=%r' % (i, j, mid))
    return 0


if __name__ == '__main__':
    sys.exit(main())
