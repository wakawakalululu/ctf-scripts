# -*- coding: utf-8 -*-
"""
find_admin_url.py — 后台目录爆破分析(题型:黑客扫描到的后台登录地址是什么?)

思路:目录爆破会产生大量 404 请求 + 少量 200 请求,后台地址通常带
admin/login/manage 等关键字且最终返回 200/302。本脚本:
  1. 统计所有被请求的 URL
  2. 按后台关键字 + 状态码打分排序
  3. 输出最可能的"爆破得到的后台地址"

等价 tshark 命令: http contains "admin" / http.request.method=="GET"
"""
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

ADMIN_KEYWORDS = ['admin', 'login', 'manage', 'backstage', 'manager',
                  'console', 'dashboard', 'phpmyadmin', 'wp-admin', 'user',
                  'system', 'backend', 'auth', 'sign']


def analyze(path):
    lt, pkts = pcaplib.read_pcap(path)
    reqs = []          # (method, path, host)
    resp_status = {}   # 按 (host+path) 记录最后一个状态码
    for i, msg, st in pcaplib.iter_http(pkts, lt):
        if isinstance(msg, pcaplib.HttpRequest):
            reqs.append((msg.method, msg.path, msg.header('host')))
        elif isinstance(msg, pcaplib.HttpResponse):
            resp_status[st.client[1]] = resp_status.get(st.client[1], {})
            resp_status[st.client[1]][msg.pkt if hasattr(msg, 'pkt') else 0] = msg.status
    return reqs, pkts, lt


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else default_sample()
    if not path or not os.path.exists(path):
        print('用法: python find_admin_url.py <pcap>')
        sys.exit(1)
    print('[*] 分析 %s' % path)
    lt, pkts = pcaplib.read_pcap(path)

    url_count = Counter()
    scored = Counter()
    # 为把"URL -> 响应码"对应起来,逐流配对请求/响应
    streams = pcaplib.build_streams(pkts, lt)
    pair_status = {}
    for st in streams:
        reqs = pcaplib.parse_http_stream(st.client_stream(), is_request=True)
        resps = [r for r in pcaplib.parse_http_stream(st.server_stream(), is_request=False)
                 if isinstance(r, pcaplib.HttpResponse)]
        for j, req in enumerate(reqs):
            code = resps[j].status if j < len(resps) else '?'
            key = (req.header('host') or '%s:%d' % st.server, req.path)
            url_count[key] += 1
            pair_status[key] = code

    if not url_count:
        print('[-] 没有解析到 HTTP 请求')
        return

    for (host, p), cnt in url_count.items():
        score = 0
        low = p.lower()
        for kw in ADMIN_KEYWORDS:
            if kw in low:
                score += 10
        code = pair_status.get((host, p), '?')
        if code in ('200', '302'):
            score += 20          # 爆破成功后能访问到的
        if score:
            scored[(host, p, code, cnt)] = score

    print('[*] 共 %d 个不同 URL,其中 %d 个请求带后台特征' % (len(url_count), len(scored)))
    print('[*] 请求最频繁的 10 个 URL(爆破痕迹):')
    for (host, p), cnt in url_count.most_common(10):
        print('    %4d 次  http://%s%s' % (cnt, host, p))

    if scored:
        print('[+] 疑似后台地址(按得分排序):')
        best = None
        for (host, p, code, cnt), sc in sorted(scored.items(), key=lambda x: -x[1]):
            print('    score=%d  %s  (请求 %d 次, 响应 %s)' % (sc, 'http://%s%s' % (host, p), cnt, code))
            if best is None:
                best = 'http://%s%s' % (host, p)
        print()
        print('[+] 答案(后台登录地址): %s' % best)
    else:
        print('[-] 未匹配到后台关键字,请人工翻看上面的 URL 列表')

    # 全文搜 flag
    raw_all = b''.join(st.client_stream() + st.server_stream() for st in streams)
    flags = pcaplib.find_flags(raw_all)
    for f in flags:
        print('[+] 顺带发现 flag: %s' % f)


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, 'samples/web_attack.pcap')
    return p if os.path.exists(p) else None


if __name__ == '__main__':
    main()
