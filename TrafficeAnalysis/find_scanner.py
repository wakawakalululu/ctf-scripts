# -*- coding: utf-8 -*-
"""
find_scanner.py — WEB扫描器识别(题型:黑客使用的是什么扫描器?)

思路:扫描器会在 HTTP 请求里留下特征(UA、特定 Header、特征路径),
用 tshark 是 `http contains "扫描器特征值"`,这里用纯 python 对全部
HTTP 请求做特征匹配,常见扫描器特征都内置了。

用法: python find_scanner.py <pcap>       (缺省自动找 samples 里的包)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

# 扫描器特征:(名称, 匹配方式, 特征串)
# 匹配方式: ua=User-Agent 子串, path=URL 路径子串, header=任意请求头子串, body=任意内容子串
SCANNER_SIGS = [
    ('AWVS (Acunetix Web Vulnerability Scanner)', 'ua', 'acunetix'),
    ('AWVS (Acunetix Web Vulnerability Scanner)', 'path', 'acunetix_wvs_security_test'),
    ('AWVS (Acunetix Web Vulnerability Scanner)', 'body', 'acunetix'),
    ('Netsparker', 'ua', 'netsparker'),
    ('AppScan', 'ua', 'appscan'),
    ('WebInspect', 'ua', 'webinspect'),
    ('RSAS(绿盟极光)', 'ua', 'nsfocus'),
    ('Nessus', 'ua', 'nessus'),
    ('WebReaver', 'ua', 'webreaver'),
    ('Sqlmap', 'ua', 'sqlmap'),
    ('Sqlmap', 'header', 'sqlmap'),
    ('w3af', 'ua', 'w3af'),
    ('Nikto', 'ua', 'nikto'),
    ('WhatWeb', 'ua', 'whatweb'),
    ('DirBuster', 'ua', 'dirbuster'),
    ('DirBuster', 'ua', 'dirb'),
    ('Gobuster', 'ua', 'gobuster'),
    ('OWASP ZAP', 'ua', 'zap'),
    ('Nmap NSE', 'ua', 'nmap scripting engine'),
    ('御剑', 'ua', 'yujian'),
    ('WebSafe/WEBSUIT', 'ua', 'webscan'),
    ('BugScan', 'ua', 'bugscan'),
    ('Havij', 'ua', 'havij'),
    ('Pangolin', 'ua', 'pangolin'),
    ('Arachni', 'ua', 'arachni'),
    ('Hydra', 'body', 'hydra'),
]


def analyze(path):
    lt, pkts = pcaplib.read_pcap(path)
    hits = {}       # scanner -> [证据字符串]
    for _i, req, _st in pcaplib.iter_http(pkts, lt):
        if not isinstance(req, pcaplib.HttpRequest):
            continue
        ua = req.header('user-agent')
        blob_all = req.raw.decode('latin1', 'replace')
        for name, kind, sig in SCANNER_SIGS:
            s = sig.lower()
            evidence = None
            if kind == 'ua' and s in ua.lower():
                evidence = 'User-Agent: %s' % ua
            elif kind == 'path' and s in req.path.lower():
                evidence = '路径: %s' % req.path
            elif kind == 'header' and s in blob_all.lower():
                evidence = '报文包含特征串: %s' % sig
            elif kind == 'body' and s in blob_all.lower():
                evidence = '报文包含特征串: %s' % sig
            if evidence:
                hits.setdefault(name, [])
                if evidence not in hits[name]:
                    hits[name].append(evidence)
    return hits


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else default_sample()
    if not path or not os.path.exists(path):
        print('用法: python find_scanner.py <pcap>')
        sys.exit(1)
    print('[*] 分析 %s' % path)
    hits = analyze(path)
    if not hits:
        print('[-] 未发现已知扫描器特征')
        return
    print('[+] 检测到 %d 个扫描器特征:' % len(hits))
    for name, evs in hits.items():
        print('  == %s  (命中 %d 处) ==' % (name, len(evs)))
        for e in evs[:5]:
            print('     %s' % e)
    print()
    print('[+] 答案(黑客使用的扫描器): %s' % ' / '.join(hits.keys()))


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ('samples/web_attack.pcap', 'sample_web.pcap'):
        p = os.path.join(here, name)
        if os.path.exists(p):
            return p
    return None


if __name__ == '__main__':
    main()
