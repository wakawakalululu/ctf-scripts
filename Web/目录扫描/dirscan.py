# -*- coding: utf-8 -*-
"""dirscan 轻量目录/文件扫描

参考: https://github.com/maurosoria/dirsearch (通用扫描逻辑的轻量实现)
用途: Web 题扫后台/备份文件/敏感路径; 内置常见路径词表, 支持自定义字典与扩展名。

用法:
    python dirscan.py --selftest                        # 自测(本地起临时HTTP服务)
    python dirscan.py -u http://target/                 # 用内置词表
    python dirscan.py -u http://target/ -w dict.txt     # 自定义字典(每行一个)
    python dirscan.py -u http://target/ --ext php,bak   # 每个词条追加扩展名
    python dirscan.py -u http://target/ -t 20 --ok 200,301,403
"""
import argparse
import sys
import threading
from queue import Queue

DEFAULT_WORDS = [
    'admin', 'login', 'flag', 'flag.php', 'index.php', 'backup', 'bak',
    'test', 'debug', 'console', 'robots.txt', '.git/HEAD', '.env',
    'uploads', 'upload', 'include', 'config', 'db.sql', 'www.zip',
    'backup.zip', 'index.bak', 'phpinfo.php', 'info.php', 'shell.php',
]


def _worker(q, base, sess, ok_codes, results, lock):
    while True:
        try:
            path = q.get_nowait()
        except Exception:
            return
        url = base.rstrip('/') + '/' + path.lstrip('/')
        try:
            r = sess.get(url, timeout=8, allow_redirects=False)
            if r.status_code in ok_codes:
                with lock:
                    results.append((r.status_code, len(r.content), url))
                    print(f'[{r.status_code}] {len(r.content):>8}  {url}')
        except Exception:
            pass
        finally:
            q.task_done()


def scan(base, words, extensions=(), threads=10, ok_codes=(200, 204, 301, 302, 307, 401, 403)):
    import requests
    targets = []
    for w in words:
        targets.append(w)
        for ext in extensions:
            targets.append(f'{w}.{ext}')
    q = Queue()
    for t in targets:
        q.put(t)
    results, lock = [], threading.Lock()
    sess = requests.Session()
    threads_list = [threading.Thread(target=_worker,
                                     args=(q, base, sess, set(ok_codes), results, lock),
                                     daemon=True)
                    for _ in range(max(1, threads))]
    for th in threads_list:
        th.start()
    q.join()
    return sorted(results)


def _selftest():
    import http.server
    import socketserver
    import tempfile
    import os
    import io

    ok = True
    tmpdir = tempfile.mkdtemp()
    with open(os.path.join(tmpdir, 'secret.txt'), 'w') as f:
        f.write('flag{dirscan_found}')
    with open(os.path.join(tmpdir, 'a.html'), 'w') as f:
        f.write('<h1>hi</h1>')

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=tmpdir, **kw)

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(('127.0.0.1', 0), Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        results = scan(f'http://127.0.0.1:{port}/',
                       ['admin', 'a.html', 'secret.txt', 'nope'],
                       threads=4, ok_codes=(200,))
        found = {r[2].rsplit('/', 1)[-1] for r in results}
        good = 'secret.txt' in found and 'a.html' in found and 'admin' not in found
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 扫描命中: {sorted(found)}")
    finally:
        srv.shutdown()
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='轻量目录扫描')
    ap.add_argument('-u', '--url', help='目标根 URL(如 http://target/)')
    ap.add_argument('-w', '--wordlist', help='自定义字典文件')
    ap.add_argument('--ext', default='', help='追加扩展名, 逗号分隔')
    ap.add_argument('-t', '--threads', type=int, default=10)
    ap.add_argument('--ok', default='200,204,301,302,307,401,403', help='视为存在的状态码')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest or not args.url:
        if args.url:
            ap.error('-u 为实战模式必填(自测用 --selftest)')
        _selftest()
        return
    words = DEFAULT_WORDS
    if args.wordlist:
        with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
    exts = [e for e in args.ext.split(',') if e]
    results = scan(args.url, words, exts, args.threads,
                   tuple(int(x) for x in args.ok.split(',')))
    print(f'\n共 {len(results)} 个命中')


if __name__ == '__main__':
    main()
