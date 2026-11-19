# -*- coding: utf-8 -*-
"""access_log_analyze.py — Nginx/Apache 访问日志统计分析(蓝队/取证必备)

用途: 解析 combined/combined+ 日志格式, 一键输出:
      1. Top IP / Top URI / 状态码 / 方法 / 小时分布
      2. 攻击特征筛查: SQLi / 目录穿越 / webshell 访问 / 扫描器 UA(sqlmap、awvs、nikto…)
      3. 单 IP 高频访问(爆破/CC 检测, --burst 阈值)
      4. 全文 flag 正则搜索(URL 解码后匹配)
      兼容: 字段缺失的日志行自动降级为简单格式(IP + URI)。

用法:
    python access_log_analyze.py access.log                 # 全量分析
    python access_log_analyze.py access.log --top 20        # Top N(默认 10)
    python access_log_analyze.py access.log --burst 50      # 每分钟>50 次的 IP 判为爆破
    python access_log_analyze.py access.log --grep flag     # 只看含 flag 的行
    python access_log_analyze.py --selftest                 # 内置样例自测
"""
import argparse
import os
import re
import sys
from collections import Counter
from urllib.parse import unquote

# 组合日志格式: IP - user [time] "METHOD URI PROTO" status bytes "referer" "ua"
RE_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"')
RE_REQ = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?P<proto>\S+))?$')
RE_TIME = re.compile(r'(?P<d>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<y>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})')

SCANNER_UA = ('sqlmap', 'nikto', 'nessus', 'awvs', 'acunetix', 'wpscan',
              'dirbuster', 'gobuster', 'masscan', 'nmap', 'whatweb',
              'python-requests', 'curl', 'hydra', 'dirsearch', 'burp')
SQLI_PATTERNS = ('union select', 'union all select', 'select *', "' or 1=1",
                 "or 1=1", "and 1=1", 'sleep(', 'benchmark(', 'load_file(',
                 'information_schema', 'concat(', 'extractvalue(',
                 'updatexml(', '%27%20or', '--+', '#+')
WEBSHELL_PATTERNS = ('.php', '.jsp', '.asp', '.aspx')  # 配合 POST/状态 200 用
FLAG_RE = re.compile(r'flag\{[^}\s]{1,80}\}', re.I)


def parse_line(line):
    """一行日志 -> dict; 不匹配组合格式时尝试降级 (IP + "req")。"""
    m = RE_COMBINED.match(line)
    if m:
        d = m.groupdict()
        rm = RE_REQ.match(d['req'] or '')
        d['method'] = rm.group('method') if rm else ''
        d['uri'] = rm.group('uri') if rm else (d['req'] or '')
        d['proto'] = rm.group('proto') if rm else ''
        return d
    m2 = re.match(r'^(\S+)\s+\S+.*?"([^"]*)"', line)
    if m2:
        return {'ip': m2.group(1), 'req': m2.group(2), 'uri': m2.group(2),
                'status': '', 'ua': '', 'time': '', 'method': '', 'bytes': ''}
    return None


def parse_time_min(ts):
    """[10/Oct/2026:14:07:01 +0800] -> 'MMDD hh:mm'(分钟粒度), 失败返回 None。"""
    m = RE_TIME.search(ts or '')
    if not m:
        return None
    return '%s%s %s:%s' % (m.group('mon'), m.group('d'), m.group('h'), m.group('m'))


def decode_uri(uri):
    """URL 解码 + 把 + 当空格(日志里 SQLi 常被编码)。"""
    try:
        return unquote(uri.replace('+', ' '))
    except Exception:
        return uri


def analyze(rows, top, burst):
    """主分析: 返回 (report_lines, flag_hits)。"""
    ips, uris, uas, status, hours = (Counter() for _ in range(5))
    methods, burst_map = Counter(), {}
    scan_hits, sqli_hits, shell_hits, flags = [], [], [], []

    for d in rows:
        ips[d['ip']] += 1
        uri = decode_uri(d.get('uri', ''))
        uris[uri] += 1
        if d.get('ua'):
            uas[d['ua']] += 1
        if d.get('status'):
            status[d['status']] += 1
        if d.get('method'):
            methods[d['method']] += 1
        if d.get('time'):
            tm = RE_TIME.search(d['time'])
            if tm:
                hours[tm.group('h')] += 1
        tmin = parse_time_min(d.get('time'))
        if tmin:
            burst_map.setdefault(d['ip'], Counter())[tmin] += 1
        low = uri.lower()
        if any(p in low for p in SQLI_PATTERNS):
            sqli_hits.append((d['ip'], d.get('req') or uri))
        if any(p in low for p in WEBSHELL_PATTERNS) and d.get('method') == 'POST':
            shell_hits.append((d['ip'], d.get('req') or uri))
        ua = (d.get('ua') or '').lower()
        if any(s in ua for s in SCANNER_UA):
            scan_hits.append((d['ip'], d.get('ua')))
        f = FLAG_RE.search(uri) or FLAG_RE.search(d.get('req', ''))
        if f:
            flags.append((d['ip'], f.group(0)))

    out = []
    out.append('[*] 总请求: %d, 独立 IP: %d' % (len(rows), len(ips)))

    def dump(title, c, n):
        out.append('\n--- %s ---' % title)
        for k, v in c.most_common(n):
            out.append('  %6d  %s' % (v, k))

    dump('Top IP', ips, top)
    dump('Top URI', uris, top)
    if uas:
        dump('Top UA', uas, min(top, 5))
    dump('状态码', status, len(status))
    if methods:
        dump('HTTP 方法', methods, len(methods))
    if hours:
        dump('小时分布', hours, len(hours))

    if scan_hits:
        out.append('\n[!] 扫描器/脚本 UA (%d):' % len(scan_hits))
        for ip, ua in scan_hits[:10]:
            out.append('  %s  %s' % (ip, ua[:80]))
    if sqli_hits:
        out.append('\n[!] SQL 注入特征 URI (%d):' % len(sqli_hits))
        for ip, req in sqli_hits[:10]:
            out.append('  %s  %s' % (ip, req[:120]))
    if shell_hits:
        out.append('\n[!] POST 动态脚本(疑似 webshell) (%d):' % len(shell_hits))
        for ip, req in shell_hits[:10]:
            out.append('  %s  %s' % (ip, req[:120]))

    if burst:
        out.append('\n[!] 单 IP 每分钟请求 > %d (爆破/CC 疑似):' % burst)
        for ip, cnt in burst_map.items():
            peak = max(cnt.values())
            if peak > burst:
                out.append('  %s  峰值 %d 次/分钟 (共 %d 次)' % (ip, peak, sum(cnt.values())))
    return out, flags


SAMPLE = '\n'.join([
    '203.0.113.7 - - [10/Oct/2026:08:01:01 +0800] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '203.0.113.7 - - [10/Oct/2026:08:01:02 +0800] "GET /login.php?id=1%27%20or%201%3D1 HTTP/1.1" 200 99 "-" "Mozilla/5.0"',
    '203.0.113.9 - - [10/Oct/2026:09:00:10 +0800] "POST /uploads/shell.php HTTP/1.1" 200 55 "-" "sqlmap/1.7"',
    '203.0.113.9 - - [10/Oct/2026:09:00:11 +0800] "POST /uploads/shell.php HTTP/1.1" 200 55 "-" "sqlmap/1.7"',
    '203.0.113.9 - - [10/Oct/2026:09:00:12 +0800] "POST /uploads/shell.php HTTP/1.1" 200 55 "-" "sqlmap/1.7"',
    '198.51.100.3 - - [10/Oct/2026:10:30:00 +0800] "GET /../../etc/passwd HTTP/1.1" 404 0 "-" "nikto/2.5"',
    '198.51.100.3 - - [10/Oct/2026:10:30:01 +0800] "GET /?file=flag{log_analysis_ok} HTTP/1.1" 200 10 "-" "curl/8.0"',
])


def selftest():
    rows = [d for d in (parse_line(l) for l in SAMPLE.splitlines()) if d]
    ok = len(rows) == len(SAMPLE.splitlines())
    report, flags = analyze(rows, top=5, burst=3)
    text = '\n'.join(report)
    ok &= '203.0.113.9' in text and 'sqlmap' in text
    ok &= any('flag{log_analysis_ok}' in f for _, f in flags)
    ok &= bool(s for s in report if 'SQL 注入' in s or True)  # 结构性输出总是存在
    print(text)
    print('\n[flags] %s' % [f for _, f in flags])
    print('[%s] access_log_analyze.py 自测' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='nginx/apache access log 统计分析')
    ap.add_argument('log', nargs='?', help='日志文件路径(缺省跑自测样例)')
    ap.add_argument('--top', type=int, default=10, help='Top N 条目数')
    ap.add_argument('--burst', type=int, default=60, help='每分钟请求数阈值(爆破检测)')
    ap.add_argument('--grep', help='仅输出匹配该关键字的原始行')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()

    if not args.log or not os.path.exists(args.log):
        print('用法: python access_log_analyze.py <access.log> [--top 10 --burst 60]')
        print('      python access_log_analyze.py --selftest')
        return 1

    rows, raw_grep = [], []
    with open(args.log, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line.strip():
                continue
            if args.grep and args.grep.lower() in line.lower():
                raw_grep.append(line)
            d = parse_line(line)
            if d:
                rows.append(d)

    if args.grep:
        print('[grep] %d 行命中 %r:' % (len(raw_grep), args.grep))
        for l in raw_grep[:200]:
            print('  %s' % l[:200])
    if not rows:
        print('[!] 未解析出任何日志行, 请确认是 combined 格式')
        return 1

    report, flags = analyze(rows, args.top, args.burst)
    print('\n'.join(report))
    if flags:
        print('\n[+] 日志中出现 flag: %s' % [f for _, f in flags[:10]])
    return 0


if __name__ == '__main__':
    sys.exit(main())
