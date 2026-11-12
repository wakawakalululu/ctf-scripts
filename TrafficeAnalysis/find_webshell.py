# -*- coding: utf-8 -*-
"""
find_webshell.py — WEBSHELL 上传/连接分析(题型:黑客上传的webshell文件名和内容是什么?)

思路:
  1. 上传:multipart/form-data 的 POST,文件内容常见 eval/system/assert
  2. 菜刀/蚁剑连接:URL 参数、base64 的 payload、响应内容
脚本会列出所有可疑 POST,解析出 文件名 + 内容,并尝试解码 base64 payload。

等价 tshark: http.request.method=="POST" && (http contains "eval" || ...)
"""
import os
import re
import sys
import base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

WEBSHELL_WORDS = ['eval(', 'assert(', 'system(', 'exec(', 'shell_exec',
                  'passthru(', 'base64_decode(', '$_POST[', '$_GET[', '$_REQUEST[',
                  'cmd=', '&z0=', 'cexec', '创建 ActiveXObject', 'wscript.shell']


def parse_multipart(body, boundary):
    """解析 multipart/form-data,返回 [(字段名, 文件名, 内容bytes)]"""
    parts = []
    for chunk in body.split(b'--' + boundary.encode('latin1')):
        chunk = chunk.strip(b'\r\n')
        if not chunk or chunk == b'--':
            continue
        if b'\r\n\r\n' not in chunk:
            continue
        head, content = chunk.split(b'\r\n\r\n', 1)
        name = filename = None
        for line in head.split(b'\r\n'):
            m = re.search(rb'name="([^"]*)"', line)
            if m:
                name = m.group(1).decode('utf-8', 'replace')
            m = re.search(rb'filename="([^"]*)"', line)
            if m:
                filename = m.group(1).decode('utf-8', 'replace')
        parts.append((name, filename, content))
    return parts


def analyze(path):
    lt, pkts = pcaplib.read_pcap(path)
    findings = []
    for i, msg, st in pcaplib.iter_http(pkts, lt):
        if not isinstance(msg, pcaplib.HttpRequest) or msg.method != 'POST':
            continue
        body = msg.body
        ct = msg.header('content-type')
        low = body.lower()
        suspicious = any(w.encode('utf-8', 'ignore') in low for w in WEBSHELL_WORDS)
        # base64 解码后匹配(菜刀/蚁剑的 payload)
        b64_hits = []
        for m in re.finditer(rb'[A-Za-z0-9+/=]{24,}', body):
            try:
                dec = base64.b64decode(m.group(0) + b'=' * (-len(m.group(0)) % 4))
                if any(w.encode('utf-8', 'ignore') in dec.lower() for w in WEBSHELL_WORDS):
                    b64_hits.append((m.group(0), dec))
            except Exception:
                pass
        if not (suspicious or b64_hits or 'multipart/form-data' in ct):
            continue
        rec = {'path': msg.path, 'host': msg.header('host'),
               'body': body, 'files': [], 'b64': b64_hits, 'ct': ct}
        if 'multipart/form-data' in ct:
            m = re.search(r'boundary=([^;]+)', ct)
            if m:
                for name, filename, content in parse_multipart(body, m.group(1)):
                    rec['files'].append((name, filename, content))
        findings.append(rec)
    return findings


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else default_sample()
    if not path or not os.path.exists(path):
        print('用法: python find_webshell.py <pcap> [导出目录]')
        sys.exit(1)
    outdir = sys.argv[2] if len(sys.argv) > 2 else 'webshell_export'
    print('[*] 分析 %s' % path)
    findings = analyze(path)
    if not findings:
        print('[-] 未发现 webshell 相关请求')
        return
    names = []
    for k, rec in enumerate(findings, 1):
        print('==== 可疑请求 #%d: POST http://%s%s (Content-Type: %s) ====' % (
            k, rec['host'], rec['path'], rec['ct'] or '?'))
        for name, filename, content in rec['files']:
            low = content.lower()
            printable = any(w.encode('utf-8', 'ignore') in low for w in WEBSHELL_WORDS)
            if printable or filename:
                print('  [上传文件] filename=%s fieldname=%s size=%d%s' % (
                    filename, name, len(content),
                    '   <== 包含 webshell 关键字' if printable else ''))
                if printable:
                    names.append(filename)
                    os.makedirs(outdir, exist_ok=True)
                    out = os.path.join(outdir, os.path.basename(filename) or 'shell_%d.php' % k)
                    with open(out, 'wb') as f:
                        f.write(content)
                    print('    内容已保存到 %s' % out)
                    print('    ---- 内容 ----')
                    print(pcaplib.printable(content, keep_newline=True))
                    print('    --------------')
        if not rec['files'] and rec['body']:
            print('  [POST body] %s' % pcaplib.shorten(rec['body'], 300))
        for b64, dec in rec['b64'][:3]:
            print('  [base64 payload] %s' % b64.decode('latin1'))
            print('    解码: %s' % pcaplib.shorten(dec, 300))
        print()

    if names:
        print('[+] 答案(上传的 webshell 文件名): %s' % ', '.join(names))
    flags = pcaplib.find_flags(b' '.join(rec['body'] for rec in findings))
    for f in flags:
        print('[+] 顺带发现 flag: %s' % f)


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, 'samples/web_attack.pcap')
    return p if os.path.exists(p) else None


if __name__ == '__main__':
    main()
