# -*- coding: utf-8 -*-
"""ps_decode.py — PowerShell 编码命令解码(蓝队/日志取证高频)

用途: 从安全日志/脚本块日志/ps1/文本中提取并解码:
      1. powershell -enc / -EncodedCommand 的 Base64(UTF-16LE) 命令;
      2. [System.Convert]::FromBase64String('...') 内联 base64;
      3. -w hidden -nop 等混淆参数自动忽略; 解码后 flag/关键字高亮。
      配合 LogAnalysis/access_log分析 使用可覆盖大部分 Windows 日志题。

用法:
    python ps_decode.py security.evtx.log          # 解析日志文本
    python ps_decode.py run.ps1 --grep flag        # 只看含 flag 的解码结果
    python ps_decode.py -s SQBwAG8AdAAtAFIAZQBmAGwAZQBjAHQA -t u16   # 手动解码
    python ps_decode.py --selftest                 # 内置自测
"""
import argparse
import base64
import os
import re
import sys

RE_ENC = re.compile(
    r'(?:-enc(?:odedcommand)?|/enc(?:odedcommand)?)\s+["\']?([A-Za-z0-9+/=]{40,})["\']?',
    re.I)
RE_INLINE = re.compile(
    r'FromBase64String\(\s*["\']([A-Za-z0-9+/=]{16,})["\']', re.I)
FLAG_RE = re.compile(r'(?:flag|key|ctf)\{[^}]{0,200}\}', re.I)


def b64_decode(s):
    s = re.sub(r'\s+', '', s)
    s += '=' * (-len(s) % 4)
    raw = base64.b64decode(s)
    for enc in ('utf-16-le', 'utf-8', 'cp1252'):
        try:
            text = raw.decode(enc)
            if sum(c.isprintable() or c in '\r\n\t' for c in text) / max(len(text), 1) > 0.85:
                return text, enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.hex(), 'hex'


def extract(text, grep=None):
    results = []
    seen = set()
    for m in RE_ENC.finditer(text) or []:
        results.append(('-enc', m.group(1)))
    for m in RE_INLINE.finditer(text):
        results.append(('FromBase64String', m.group(1)))
    for kind, b64 in results:
        if b64 in seen:
            continue
        seen.add(b64)
        decoded, enc = b64_decode(b64)
        if grep and grep.lower() not in decoded.lower():
            continue
        yield kind, b64[:40], decoded, enc


def selftest():
    cmd = "Write-Host 'flag{ps_ok_123}'"
    b64u16 = base64.b64encode(cmd.encode('utf-16-le')).decode()
    line1 = 'powershell -w hidden -nop -enc %s' % b64u16
    b64u8 = base64.b64encode(b'flag{inline_ok}').decode()
    line2 = "[System.Convert]::FromBase64String('%s')" % b64u8
    text = line1 + '\n' + line2
    out = list(extract(text))
    ok = any('flag{ps_ok_123}' in d for _, _, d, _ in out)
    ok = ok and any('flag{inline_ok}' in d for _, _, d, _ in out)
    print('PowerShell -enc/内联base64 解码:', 'OK' if ok else 'FAIL (%r)' % out)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='PowerShell 编码命令解码')
    ap.add_argument('file', nargs='?', help='日志/ps1/文本文件')
    ap.add_argument('-s', '--string', help='直接解码单个 base64 串')
    ap.add_argument('-t', '--enc', choices=['u16', 'u8', 'auto'], default='auto',
                    help='手动模式编码(u16=UTF-16LE)')
    ap.add_argument('--grep', help='只输出包含关键字的解码结果')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if args.string:
        raw = base64.b64decode(args.string + '=' * (-len(args.string) % 4))
        encs = {'u16': 'utf-16-le', 'u8': 'utf-8', 'auto': None}[args.enc]
        if encs:
            print(raw.decode(encs, 'replace'))
        else:
            text, enc = b64_decode(args.string)
            print('%s  [编码: %s]' % (text, enc))
        return
    if not args.file:
        ap.error('需要日志文件或 -s base64(或 --selftest)')
    text = open(args.file, encoding='utf-8', errors='replace').read()
    n = 0
    for kind, head, decoded, enc in extract(text, args.grep):
        n += 1
        print('== [%s] %s… (编码: %s)' % (kind, head, enc))
        print(decoded[:1500])
        for fl in FLAG_RE.findall(decoded):
            print('>>> 疑似 flag:', fl)
    if not n:
        print('未发现 -enc / FromBase64String 编码片段')


if __name__ == '__main__':
    main()
