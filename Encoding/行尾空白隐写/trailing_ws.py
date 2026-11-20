# -*- coding: utf-8 -*-
"""trailing_ws.py — 行尾空白隐写解析(空格/Tab 当二进制, Misc/Encoding 常见)

规则: 每行行尾的空格与 Tab 承载信息, 常见约定(自动全试):
      1 空格=0 / 2 空格=1;  Tab=1 无 Tab=0;  空格=0 Tab=1;
      位流按 8bit 组装转 ASCII(--7 用 7bit)。--encode 可把消息写入
      目标文件行尾(默认 2 空格=1, 1 空格=0), 保留原文件内容不变。

用法:
    python trailing_ws.py stego.txt                 # 解析(输出全部模式)
    python trailing_ws.py stego.txt -m tab          # 只试 Tab=1 模式
    python trailing_ws.py plain.txt -e "flag{...}"  # 编码写回同文件
    python trailing_ws.py --selftest                # 内置自测
"""
import argparse
import os
import re
import sys

# 只看每行**行尾**的空白部分(正文里的空格/Tab 不计)
MODES = {
    'space12': lambda tail: ('0' if tail == ' ' else
                             '1' if tail == '  ' else ''),
    'tab': lambda tail: '1' if '\t' in tail else '0',
    'spacetab': lambda tail: ('0' if tail == ' ' else
                              '1' if tail == '\t' else ''),
}


def trailing(line):
    m = re.search(r'[ \t]+$', line)
    return m.group(0) if m else ''


def bits_to_text(bits, width=8):
    out = []
    for i in range(0, len(bits) - width + 1, width):
        v = int(bits[i:i + width], 2)
        out.append(chr(v))
    return ''.join(out)


def decode(path, mode=None, width=8):
    lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
    lines = [ln.rstrip('\r\n') for ln in lines]
    modes = [mode] if mode else list(MODES)
    results = {}
    for name in modes:
        bits = ''.join(MODES[name](trailing(ln)) for ln in lines)
        text = bits_to_text(bits, width)
        printable = sum(c.isprintable() for c in text) / max(len(text), 1)
        results[name] = (bits, text, printable)
    return results


def encode(path, message, mode='space12'):
    lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
    msg = message
    bits = ''.join(format(ord(c), '08b') for c in msg)
    if len(bits) > len(lines):
        raise SystemExit('消息 %d bit 超过行数 %d, 需 %d 行' % (len(bits), len(lines), len(bits)))
    out = []
    for i, ln in enumerate(lines):
        if i < len(bits):
            ln = ln.rstrip()
            ln += ' ' * (2 if bits[i] == '1' else 1)
        out.append(ln)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(out) + '\n')
    print('已写入 %s (共 %d 行, 消息 %d 字符)' % (path, len(out), len(msg)))


def selftest():
    import tempfile
    fd, path = tempfile.mkstemp(suffix='.txt')
    os.close(fd)
    with open(path, 'w', encoding='utf-8') as f:
        for i in range(70):
            f.write('sample line %d some filler text\n' % i)
    encode(path, 'flag{ws}')
    res = decode(path)
    os.unlink(path)
    hit = any('flag{ws}' in text for _, text, _ in res.values())
    print('行尾空白编码->解析回环:', 'OK' if hit else 'FAIL %r' % res)
    return 0 if hit else 1


def main():
    ap = argparse.ArgumentParser(description='行尾空白隐写解析')
    ap.add_argument('file', nargs='?', help='目标文本文件')
    ap.add_argument('-m', '--mode', choices=list(MODES), help='只试指定模式')
    ap.add_argument('-7', '--seven', action='store_true', help='按 7bit 组装(默认 8bit)')
    ap.add_argument('-e', '--encode', metavar='MSG', help='把消息编码写入行尾')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.file:
        ap.error('需要文件参数(或 --selftest)')
    if args.encode:
        encode(args.file, args.encode)
        return
    width = 7 if args.seven else 8
    for name, (_, text, ratio) in decode(args.file, args.mode, width).items():
        print('== 模式 %s (可读率 %.0f%%) ==' % (name, ratio * 100))
        print(repr(text))


if __name__ == '__main__':
    main()
