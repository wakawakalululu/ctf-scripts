# -*- coding: utf-8 -*-
"""摩斯密码 加解密脚本(补充题型: Crypto/编码)

用途:
    摩斯电码(Morse Code) 与文本互转。自动适配常见分隔写法:
    - 点/划:  . - 、 · / — / _ 均可识别, 统一归一化为 . 和 -
    - 字母分隔: 空格或 / ; 单词分隔: / 或 多空格 或 | (自动猜测)

用法:
    python morse.py                # 自测(内置用例)
    python morse.py -e "SOS HELP"  # 编码
    python morse.py -d ".. --- ... / .... . .-.. .-.."  # 解码
    echo "..." | python morse.py -d  # 从管道读取
"""
import argparse
import re
import sys

MORSE = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',   'E': '.',
    'F': '..-.',  'G': '--.',   'H': '....',  'I': '..',    'J': '.---',
    'K': '-.-',   'L': '.-..',  'M': '--',    'N': '-.',    'O': '---',
    'P': '.--.',  'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',  'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', '/': '-..-.',
    '@': '.--.-.', '-': '-....-', '=': '-...-', ':': '---...',
    '(': '-.--.', ')': '-.--.-', '"': '.-..-.', '\'': '.----.',
    '!': '-.-.--', '&': '.-...', ';': '-.-.-.', '+': '.-.-.', '_': '..--.-',
}
REVERSE = {v: k for k, v in MORSE.items()}


def normalize(code: str) -> str:
    """把 · 、 — _ ∙ 等变体统一成 . -"""
    out = []
    for ch in code:
        if ch == '.':        # 原版 '._' 把 '_' 拦在这里原样保留, 落不到下一分支当 '-' 用
            out.append(ch)
        elif ch in '·∙•':
            out.append('.')
        elif ch in '—–_-─':
            out.append('-')
        else:
            out.append(ch)
    return ''.join(out)


def encode(text: str) -> str:
    """编码: 字母间空格, 单词间 ' / '。未知字符原样跳过。"""
    words = []
    for word in text.upper().split():
        letters = [MORSE[c] for c in word if c in MORSE]
        if letters:
            words.append(' '.join(letters))
    return ' / '.join(words)


def decode(code: str) -> str:
    """解码: 自动猜测字母/单词分隔符。"""
    code = normalize(code).strip()
    # 单词分隔优先级: / > 多空格 > |
    if '/' in code:
        words = [w for w in code.split('/')]
    elif '|' in code:
        words = [w for w in code.split('|')]
    elif '  ' in code:  # 两个及以上空格
        words = re.split(r'\s{2,}', code)
    else:
        words = [code]
    out = []
    for w in words:
        letters = [REVERSE.get(tok.strip(), '?') for tok in w.split() if tok.strip()]
        out.append(''.join(letters))
    return ' '.join(out)


def _fix_neg(argv):
    """摩斯串常以 '-'(划)开头, argparse 把 '-...' 当选项报 expected one argument;
    统一改写成 --decode=... 形式规避。"""
    out, i = [], 0
    while i < len(argv):
        if argv[i] in ('-e', '-d', '--encode', '--decode') and i + 1 < len(argv):
            out.append('%s=%s' % (argv[i], argv[i + 1]))
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return out


def main():
    ap = argparse.ArgumentParser(description='摩斯密码加解密')
    ap.add_argument('-e', '--encode', metavar='TEXT', help='编码文本')
    ap.add_argument('-d', '--decode', metavar='CODE', help='解码摩斯串')
    args = ap.parse_args(_fix_neg(sys.argv[1:]))

    if args.encode:
        print(encode(args.encode))
    elif args.decode:
        data = args.decode
        if data == '-':  # 管道
            data = sys.stdin.read()
        print(decode(data))
    else:
        # 自测
        cases = ['SOS', 'FLAG IS FUN', 'CTF2026']
        ok = True
        for t in cases:
            e = encode(t)
            back = decode(e)
            status = 'OK' if back == t else 'FAIL'
            ok &= (back == t)
            print(f'[{status}] {t!r} -> {e!r} -> {back!r}')
        # 变体字符
        e = encode('SOS')
        variant = e.replace('.', '·').replace('-', '—')
        status = 'OK' if decode(variant) == 'SOS' else 'FAIL'
        ok &= (status == 'OK')
        print(f'[{status}] 变体字符识别: {variant!r} -> {decode(variant)!r}')
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
