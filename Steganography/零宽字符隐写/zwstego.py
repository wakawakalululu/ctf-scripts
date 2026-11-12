# -*- coding: utf-8 -*-
"""zwstego 零宽字符隐写 编码/解码

参考: https://github.com/ridpath/ZeroWidthStego 与 330k unicode_steganography 的通用映射
字符集: U+200B(位0) U+200C(位1) U+200D(字节分隔) U+FEFF(密文边界)
密文格式: FEFF + 每字节8位映射(按字节用200D分隔) + FEFF, 可嵌入任意可见文本之间/末尾。

用法:
    python zwstego.py -e "载体文本" --secret "flag{zws}"     # 输出含隐藏信息的文本
    python zwstego.py -d stego.txt                           # 解出隐藏内容
    python zwstego.py -e cover.txt --secret flag -o out.txt  # 从文件读载体
    python zwstego.py                                        # 自测
"""
import argparse
import sys

ZW_ZERO = '\u200b'   # 位 0
ZW_ONE = '\u200c'    # 位 1
ZW_SEP = '\u200d'    # 字节分隔
ZW_BOUND = '\ufeff'  # 密文边界


def encode(carrier: str, secret: str) -> str:
    bits = ''.join(f'{b:08b}' for b in secret.encode('utf-8'))
    body = ZW_SEP.join(
        ''.join(ZW_ZERO if bit == '0' else ZW_ONE for bit in bits[i:i + 8])
        for i in range(0, len(bits), 8)
    )
    return carrier + ZW_BOUND + body + ZW_BOUND


def decode(text: str) -> str:
    out = []
    for m in _find_payloads(text):
        data = bytearray()
        for chunk in m.split(ZW_SEP):
            if not chunk:
                continue
            bits = ''.join('1' if c == ZW_ONE else '0' for c in chunk)
            if len(bits) == 8:
                data.append(int(bits, 2))
        out.append(data.decode('utf-8', errors='replace'))
    return '\n'.join(out)


def _find_payloads(text: str):
    payloads = []
    i = 0
    while True:
        start = text.find(ZW_BOUND, i)
        if start < 0:
            break
        end = text.find(ZW_BOUND, start + 1)
        if end < 0:
            break
        body = text[start + 1:end]
        if body and all(c in (ZW_ZERO, ZW_ONE, ZW_SEP) for c in body):
            payloads.append(body)
            i = end + 1
        else:
            i = start + 1
    return payloads


def main():
    ap = argparse.ArgumentParser(description='零宽字符隐写')
    ap.add_argument('-e', '--encode', metavar='CARRIER', help='载体文本(或配合 --file)')
    ap.add_argument('-f', '--file', metavar='TXT', help='从文件读载体(-e 用)')
    ap.add_argument('--secret', help='要隐藏的内容(-e 时必填)')
    ap.add_argument('-d', '--decode', metavar='TXT', help='解码目标(文件或直接文本)')
    ap.add_argument('-o', '--out', help='编码结果写入文件')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()

    if args.selftest or not (args.encode or args.file or args.decode):
        selftest()
        return

    if args.encode or args.file:
        if not args.secret:
            ap.error('-e/--file 编码需 --secret')
        carrier = args.encode
        if args.file:
            with open(args.file, 'r', encoding='utf-8') as f:
                carrier = f.read()
        result = encode(carrier, args.secret)
        if args.out:
            with open(args.out, 'w', encoding='utf-8') as f:
                f.write(result)
            print('已写入:', args.out)
        else:
            print(result)
    elif args.decode:
        text = args.decode
        try:
            with open(args.decode, 'r', encoding='utf-8') as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            pass
        hidden = decode(text)
        print(hidden if hidden else '(未发现零宽密文)')


def selftest():
    ok = True
    stego = encode('Hello, world!', 'flag{zw_5t3g0}')
    got = decode(stego)
    good = got == 'flag{zw_5t3g0}'
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] 回环: {got!r}")
    # 中文载体 + 多段密文
    stego2 = encode('第一段', 'A') + '中间可见' + encode('第二段', 'B')
    got2 = decode(stego2)
    good2 = got2 == 'A\nB'
    ok &= good2
    print(f"[{'OK' if good2 else 'FAIL'}] 多段解码: {got2!r}")
    # 无密文文本
    got3 = decode('普通文本')
    good3 = got3 == ''
    ok &= good3
    print(f"[{'OK' if good3 else 'FAIL'}] 普通文本: {got3!r}")
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
