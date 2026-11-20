# -*- coding: utf-8 -*-
"""ascii2img.py — 字符画转灰度图片(把 ASCII art 还原成图, Misc/隐写高频)

用途: 按字符亮度梯度把字符画还原成灰度图(常见"flag 画在字符画里"、
      字符画->图片->二维码 扫码题型)。默认梯度
      " .:-=+*#%@"(由暗到亮), --charset 自定义, --invert 反相。

依赖:
    pip install numpy pillow

用法:
    python ascii2img.py art.txt -o out.png            # 字符画 -> 灰度图
    python ascii2img.py art.txt --charset "@#*+=-:. " # 自定义亮度序(亮到暗)
    python ascii2img.py art.txt --invert              # 反相
    python ascii2img.py --selftest                    # 内置自测
"""
import argparse
import os
import sys

import numpy as np
from PIL import Image

DEFAULT_GRADIENT = ' .:-=+*#%@'  # 由暗到亮


def load_charset(s, invert=False):
    if not s:
        s = DEFAULT_GRADIENT
    if invert:
        s = s[::-1]
    levels = {}
    for i, ch in enumerate(s):
        if ch not in levels:
            levels[ch] = int(i / max(len(s) - 1, 1) * 255)
    return levels


def convert(text, charset=None, invert=False, scale=8):
    levels = load_charset(charset, invert)
    lines = [ln.rstrip('\n') for ln in text.splitlines() if ln.strip()]
    w = max(len(ln) for ln in lines)
    h = len(lines)
    img = np.zeros((h, w), dtype=np.uint8)
    for y, ln in enumerate(lines):
        for x, c in enumerate(ln):
            img[y, x] = levels.get(c, levels.get(' ', 0))
    if scale > 1:
        img = np.repeat(np.repeat(img, scale, axis=0), scale, axis=1)
    return Image.fromarray(img, 'L')


def selftest():
    art = '@@@\n@@@\n...\n...'          # 亮块在上, 暗块在下
    im = convert(art, scale=1)
    px = im.load()
    ok = px[1, 1] > 200 and px[1, 3] < 60   # '@' 应亮, '.' 应暗
    im2 = convert(art, invert=True, scale=1)
    ok = ok and im2.load()[1, 1] < 60       # 反相后 '@' 应暗
    print('字符画转灰度图/反相:', 'OK' if ok else 'FAIL (%d/%d)' % (px[1, 1], px[1, 3]))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='字符画转图片')
    ap.add_argument('file', nargs='?', help='字符画文本文件')
    ap.add_argument('-o', '--output', help='输出 PNG(默认 <文件名>_img.png)')
    ap.add_argument('--charset', help='自定义字符亮度梯度(默认 .:-=+*#%@ 由暗到亮)')
    ap.add_argument('--invert', action='store_true', help='反相')
    ap.add_argument('--scale', type=int, default=8, help='每字符边长像素(默认 8)')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.file:
        ap.error('需要字符画文本文件(或 --selftest)')
    text = open(args.file, encoding='utf-8', errors='replace').read()
    out = args.output or os.path.splitext(args.file)[0] + '_img.png'
    convert(text, args.charset, args.invert, args.scale).save(out)
    print('已保存 -> %s' % out)


if __name__ == '__main__':
    main()
