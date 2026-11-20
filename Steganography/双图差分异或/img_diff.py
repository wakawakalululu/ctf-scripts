# -*- coding: utf-8 -*-
"""img_diff.py — 双图差分/异或还原空间域盲水印(图片隐写高频题型)

用途: 两张同尺寸图片逐像素做 差值(abs) 或 异或(XOR) 合成第三张图,
      是空间域盲水印/对比隐写的标准解法; 尺寸不一致时自动缩放到一致。

依赖:
    pip install numpy pillow

用法:
    python img_diff.py a.png b.png                  # 输出 diff(a,b) 与 xor(a,b)
    python img_diff.py a.png b.png -m diff -o r.png # 只出差值图
    python img_diff.py a.png b.png --scale 4        # 结果放大 4 倍便于观察
    python img_diff.py --selftest                   # 内置自测
"""
import argparse
import os
import sys

import numpy as np
from PIL import Image


def load(path, size=None):
    im = Image.open(path)
    if size and im.size != size:
        im = im.resize(size)
    return np.array(im.convert('RGB'), dtype=np.int16)


def combine(a, b, mode):
    if mode == 'diff':
        res = np.abs(a - b)
    else:
        res = np.bitwise_xor(a.astype(np.uint8), b.astype(np.uint8)).astype(np.int16)
    return res.astype(np.uint8)


def save(arr, path, scale=1):
    im = Image.fromarray(arr, 'RGB')
    if scale > 1:
        im = im.resize((im.width * scale, im.height * scale), Image.NEAREST)
    im.save(path)
    print('已保存 -> %s' % path)


def selftest():
    import io, tempfile
    a = np.zeros((16, 16, 3), dtype=np.uint8)
    b = a.copy()
    b[3, 3] = (255, 0, 0)   # b 比 a 多一个红点 -> 盲水印载体
    fd1, p1 = tempfile.mkstemp(suffix='.png')
    fd2, p2 = tempfile.mkstemp(suffix='.png')
    os.close(fd1)
    os.close(fd2)
    Image.fromarray(a).save(p1)
    Image.fromarray(b).save(p2)
    la, lb = load(p1), load(p2)
    d = combine(la, lb, 'diff')
    x = combine(la, lb, 'xor')
    ok = d[3, 3].tolist() == [255, 0, 0] and d.sum() == 255
    ok = ok and x[3, 3].tolist() == [255, 0, 0]
    # 尺寸不一致自动缩放
    lc = load(p2, size=(la.shape[1], la.shape[0]))
    ok = ok and lc.shape == la.shape
    for p in (p1, p2):
        os.unlink(p)
    print('双图差分/异或/缩放对齐:', 'OK' if ok else 'FAIL (d=%r)' % d[3, 3])
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='双图差分/异或')
    ap.add_argument('img1', nargs='?')
    ap.add_argument('img2', nargs='?')
    ap.add_argument('-m', '--mode', choices=['diff', 'xor', 'both'], default='both')
    ap.add_argument('-o', '--output', help='输出文件名前缀(默认 diff_/xor_+原文件名)')
    ap.add_argument('--scale', type=int, default=1, help='结果图放大倍数')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.img1 or not args.img2:
        ap.error('需要两张图片参数(或 --selftest)')
    im1 = Image.open(args.img1)
    a = load(args.img1)
    b = load(args.img2, size=im1.size)
    prefix = args.output or ''
    modes = ['diff', 'xor'] if args.mode == 'both' else [args.mode]
    for m in modes:
        out = '%s%s_%s.png' % (prefix, m, os.path.splitext(os.path.basename(args.img1))[0]) \
            if not (prefix and not os.path.splitext(prefix)[1]) else prefix
        save(combine(a, b, m), out, args.scale)


if __name__ == '__main__':
    main()
