# -*- coding: utf-8 -*-
"""img_solve 内存 dump 数据转图片

来源: https://github.com/SourceLizi/ctf-toolbox (py3 重写完善)
用途: 逆向题把图片数据 dump 成 img_dump.mem 后, 按指定宽高还原显示/保存。

用法:
    python img_solve.py img_dump.mem -W 150 -H 600           # 灰度 150x600, 行优先
    python img_solve.py img_dump.mem -W 100 -m rgb           # RGB, 高度按文件大小自动算
    python img_solve.py img_dump.mem -W 150 -H 600 --major col  # 列优先(原版行为)
    python img_solve.py img_dump.mem -W 150 --offset 64 -s 4 # 跳过文件头64字节, 放大4倍
    python img_solve.py img_dump.mem -W 150 -H 600 --save out.png  # 只保存不弹窗
    python img_solve.py                                      # 自测
"""
import argparse
import os
import sys


def load_image(data, width, height, mode="gray", offset=0, major="row", scale=1):
    from PIL import Image
    body = data[offset:]
    need = width * height * (1 if mode == "gray" else 3)
    if len(body) < need:
        print(f"[warn] 数据不足: 需要 {need} 字节, 实际 {len(body)}, 不足部分补 0")
        body = body + b"\x00" * (need - len(body))
    if height == 0:
        height = max(1, len(body) // (width * (1 if mode == "gray" else 3)))
    img = Image.new("RGB", (width, height))
    px = img.load()
    for a in range(width):
        for b in range(height):
            if major == "row":       # 第 a 列第 b 行 -> 像素 (a,b) 按行优先取
                idx = (b * width + a) * (1 if mode == "gray" else 3)
            else:                    # 列优先(原版): 先列后行
                idx = (a * height + b) * (1 if mode == "gray" else 3)
            if mode == "gray":
                v = body[idx]
                px[a, b] = (v, v, v)
            else:
                px[a, b] = (body[idx], body[idx + 1], body[idx + 2])
    if scale > 1:
        img = img.resize((width * scale, height * scale), Image.NEAREST)
    return img


def main():
    ap = argparse.ArgumentParser(description='内存 dump 转图片')
    ap.add_argument('file', nargs='?')
    ap.add_argument('-W', '--width', type=int, default=100, help='宽(默认100)')
    ap.add_argument('-H', '--height', type=int, default=0,
                    help='高(默认0=按剩余数据自动计算)')
    ap.add_argument('-m', '--mode', choices=['gray', 'rgb'], default='gray')
    ap.add_argument('--offset', type=lambda x: int(x, 0), default=0, help='起始字节偏移')
    ap.add_argument('--major', choices=['row', 'col'], default='row',
                    help='row=行优先(默认), col=列优先(原版行为)')
    ap.add_argument('-s', '--scale', type=int, default=1, help='放大倍数')
    ap.add_argument('--save', default='', help='保存为 PNG(不指定则弹窗显示)')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        try:
            from PIL import Image  # noqa: F401
        except ImportError:
            print('缺少依赖: pip install pillow')
            sys.exit(2)
        data = bytes(range(256)) * 2            # 512 字节
        img = load_image(data, 16, 16)          # 灰度 16x16 行优先
        px = img.load()
        good = px[0, 0] == (0, 0, 0) and px[1, 0] == (1, 1, 1) and px[0, 1] == (16, 16, 16)
        good &= px[15, 15] == (255, 255, 255)
        print(f"[{'OK' if good else 'FAIL'}] gray 行优先: {px[0, 0]} {px[1, 0]} {px[0, 1]} {px[15, 15]}")
        img2 = load_image(data, 8, 21, mode='rgb')
        px2 = img2.load()
        good2 = px2[0, 0] == (0, 1, 2) and px2[1, 0] == (3, 4, 5)
        print(f"[{'OK' if good2 else 'FAIL'}] rgb 行优先: {px2[0, 0]} {px2[1, 0]}")
        img3 = load_image(data, 16, 16, major='col')
        px3 = img3.load()
        good3 = px3[1, 0] == (16, 16, 16) and px3[0, 1] == (1, 1, 1)
        print(f"[{'OK' if good3 else 'FAIL'}] gray 列优先(原版): {px3[1, 0]} {px3[0, 1]}")
        img4 = load_image(b'\x10' * 8, 16, 8)   # 不足自动补0
        good4 = img4.size == (16, 8)
        print(f"[{'OK' if good4 else 'FAIL'}] 数据不足自动补齐: {img4.size}")
        sys.exit(0 if (good and good2 and good3 and good4) else 1)

    if not args.file:
        ap.error('需要文件参数(或 --selftest)')
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        print('缺少依赖: pip install pillow')
        sys.exit(2)
    with open(args.file, 'rb') as f:
        data = f.read()
    img = load_image(data, args.width, args.height, args.mode,
                     args.offset, args.major, args.scale)
    if args.save:
        img.save(args.save)
        print('已保存:', args.save, '尺寸:', img.size)
    else:
        img.show()


if __name__ == '__main__':
    main()
