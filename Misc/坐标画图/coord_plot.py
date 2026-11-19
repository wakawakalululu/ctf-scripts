# -*- coding: utf-8 -*-
"""coord_plot.py — 坐标点/连线画图(misc 高频: 给一堆坐标求 flag 图)

用途: 题目给文本坐标(每行 "x,y" / "x y" / "(x,y)", 也可能是浮点/负数),
      自动归一化缩放后用 PIL 画成图片。空行(或 --sep 字符串)分隔多段笔画,
      段内连线、段间不连; --mode point 只打点不连线。
      自动翻转 Y 轴(数学坐标 -> 图片坐标), 出图即可肉眼读 flag。

用法:
    python coord_plot.py points.txt                  # 默认连线画图 -> out.png
    python coord_plot.py points.txt -o flag.png --mode point
    python coord_plot.py points.txt --sep ';'        # ';' 行分隔笔画
    python coord_plot.py --data "0,0 100,50 0,100"   # 直接命令行给坐标
    python coord_plot.py --selftest                  # 内置自测
"""
import argparse
import os
import re
import sys
from PIL import Image, ImageDraw

RE_PAIR = re.compile(r'[-+]?\d+(?:\.\d+)?')

DEFAULT_SEP = '__STROKE__'      # 空行转成该哨兵再统一处理


def load_coords(text, sep=None):
    """解析坐标文本 -> [ [(x,y)...](笔画1), ... ]。
    空行默认分隔笔画; 传 sep 时用该行内容(如 '--')分隔。"""
    strokes, cur = [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            if cur:
                strokes.append(cur)
                cur = []
            continue
        if sep and line == sep:
            if cur:
                strokes.append(cur)
                cur = []
            continue
        nums = [float(x) for x in RE_PAIR.findall(line)]
        # 一行内可含多个坐标对: "x,y" 或 "x,y x,y ..." 两两分组
        for i in range(0, len(nums) - 1, 2):
            cur.append((nums[i], nums[i + 1]))
    if cur:
        strokes.append(cur)
    return strokes


def render(strokes, out, mode='line', width=0, height=0, pad=20, bg=(255, 255, 255), fg=(0, 0, 0)):
    pts = [p for s in strokes for p in s]
    if not pts:
        raise ValueError('没有解析到任何坐标')
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
    span_x, span_y = (x1 - x0) or 1.0, (y1 - y0) or 1.0
    W = int(width or min(max(400, (x1 - x0) + 2 * pad), 4000))
    H = int(height or min(max(400, (y1 - y0) + 2 * pad), 4000))
    scale = min((W - 2 * pad) / span_x, (H - 2 * pad) / span_y)
    img = Image.new('RGB', (W, H), bg)
    dr = ImageDraw.Draw(img)

    def tp(p):
        # 数学坐标 -> 图片坐标: 缩放居中 + Y 轴翻转
        x = pad + (p[0] - x0) * scale + (W - 2 * pad - span_x * scale) / 2
        y = pad + (p[1] - y0) * scale + (H - 2 * pad - span_y * scale) / 2
        return x, H - y

    for s in strokes:
        pix = [tp(p) for p in s]
        if mode == 'line' and len(pix) >= 2:
            dr.line(pix, fill=fg, width=2)
        for p in pix:
            dr.ellipse([p[0] - 1, p[1] - 1, p[0] + 1, p[1] + 1], fill=fg)
    img.save(out)
    return out, W, H, len(pts)


SAMPLE = '''
0,0
100,0
100,80
200,80
200,0
300,0

0,120
50,200
100,120
'''


def selftest():
    import tempfile
    strokes = load_coords(SAMPLE)
    ok = len(strokes) == 2 and len(strokes[0]) == 6 and len(strokes[1]) == 3
    path = os.path.join(tempfile.gettempdir(), 'coord_plot_selftest.png')
    out, W, H, n = render(strokes, path)
    g = Image.open(out).convert('L')
    dark = sum(1 for v in g.tobytes() if v < 128)
    ok &= n == 9 and dark > 50          # 有笔画像素(默认模式含点+线)
    out2, _, _, _ = render(strokes, path, mode='point')
    g2 = Image.open(out2).convert('L')
    dark2 = sum(1 for v in g2.tobytes() if v < 128)
    ok &= dark2 > 0 and dark2 < dark    # 只打点像素更少
    # 一行多对(空格分隔) 与 一行一对 均可解析
    ok &= load_coords('1,1 2,2\n3,3')[0] == [(1.0, 1.0), (2.0, 2.0), (3.0, 3.0)]
    os.remove(path)
    print('[%s] coord_plot.py 自测: 解析 %d 笔画 / %d 点, line=%d px, point=%d px'
          % ('OK' if ok else 'FAIL', len(strokes), n, dark, dark2))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='坐标文本画图(PIL)')
    ap.add_argument('file', nargs='?', help='坐标文本文件(每行 x,y 或 x y)')
    ap.add_argument('--data', help='直接命令行给坐标, 如 "0,0 100,50\\n0,100"')
    ap.add_argument('-o', '--out', default='coord_out.png', help='输出图片路径')
    ap.add_argument('--mode', choices=['line', 'point'], default='line', help='连线/打点')
    ap.add_argument('--sep', help='笔画分隔行的内容(如 "--"); 默认空行分隔')
    ap.add_argument('--width', type=int, default=0, help='画布宽(默认按坐标范围)')
    ap.add_argument('--height', type=int, default=0, help='画布高(默认按坐标范围)')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()

    if args.data:
        text = args.data.replace('\\n', '\n')
    elif args.file and os.path.exists(args.file):
        with open(args.file, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    else:
        print('用法: python coord_plot.py <points.txt> [-o out.png --mode line|point]')
        print('      python coord_plot.py --data "0,0 100,50\\n0,100"')
        print('      python coord_plot.py --selftest')
        return 1

    try:
        strokes = load_coords(text, args.sep)
        out, W, H, n = render(strokes, args.out, args.mode, args.width, args.height)
    except ValueError as e:
        print('[!] %s' % e)
        return 1
    print('[+] %d 笔画 / %d 点 -> %s (%dx%d)' % (len(strokes), n, out, W, H))
    return 0


if __name__ == '__main__':
    sys.exit(main())
