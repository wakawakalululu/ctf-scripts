# -*- coding: utf-8 -*-
"""usb_mouse USB 鼠标流量还原轨迹

参考: https://github.com/P001water/UsbmiceCracker (按 CTF 通用做法实现)
用途: Misc 流量题——从 USB 鼠标 HID 数据(按键, dx, dy)还原鼠标轨迹图。
      支持两种输入: 1) usbdata.txt 文本(每行 hex 字节)  2) pcap/pcapng(经 tshark 提取)

HID 报文: [button][dx][dy] (+填充字节), dx/dy 为 8 位有符号相对位移。

用法:
    python usb_mouse.py -f usbdata.txt                     # 文本输入, 连线轨迹图 mouse.png
    python usb_mouse.py -f usbdata.txt --mode click        # 只画左键按下点(常见画图题)
    python usb_mouse.py -p capture.pcapng                  # pcap 输入(需系统装 tshark)
    python usb_mouse.py -f usbdata.txt -s 5 -o out.png     # 放大5倍, 指定输出
    python usb_mouse.py --selftest                         # 自测
"""
import argparse
import sys


def parse_text(path, skip=0):
    """文本: 每行 hex(可带空格), 取 [skip], [skip+1], [skip+2] 三个字节。"""
    reports = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            hexs = ''.join(c for c in line.strip() if c in '0123456789abcdefABCDEF')
            if len(hexs) < (skip + 3) * 2:
                continue
            b = bytes.fromhex(hexs)
            reports.append((b[skip], b[skip + 1], b[skip + 2]))
    return reports


def parse_pcap(path, skip=0):
    """pcap 输入: 借助 tshark 提取 usb.capdata / usbhid.data 字段。
    skip 与文本路径一致: 每行报文起始字节偏移(带前缀的抓包常见)。"""
    import subprocess
    try:
        subprocess.run(['tshark', '--version'], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print('未找到 tshark: 安装 Wireshark 或改用 -f 文本输入'
              '(Wireshark 中选中数据 -> Follow -> Raw Dump 导出文本)')
        sys.exit(2)
    cmd = ['tshark', '-r', path, '-T', 'fields', '-e', 'usb.capdata', '-e', 'usbhid.data']
    r = subprocess.run(cmd, capture_output=True, text=True)
    reports = []
    for line in r.stdout.splitlines():
        hexs = ''.join(c for c in line.strip().replace(':', '')
                       if c in '0123456789abcdefABCDEF')
        if len(hexs) >= (skip + 3) * 2:
            b = bytes.fromhex(hexs)
            reports.append((b[skip], b[skip + 1], b[skip + 2]))   # 原版硬取 b[0..2]
    return reports


def signed(b):
    return b - 256 if b >= 128 else b


def reconstruct(reports):
    """累积相对位移 -> (路径点列表, 左键按下点列表)。"""
    path_pts, click_pts = [], []
    x = y = 0
    prev_btn = 0
    for btn, dx, dy in reports:
        x += signed(dx)
        y += signed(dy)
        if btn & 0x01 and not prev_btn & 0x01:   # 左键按下沿
            click_pts.append((x, y))
        prev_btn = btn
        path_pts.append((x, y))
    return path_pts, click_pts


def draw(path_pts, click_pts, out='mouse.png', scale=3, mode='path'):
    from PIL import Image, ImageDraw
    pts = path_pts + click_pts
    if not pts:
        raise ValueError('没有可绘制的点')
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    margin = 10
    minx, miny = min(xs) - margin, min(ys) - margin
    maxx, maxy = max(xs) + margin, max(ys) + margin
    w = (maxx - minx + 1) * scale
    h = (maxy - miny + 1) * scale
    img = Image.new('RGB', (w, h), (0, 0, 0))
    d = ImageDraw.Draw(img)

    def to_px(p):
        return ((p[0] - minx) * scale, (p[1] - miny) * scale)

    if mode in ('path', 'both'):
        for i in range(1, len(path_pts)):
            d.line([to_px(path_pts[i - 1]), to_px(path_pts[i])], fill=(255, 255, 255), width=scale)
    if mode in ('click', 'both'):
        for p in click_pts:
            cx, cy = to_px(p)
            d.ellipse([cx - scale * 2, cy - scale * 2, cx + scale * 2, cy + scale * 2],
                      fill=(255, 0, 0))
    img.save(out)
    return out, img.size


def main():
    ap = argparse.ArgumentParser(description='USB 鼠标流量轨迹还原')
    ap.add_argument('-f', '--file', help='usbdata 文本文件(每行 hex)')
    ap.add_argument('-p', '--pcap', help='pcap/pcapng 文件(需 tshark)')
    ap.add_argument('--skip', type=int, default=0,
                    help='每行报文起始字节偏移(如 Leftover 数据 4 字节取前3则0)')
    ap.add_argument('--mode', choices=['path', 'click', 'both'], default='path',
                    help='path=连线轨迹 click=左键点 both=叠加')
    ap.add_argument('-s', '--scale', type=int, default=3)
    ap.add_argument('-o', '--out', default='mouse.png')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        # 合成数据: 画一个 "L" 形轨迹 + 一次左键点击
        blocks = []
        for _ in range(4):
            blocks.append((0x00, 0x10, 0x00))    # 右移 4x16
        for _ in range(2):
            blocks.append((0x00, 0x00, 0x10))    # 下移 2x16
        blocks.append((0x01, 0x00, 0x00))        # 左键按下
        blocks.append((0x00, 0x00, 0x00))        # 抬起
        with open('_test_usb.txt', 'w') as f:
            for b in blocks:
                f.write('%02x%02x%02x\n' % b)
        reports = parse_text('_test_usb.txt')
        pts, clicks = reconstruct(reports)
        good = len(pts) == len(blocks) and pts[-1] == (64, 32)
        print(f"[{'OK' if good else 'FAIL'}] 轨迹终点: {pts[-1]} (期望 (64,32))")
        good2 = len(clicks) == 1 and clicks[0] == (64, 32)
        print(f"[{'OK' if good2 else 'FAIL'}] 左键点击点: {clicks}")
        out, size = draw(pts, clicks, out='_test_mouse.png', scale=2, mode='both')
        # 期望画布: (x跨度+21)*scale x (y跨度+21)*scale, margin=10
        xs = [p[0] for p in pts + clicks]
        ys = [p[1] for p in pts + clicks]
        exp = ((max(xs) - min(xs) + 21) * 2, (max(ys) - min(ys) + 21) * 2)
        good3 = size == exp
        print(f"[{'OK' if good3 else 'FAIL'}] 画图输出: {out} {size} (期望 {exp})")
        import os
        os.remove('_test_usb.txt')
        os.remove('_test_mouse.png')
        sys.exit(0 if (good and good2 and good3) else 1)

    if args.pcap:
        reports = parse_pcap(args.pcap, args.skip)
    elif args.file:
        reports = parse_text(args.file, args.skip)
    else:
        ap.error('需要 -f 或 -p(或 --selftest)')
    if not reports:
        print('未解析到 HID 报文; 若为 4 字节 Leftover 数据试试 --skip 0, 数据在报文尾部则加大 --skip')
        sys.exit(1)
    pts, clicks = reconstruct(reports)
    print('报文数: %d, 轨迹点: %d, 左键点: %d' % (len(reports), len(pts), len(clicks)))
    out, size = draw(pts, clicks, args.out, args.scale, args.mode)
    print('已生成:', out, '尺寸:', size)


if __name__ == '__main__':
    main()
