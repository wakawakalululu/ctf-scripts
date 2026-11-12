# -*- coding: utf-8 -*-
"""
usb_mouse.py — USB 鼠标流量还原(题型:Flag藏在鼠标移动轨迹中)

原理:USB HID 鼠标数据 4 字节: [按键] [dx 有符号] [dy 有符号] [滚轮]
  如 0x00002000 表示垂直向上移动 0x20=32 像素。
脚本累积坐标还原轨迹,用 PIL 画成 PNG;某些题只在按住左键时画线,
所以同时输出 三个版本:全部移动 / 仅按左键移动 / 仅右键。

用法: python usb_mouse.py <pcap> [输出.png]
"""
import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib


def extract_mouse(path):
    """返回 [(包号, data)] 4字节鼠标报告。"""
    rows = pcaplib.tshark_fields(path, ['usb.capdata', 'usbhid.data'],
                                 display_filter='usb.capdata || usbhid.data')
    out = []
    if rows is not None:
        for i, row in enumerate(rows, 1):
            for cell in row:
                cell = cell.replace(':', '').replace(',', '')
                if len(cell) == 8:
                    try:
                        out.append((i, bytes.fromhex(cell)))
                    except ValueError:
                        pass
        if out:
            return out, 'tshark'
    lt, pkts = pcaplib.read_pcap(path)
    if lt not in (pcaplib.LINKTYPE_USB_LINUX, pcaplib.LINKTYPE_USBPCAP):
        return [], 'not-usb'
    # interrupt IN 且长度像鼠标报告的数据;混合流量时按设备聚类,
    # 优先选报告为 4 字节(经典鼠标格式)且数量最多的设备
    by_dev = {}
    for rec in pcaplib.iter_usb(pkts, lt):
        if rec.xfer == 1 and rec.dir_in and len(rec.data) in (3, 4, 5, 6, 7, 8):
            by_dev.setdefault((rec.dev, rec.ep, len(rec.data)), []).append(
                (rec.index, rec.data))
    if not by_dev:
        return [], 'python'
    best_key = max(by_dev, key=lambda k: (k[2] == 4, len(by_dev[k])))
    return by_dev[best_key], 'python'


def to_signed(b):
    return b - 256 if b >= 128 else b


def build_track(records):
    """返回 (全部轨迹点, 左键按下时的点, 右键按下时的点)
    每个点是 (x, y, button)"""
    x = y = 0
    all_pts, l_pts, r_pts = [], [], []
    for _pkt, data in records:
        if len(data) < 3:
            continue
        btn = data[0]
        dx = to_signed(data[1])
        dy = to_signed(data[2])
        x += dx
        y += dy
        all_pts.append((x, y, btn))
        if btn & 0x01:
            l_pts.append((x, y, btn))
        if btn & 0x02:
            r_pts.append((x, y, btn))
    return all_pts, l_pts, r_pts


def draw_png(segments, out_path, scale=4, pad=20):
    """segments: [[(x,y),...], ...] 每段是一条折线"""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print('[!] 未安装 Pillow,跳过画图: pip install pillow')
        return False
    pts = [p for seg in segments for p in seg]
    if not pts:
        return False
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    w = (max(xs) - min(xs) + 1) * scale + pad * 2
    h = (max(ys) - min(ys) + 1) * scale + pad * 2
    img = Image.new('RGB', (min(w, 10000), min(h, 10000)), 'white')
    dr = ImageDraw.Draw(img)
    for seg in segments:
        if len(seg) < 2:
            continue
        pix = [(pad + (px - min(xs)) * scale, pad + (py - min(ys)) * scale)
               for px, py in seg]
        dr.line(pix, fill='black', width=max(1, scale // 2))
    img.save(out_path)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pcap', nargs='?', default=default_sample())
    ap.add_argument('outpng', nargs='?', default=None)
    ap.add_argument('--dump', action='store_true', help='打印原始 capdata(题解第一步)')
    args = ap.parse_args()
    if not args.pcap or not os.path.exists(args.pcap):
        print('用法: python usb_mouse.py <usb.pcap> [out.png]')
        sys.exit(1)

    print('[*] 提取鼠标 capdata: %s' % args.pcap)
    records, engine = extract_mouse(args.pcap)
    print('[*] 引擎: %s, 提取到 %d 个数据包' % (engine, len(records)))
    if not records:
        print('[-] 没有提取到鼠标数据')
        sys.exit(0)

    if args.dump:
        for pkt_no, data in records:
            print('%4d  %s' % (pkt_no, data.hex(':')))
        return

    all_pts, l_pts, r_pts = build_track(records)
    print('[*] 坐标范围: x[%d..%d] y[%d..%d],移动事件 %d 个,左键按下 %d 个,右键 %d 个' % (
        min(p[0] for p in all_pts), max(p[0] for p in all_pts),
        min(p[1] for p in all_pts), max(p[1] for p in all_pts),
        len(all_pts), len(l_pts), len(r_pts)))

    def to_segments(pts):
        """把点列切成连续折线:按键变化处断开;
        抬笔移动的点被过滤后,位置突跳(>20px)处也要断开,否则会画出斜线"""
        segs, cur = [], []
        last_btn = None
        for x, y, btn in pts:
            if cur:
                px, py = cur[-1]
                if btn != last_btn or abs(x - px) + abs(y - py) > 20:
                    segs.append(cur)
                    cur = []
            cur.append((x, y))
            last_btn = btn
        if cur:
            segs.append(cur)
        return segs

    base = os.path.splitext(args.outpng or args.pcap)[0]
    for name, pts in (('all', all_pts), ('left', l_pts), ('right', r_pts)):
        if not pts:
            continue
        out = '%s_%s.png' % (base, name)
        if draw_png(to_segments(pts), out):
            print('[+] 轨迹图已保存: %s  (%s 模式)' % (out, name))
    print('[*] 用看图软件打开 PNG 即可看到 flag 字样;'
          '若全图杂乱,优先看 *_left.png(按住左键拖动画的字)')


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, 'samples/usb_mouse.pcap')
    return p if os.path.exists(p) else None


if __name__ == '__main__':
    main()
