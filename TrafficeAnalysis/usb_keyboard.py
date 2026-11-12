# -*- coding: utf-8 -*-
"""
usb_keyboard.py — USB 键盘流量还原(题型:Flag藏于usb键盘流量中)

原理:USB HID 键盘数据在 usb.capdata(或 usbhid.data)里,每包 8 字节:
      [modifier] [保留] [key1..key6]     键码表见 USB HID Usage ID
脚本:
  1. 有 tshark: tshark -r usb.pcap -T fields -e usb.capdata(等价流程)
  2. 无 tshark: 纯 python 直接解析 usbmon(220)/USBPcap(249) 链路层
输出:逐包键码 -> 还原的击键字符串,并自动高亮 flag{...} / 连续数字密码。

用法: python usb_keyboard.py <pcap> [--raw]
"""
import os
import re
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib


def extract_capdata(path):
    """返回 [(包号, data_bytes)],data 为 HID 键盘报告。
    优先 tshark 提取(等价官方题解命令),失败用纯 python。"""
    rows = pcaplib.tshark_fields(path, ['usb.capdata', 'usbhid.data'],
                                 display_filter='usb.capdata || usbhid.data')
    out = []
    if rows is not None:
        for i, row in enumerate(rows, 1):
            for cell in row:
                cell = cell.replace(':', '').replace(',', '')
                if cell:
                    try:
                        out.append((i, bytes.fromhex(cell)))
                    except ValueError:
                        pass
        if out:
            return out, 'tshark'
    # ---- 纯 python 回退 ----
    lt, pkts = pcaplib.read_pcap(path)
    if lt not in (pcaplib.LINKTYPE_USB_LINUX, pcaplib.LINKTYPE_USBPCAP):
        return [], 'not-usb'
    # 键盘为 interrupt 传输的 IN 数据;混合流量时按设备聚类,
    # 优先选报告为 8 字节(经典键盘格式)且数量最多的设备
    by_dev = {}
    for rec in pcaplib.iter_usb(pkts, lt):
        if rec.xfer == 1 and rec.dir_in and 6 <= len(rec.data) <= 16:
            by_dev.setdefault((rec.dev, rec.ep, len(rec.data)), []).append(
                (rec.index, rec.data))
    if not by_dev:
        return [], 'python'
    best_key = max(by_dev, key=lambda k: (k[2] == 8, len(by_dev[k])))
    return by_dev[best_key], 'python'


def decode_all(records):
    """还原击键。返回 (逐包信息列表, 拼接字符串)"""
    lines = []
    text = []
    for pkt_no, data in records:
        ch = pcaplib.decode_hid_keyboard(data)
        if ch is None:
            continue
        text.append(ch)
        lines.append((pkt_no, data.hex(), ch))
    return lines, ''.join(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pcap', nargs='?', default=default_sample())
    ap.add_argument('--raw', action='store_true', help='仅打印 capdata 原始 hex(题解第一步)')
    args = ap.parse_args()
    if not args.pcap or not os.path.exists(args.pcap):
        print('用法: python usb_keyboard.py <usb.pcap>')
        sys.exit(1)

    print('[*] 提取 capdata: %s' % args.pcap)
    records, engine = extract_capdata(args.pcap)
    print('[*] 引擎: %s, 提取到 %d 个含数据的包' % (engine, len(records)))
    if not records:
        print('[-] 没有提取到键盘数据(检查是否为 USB 流量)')
        sys.exit(0)

    if args.raw:
        for pkt_no, data in records:
            print('%4d  %s' % (pkt_no, data.hex(':')))
        return

    lines, text = decode_all(records)
    print('[*] 键码还原:')
    print('    %-6s %-24s %s' % ('包号', 'capdata', '按键'))
    for pkt_no, hexs, ch in lines:
        print('    %-6d %-24s %s' % (pkt_no, hexs, ch if ch else ''))

    print()
    print('[+] 还原出的击键内容:')
    print('    %s' % text)

    # 自动找 flag / 数字密码
    flags = pcaplib.find_flags(text)
    if flags:
        for f in flags:
            print('[+] 答案(flag): %s' % f)
    else:
        digits = re.findall(r'\d{4,}', text)
        if digits:
            print('[+] 答案(数字密码): %s' % ' , '.join(set(digits)))
        words = re.findall(r'[!-~]{6,}', text)
        if words:
            print('[~] 可疑连续字符串: %s' % ' , '.join(words[:10]))


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ('samples/usb_keyboard.pcap',):
        p = os.path.join(here, name)
        if os.path.exists(p):
            return p
    return None


if __name__ == '__main__':
    main()
