#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""USB HID 键盘流量解析(py3 移植版)

用法:
    python usbtxt.py capture.pcap      # 先用 tshark 提取再解析(需系统装 tshark)
    python usbtxt.py usbdata.txt       # 直接解析已提取的文本(每行形如 00:00:04:00)
输出: 还原的键盘输入; 大写/符号由 Shift 状态映射。
"""
import subprocess
import sys

DataFileName = "usbdata.txt"

normalKeys = {
    "04": "a", "05": "b", "06": "c", "07": "d", "08": "e", "09": "f", "0a": "g", "0b": "h",
    "0c": "i", "0d": "j", "0e": "k", "0f": "l", "10": "m", "11": "n", "12": "o", "13": "p",
    "14": "q", "15": "r", "16": "s", "17": "t", "18": "u", "19": "v", "1a": "w", "1b": "x",
    "1c": "y", "1d": "z", "1e": "1", "1f": "2", "20": "3", "21": "4", "22": "5", "23": "6",
    "24": "7", "25": "8", "26": "9", "27": "0", "28": "<RET>", "29": "<ESC>", "2a": "<DEL>",
    "2b": "\t", "2c": "<SPACE>", "2d": "-", "2e": "=", "2f": "[", "30": "]", "31": "\\",
    "32": "<NON>", "33": ";", "34": "'", "35": "<GA>", "36": ",", "37": ".", "38": "/",
    "39": "<CAP>", "3a": "<F1>", "3b": "<F2>", "3c": "<F3>", "3d": "<F4>", "3e": "<F5>",
    "3f": "<F6>", "40": "<F7>", "41": "<F8>", "42": "<F9>", "43": "<F10>", "44": "<F11>",
    "45": "<F12>"}

shiftKeys = {
    "04": "A", "05": "B", "06": "C", "07": "D", "08": "E", "09": "F", "0a": "G", "0b": "H",
    "0c": "I", "0d": "J", "0e": "K", "0f": "L", "10": "M", "11": "N", "12": "O", "13": "P",
    "14": "Q", "15": "R", "16": "S", "17": "T", "18": "U", "19": "V", "1a": "W", "1b": "X",
    "1c": "Y", "1d": "Z", "1e": "!", "1f": "@", "20": "#", "21": "$", "22": "%", "23": "^",
    "24": "&", "25": "*", "26": "(", "27": ")", "28": "<RET>", "29": "<ESC>", "2a": "<DEL>",
    "2b": "\t", "2c": "<SPACE>", "2d": "_", "2e": "+", "2f": "{", "30": "}", "31": "|",
    "32": "<NON>", "33": "\"", "34": ":", "35": "<GA>", "36": "<", "37": ">", "38": "?",
    "39": "<CAP>", "3a": "<F1>", "3b": "<F2>", "3c": "<F3>", "3d": "<F4>", "3e": "<F5>",
    "3f": "<F6>", "40": "<F7>", "41": "<F8>", "42": "<F9>", "43": "<F10>", "44": "<F11>",
    "45": "<F12>"}


def extract_from_pcap(pcap_path):
    """用 tshark 提取 usb.capdata / usbhid.data 到 usbdata.txt。"""
    cmd = ["tshark", "-r", pcap_path, "-T", "fields",
           "-e", "usb.capdata", "-e", "usbhid.data"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("未找到 tshark: 请安装 Wireshark 或直接提供 usbdata.txt")
        sys.exit(2)
    with open(DataFileName, "w") as f:
        f.write(r.stdout)


def main():
    if len(sys.argv) != 2:
        print("Usage: python usbtxt.py <capture.pcap|usbdata.txt>")
        sys.exit(1)

    path = sys.argv[1]
    if path.lower().endswith((".pcap", ".pcapng", ".cap")):
        extract_from_pcap(path)
        src = DataFileName
    else:
        src = path

    result = ""
    with open(src, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            press = line.strip().replace(":", "").lower()
            if len(press) < 6:
                continue
            press = ":".join(press[i:i + 2] for i in range(0, len(press), 2))
            b = press.split(":")
            try:
                mod = int(b[0], 16)
            except ValueError:        # 非法行直接跳过
                continue
            if mod & 0x22:            # 左Shift(0x02)/右Shift(0x20); 原版只认 0x20
                result += shiftKeys.get(b[2], "")
            elif mod == 0:            # 无修饰键
                result += normalKeys.get(b[2], "")
            # 其余修饰键(Ctrl/Alt/GUI)不产生可打印字符, 忽略
    print("[+] Found : %s" % result)


if __name__ == "__main__":
    main()
