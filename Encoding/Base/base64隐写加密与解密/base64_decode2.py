# -*- coding: utf-8 -*-
"""Base64 隐写解码 · 变体(按首个差异字符计算偏移)(py3 移植版)

用法:
    python base64_decode2.py               # 解码当前目录 flag.txt
    python base64_decode2.py stego.txt     # 指定文件
"""
import base64
import sys


def get_base64_diff_value(s1, s2):
    base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    for i in range(min(len(s1), len(s2))):
        if s1[i] != s2[i]:
            return abs(base64chars.index(s1[i]) - base64chars.index(s2[i]))
    return 0


def goflag(bin_str):
    bin_str = bin_str[:len(bin_str) - len(bin_str) % 8]   # 丢弃不足 8 位的尾部
    return ''.join(chr(int(bin_str[i:i + 8], 2)) for i in range(0, len(bin_str), 8))


def solve_stego(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        file_lines = f.readlines()
    bin_str = ''
    for line in file_lines:
        steg_line = line.strip()
        if not steg_line:
            continue
        norm = base64.b64encode(base64.b64decode(steg_line)).decode()
        norm_line = norm.replace('\n', '')
        diff = get_base64_diff_value(steg_line, norm_line)
        pads_num = steg_line.count('=')
        if diff:
            bin_str += bin(diff)[2:].zfill(pads_num * 2)
        else:
            bin_str += '0' * pads_num * 2
    print(goflag(bin_str))


if __name__ == '__main__':
    solve_stego(sys.argv[1] if len(sys.argv) > 1 else './flag.txt')
