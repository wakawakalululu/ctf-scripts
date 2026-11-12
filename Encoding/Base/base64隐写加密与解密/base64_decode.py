# -*- coding: utf-8 -*-
"""Base64 隐写解码(py3 移植版)

原理提示: 带 = 填充的 base64 行, 最后一个字符的低比特位不影响解码结果,
可用来隐藏信息; 与标准重编码结果比较得到偏移, 拼成比特串。

用法:
    python base64_decode.py              # 解码当前目录 1.txt
    python base64_decode.py stego.txt    # 指定文件
"""
import base64
import sys

b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

bin_str = ''
path = sys.argv[1] if len(sys.argv) > 1 else '1.txt'
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        stegb64 = ''.join(line.split())        # 读取文本每一行
        if not stegb64:
            continue
        norm = base64.b64encode(base64.b64decode(stegb64)).decode()
        rowb64 = ''.join(norm.split())         # 标准重编码结果
        # 文本 base64 与标准 base64 的末字符偏移
        offset = abs(b64chars.index(stegb64.replace('=', '')[-1])
                     - b64chars.index(rowb64.replace('=', '')[-1]))
        equalnum = stegb64.count('=')          # 无填充则无隐藏位
        if equalnum:
            bin_str += bin(offset)[2:].zfill(equalnum * 2)

# 8 位一组还原为字符(不足 8 位的尾部丢弃)
bin_str = bin_str[:len(bin_str) - len(bin_str) % 8]
print(''.join(chr(int(bin_str[i:i + 8], 2)) for i in range(0, len(bin_str), 8)))
