# -*- coding: utf-8 -*-
"""Nihilist 密码解密 — 基于 5x5 密钥矩阵的替换密码(py3 移植版)

用法: python nihilist.py            # 解码内置样例
     修改 enc/grid 变量为题目数据。
"""
import string

enc = 'PVSF{vVckHejqBOVX9C1c13GFfkHJrjIQeMwf}'
grid = 'LOVEKFC' + 'ABDGHIJMNPQRSTUWXY'
flag = ''

for i in enc:
    if i in string.ascii_lowercase:
        index = grid.lower().index(i)
        flag += string.ascii_lowercase[index]
        continue
    if i in string.ascii_uppercase:
        index = grid.upper().index(i)
        flag += string.ascii_uppercase[index]
        continue
    flag += i
print(flag)
