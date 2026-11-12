# -*- coding: utf-8 -*-
# 流程: 3.txt(01串) --TTL-encode.py--> 5.txt --重命名为 out.txt--> 本脚本解码
# 与 TTL-stego.py 的位序映射一致, 本版对异常行更健壮
with open('out.txt') as a_file:
    content = [x.strip() for x in a_file.readlines()]
bins = []
for i in content:
    if not i:
        continue
    try:
        bins.append(bin(int(i))[2:].zfill(8)[:2])
    except ValueError:
        print('[!] 忽略非数字行:', i)
stringBins = ''.join(bins)
num = 0
flag = ''
n_full = len(stringBins) - len(stringBins) % 8
for i in range(0, n_full, 8):
    flag+=chr(int(stringBins[num:num+8],2))
    num+=8

print(flag)
