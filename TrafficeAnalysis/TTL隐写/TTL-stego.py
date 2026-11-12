# -*- coding: utf-8 -*-
# 流程: 3.txt(01串) --TTL-encode.py--> 5.txt --重命名为 attachment.txt--> 本脚本解码
import binascii

f = open('attachment.txt','r')
s = ''
data = ''
# 63/127/191/255 低 2 位分别对应 00/01/10/11
TTL2BITS = {'63': '00', '127': '01', '191': '10', '255': '11'}
# 原版逐个 if i=="63\n" 匹配: 末行无换行/空行/异常 TTL 时沿用上一次的值继续拼接,
# 解码静默错位; 改为 strip 后按数值映射, 异常行显式提示
for i in f.readlines():
    t = i.strip()
    if not t:
        continue
    if t in TTL2BITS:
        s += TTL2BITS[t]
    else:
        print('[!] 忽略异常 TTL 行:', t)
f.close()
# print(s)

n_full = len(s) - len(s) % 8
for i in range(0, n_full, 8): # 每8位一组(不足 8 位的尾部忽略)
    data += chr(int(s[i:i+8],2)) # 转为二进制再转为ASCII字符
data = binascii.unhexlify(data)
print(data)

with open('flag.zip','wb') as f:
    f.write(data)
