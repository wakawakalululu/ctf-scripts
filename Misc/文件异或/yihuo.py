# 逐 nibble 异或 5: 读入 hex 文本, 每个十六进制位 ^5 后写出
# 原版文本模式 + 逐字符 int(i,16), 文件带换行/空白直接 ValueError 且未指定 encoding
original = open("亦真亦假", 'r', encoding='utf-8', errors='ignore').read()
hexstr = ''.join(original.split())          # 容忍换行/空格/制表符
flag = open("flag", 'w')
for i in hexstr:
    tmp = int(i, 16) ^ 5
    flag.write('%x' % tmp)
flag.close()
