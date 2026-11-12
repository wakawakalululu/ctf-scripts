from collections import Counter
f = open('./out.txt','r', encoding='utf-8', errors='ignore')   # 原版未指定编码, GBK 默认读 UTF-8 文件会炸
f_read = f.read()
print(Counter(f_read))