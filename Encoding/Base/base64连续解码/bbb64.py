import base64
import binascii

with open('./flag.txt', 'r') as f:
    data = f.read().strip()      # 原版 readlines()[0] 只取第一行
while True:
    try:
        data = base64.b64decode(data)
    except (binascii.Error, ValueError):
        print(data)              # 解不动了: 打印解到最后一层的内容
        break
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        print(data)              # 中间层已是二进制明文, 直接展示
        break
    if '{' in text:
        print(data)
        exit(0)
