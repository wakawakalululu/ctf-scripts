# py3 版演示: 原版是 py2 写法 str.decode('base64') / str.encode('base64')
import base64

text = "DR=="
raw = base64.b64decode(text)
print(raw)                                   # 解码后的字节
print(base64.b64encode(raw).decode())        # 再编码回 base64 文本
