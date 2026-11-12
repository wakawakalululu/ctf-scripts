import base64
import string

a = base64.b64decode('AAoHAR1TIiIkUFUjUFQgVyInVSVQJVFRUSNRX1YgXiJSVyJQVRs=')

# 原版 flag 在循环外定义且从不清零: 所有候选 key 的异或结果全部累加进同一字符串
for i in string.printable:
    flag = ''.join(chr(ord(i) ^ j) for j in a)
    print(flag + '\n')
