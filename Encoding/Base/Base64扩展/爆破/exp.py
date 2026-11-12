str="JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs****kxyz012789+/"
ciper="MyLkTaP3FaA7KOWjTmKkVjWjVzKjdeNvTnAjoH9iZOIvTeHbVD"#(==没有用)
import string
import binascii
# for i in string.ascii_letters+string.digits:
#     if i not in str:
#         print(i)
import itertools
s=['j','u','3','4']
for i in itertools.permutations(s,4):
    ss="JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs"+"".join(i)+"kxyz012789+/"
    bins = ""
    for j in ciper:
        bins+=bin(ss.index(j))[2:].zfill(6)
    # print(hex(eval("0b"+bins))[2:-1])
    # 原版 [2:-1] 是 py2 去掉 hex(long) 尾部 'L' 的写法, py3 下会切掉真实 hex 位,
    # 位数不巧时 unhexlify 直接 odd-length 报错; 改 to_bytes 按实际位宽转换
    n = int(bins, 2)
    print(n.to_bytes((n.bit_length() + 7) // 8, 'big'))