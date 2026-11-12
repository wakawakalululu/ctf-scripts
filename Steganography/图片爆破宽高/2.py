import struct
import zlib

def hexStr2bytes(s):
    b = b""
    for i in range(0,len(s),2):
        temp = s[i:i+2]
        b +=struct.pack("B",int(temp,16))
    return b

str1="49484452"#Chunk[0] IHDR
str2="0806000000"#Bit depth、ColorType、Compression method、Filter method、Interlace method
bytes1=hexStr2bytes(str1)
bytes2=hexStr2bytes(str2)
wid,hei = 1308,1280#当前宽高

crc32 = "0x6f03ad71"#图片原来的CRC

# 原版命中后不退出: 2000x2000=400 万次 CRC 会跑几十分钟; 且逐次走
# hex 拼接 + eval 很慢, 改 struct.pack 直接送 CRC
target = int(crc32, 16)
for w in range(wid,wid+2000):
    for h in range(hei,hei+2000):
        if zlib.crc32(bytes1 + struct.pack('>II', w, h) + bytes2) == target:
            print(hex(w),hex(h))
            break
    else:
        continue
    break
