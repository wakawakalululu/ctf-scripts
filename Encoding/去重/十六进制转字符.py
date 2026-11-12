import binascii

with open('data1.txt','r') as file:
    with open('data2.txt','wb') as data:
        for i in file.readlines():
            data.write(binascii.unhexlify(i.strip())) # 原版 i[:-1] 假设必有换行, 末行无换行时切掉真实 hex 位