data = open("photo.dat","rb")
strs = data.read()
data.close()
flag = open("flag.jpg","wb")   # 原版 'ab+' 追加模式, 重复运行会把两份异或数据叠加
for i in strs:
	flag.write(bytes([i ^ 0x33]))
flag.close()