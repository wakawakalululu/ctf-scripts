with open("./cipher.txt","r") as f:
    data = f.read().strip()   # 原版未 strip: 末尾换行拼进最后一组 int(...,2) 直接崩
    for i in range(0, len(data) - len(data) % 8, 8):
        # print(data[i:i+8])
        print(chr(int(data[i:i+8],2)),end="")