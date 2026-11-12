from urllib import parse

s = "10210897103375566531005253102975053545155505050521025256555254995410298561015151985150375568"
flag = ""
i = 0

while(i < len(s)):   # 原版 <= 越界: i==len(s) 时 int('') 抛 ValueError
    if int(s[i:i+3]) < 127:
        flag += chr(int(s[i:i+3]))
        i += 3
    else:
        flag += chr(int(s[i:i+2]))
        i += 2

print(parse.unquote(flag))