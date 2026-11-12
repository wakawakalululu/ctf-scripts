from urllib.parse import unquote

with open('./data.txt') as f:
    lines = f.readlines()
    for line in lines:
        line = unquote(line)
        if '))=' not in line or '--' not in line:
            continue   # 原版 find() 未命中返回 -1: 切片产出垃圾后 int() 崩
        line = line[line.find('))=')+3:line.find('--')]
        print(chr(int(line)),end="")
