from PIL import Image

x = y = 200 # 需要手动将()去掉
img = Image.new("RGB",(x,y))
file = open('./qr.txt','r')

# 原版固定循环 40000 次 readline: 文件行数不足时读到空串 IndexError 裸崩
lines = [l.strip() for l in file if l.strip()]
file.close()
if len(lines) < x * y:
    raise SystemExit('qr.txt 行数不足: %d < %d' % (len(lines), x * y))

it = iter(lines)
for width in range(0,x):          # 保持原版按列填充(x 外层)的顺序不变
    for height in range(0,y):
        rgb = next(it).split(',')
        img.putpixel((width,height),(int(rgb[0]),int(rgb[1]),int(rgb[2])))
img.save('flag.jpg')
