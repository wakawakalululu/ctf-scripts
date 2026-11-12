from PIL import Image
with open ("1.txt",'r') as d:
	flag = Image.new('L',(200,200))
	plain = d.read().strip()   # 原版未 strip: 换行/空白会被当成像素数据导致整图错位
	if len(plain) < 40000:
		raise SystemExit('1.txt 去掉空白后不足 40000 个字符: %d' % len(plain))
	i = 0
	for x in range(200):
		for y in range(200):
			if (plain[i] == '0'):
				flag.putpixel([x,y],0)
			else:
				flag.putpixel([x,y],255)
			i += 1
	flag.show()