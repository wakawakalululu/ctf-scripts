import gmpy2
N,p,q,e=920139713,49891,18443,19
phi = (p-1)*(q-1)
d=gmpy2.invert(e,phi)
result=[]

with open("c.txt","r") as f:
  for c in f.readlines():
    c=c.strip('\n')
    result.append(chr(pow(int(c),d,N)))

flag=''
for i in result:
  flag+=i
print(flag)   # 原版 print 缩进在循环内, 逐行打印累积前缀 N 次