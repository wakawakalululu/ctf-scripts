import pickle  

fp = open("123.txt","rb+")
fw = open('pickle.txt', 'w')
a=pickle.load(fp)
data=str(a)   # 原版变量名 pickle 覆盖了同名模块, 后续再 load/dump 即 AttributeError
fw.write( data )
fw.close()
fp.close()