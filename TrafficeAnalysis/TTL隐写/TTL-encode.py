import binascii

# 读取文件内容: strip 掉空白/换行, 否则最后一个窗口拼进 '\n' 时 int(...,2) 抛 ValueError
f = open('3.txt','r')
content = f.read().strip()
f.close()

content3 = ''
# 原版 for i in range(0,len(content)) 滑窗步长为 1: 每个比特都会成为一次窗口起点,
# 行数=内容长度, 解码端(stego/stego2)每行只还原 2 位, 永远无法与原文对齐;
# 改为步长 2, 每行编码一对比特, 编码→解码可往返
for i in range(0, len(content) - 1, 2):
    content1 = content[i:i+2] + '111111'
    content2 = hex(int(content1,2))
    content3 += str(int(content2,16))+ '\n'

# 原版 'a+' 追加模式, 重复运行内容翻倍污染
with open('5.txt','w') as f:
    f.write(content3)
