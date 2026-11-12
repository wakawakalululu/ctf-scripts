# -*- coding: utf-8 -*-
# 输出按 GBK 编码写入(题目原意: 得到 GBK 编码的字节流)
# 原文件以 GBK 保存且声明 GBK, 已转为 UTF-8 源码 + 显式输出编码, 避免跨 locale 崩溃
f = open("./test.txt", "w", encoding="gbk")
s="Hello everyone, I am Gilbert. Everyone thought that I was killed, but actually I survived. Now that I have no cash with me and I’m trapped in another country. I can't contact Violet now. She must be desperate to see me and I don't want her to cry for me. I need to pay 300 for the train, and 88 for the meal. Cash or battlenet point are both accepted. I don't play the Hearthstone, and I don't even know what is Rastakhan's Rumble."
f.write(s)
f.close()
