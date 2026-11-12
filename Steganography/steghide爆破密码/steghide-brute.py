# -*- coding: utf-8 -*-
# python3 运行: 字典爆破 steghide 隐写密码
# 依赖: 系统需安装 steghide 并加入 PATH; 同目录放 flag.jpg 与字典 english.dic
import os
import shutil
import subprocess


def foo():
    stegoFile = 'flag.jpg'      # 隐写的图片
    extractFile = 'result.txt'  # 提取数据的输出文件
    passFile = 'english.dic'    # 字典

    if shutil.which('steghide') is None:
        print('未找到 steghide, 请先安装并加入 PATH')
        return
    if not os.path.isfile(stegoFile):
        print('找不到隐写文件: %s' % stegoFile)
        return
    if not os.path.isfile(passFile):
        print('找不到字典: %s' % passFile)
        return

    wrong = 'could not extract'   # steghide 报密码错误的特征串(白名单判定)
    # 原版用黑名单判定 + shell=True 拼接命令: steghide 不在 PATH/文件不存在时
    # 会被误报成"找到密码", 密码含特殊字符还会破坏命令; 改为白名单 + 列表参数
    with open(passFile, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pwd = line.strip()
            if not pwd:
                continue
            p = subprocess.run(['steghide', 'extract', '-sf', stegoFile,
                                '-xf', extractFile, '-p', pwd],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            content = p.stdout.decode('gbk', 'replace')  # Windows 控制台输出
            if wrong in content:
                continue          # 密码错误, 试下一个
            print(content)
            print('the passphrase is %s' % pwd)
            return
    print('字典已跑完, 未命中密码')


if __name__ == '__main__':
    foo()
