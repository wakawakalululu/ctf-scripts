#coding:utf-8
import argparse
import os

ap = argparse.ArgumentParser(description='批量给目录下文件添加 .jpg 后缀')
ap.add_argument('path', help='目标目录(原版硬编码原作者机器的 G:\\ 路径)')
args = ap.parse_args()

for i in os.listdir(args.path):
    # 跳过 flag.zip; 已带 .jpg 的跳过, 防止重复运行叠加成 xxx.jpg.jpg
    if i == 'flag.zip' or i.endswith('.jpg'):
        continue
    old_name = os.path.join(args.path, i)
    new_name = os.path.join(args.path, i + '.jpg')
    os.rename(old_name, new_name)
