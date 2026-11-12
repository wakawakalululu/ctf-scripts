import cv2
import numpy as np
import random
import os
from argparse import ArgumentParser

ALPHA = 5

def build_parser():
    parser = ArgumentParser()
    parser.add_argument('--original', dest='ori', required=True)
    parser.add_argument('--image', dest='img', required=True)
    parser.add_argument('--result', dest='res', required=True)
    parser.add_argument('--alpha', dest='alpha', type=float, default=ALPHA)
    return parser

def main():
    parser = build_parser()
    options = parser.parse_args()
    ori = options.ori
    img = options.img
    res = options.res
    alpha = options.alpha
    if not os.path.isfile(ori):
        parser.error("original image %s does not exist." % ori)
    if not os.path.isfile(img):
        parser.error("image %s does not exist." % img)
    decode(ori, img, res, alpha)

def decode(ori_path, img_path, res_path, alpha):
    ori = cv2.imread(ori_path)
    img = cv2.imread(img_path)
    ori_f = np.fft.fft2(ori)
    img_f = np.fft.fft2(img)
    height, width = ori.shape[0], ori.shape[1]
    watermark = (ori_f - img_f) / alpha
    watermark = np.real(watermark)
    res = np.zeros(watermark.shape)
    random.seed(height + width)
    # py3 修复: range() 返回对象不能 shuffle, height/2 是浮点(原 py2 写法)
    h2 = height // 2
    x = list(range(h2))
    y = list(range(width))
    random.shuffle(x)
    random.shuffle(y)
    for i in range(h2):
        for j in range(width):
            res[x[i]][y[j]] = watermark[i][j]
    # float64 含负值, JPEG 无法保存且 imwrite 静默返回 False; 归一化到 0-255 再写
    res = np.abs(res)
    cv2.normalize(res, res, 0, 255, cv2.NORM_MINMAX)
    res = res.astype(np.uint8)
    if not cv2.imwrite(res_path, res, [int(cv2.IMWRITE_JPEG_QUALITY), 100]):
        print('写入失败:', res_path)

if __name__ == '__main__':
    main()