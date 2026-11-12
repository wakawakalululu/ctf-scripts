# -*- coding: utf-8 -*-
"""qr_decode 二维码解码(opencv / pyzbar 双引擎)

用途: Misc 题解码二维码/图片中的 QR; 支持整图、拼图残片(先二值化再试)。

依赖:
    pip install opencv-python     # 引擎1(首选)
    pip install pyzbar            # 引擎2(可选, Windows 需 VC++ 运行库)

用法:
    python qr_decode.py --selftest                # 自测(qrcode 生成 -> 解码)
    python qr_decode.py qr.png                    # 解码单张
    python qr_decode.py qr.png --binarize 128     # 灰度阈值二值化后再试(污损图)
    python qr_decode.py big.png --scale 3         # 小图放大后再解码
"""
import argparse
import sys


def decode_image(path, binarize=0, scale=1):
    """返回 [(引擎名, 内容), ...]"""
    results = []
    img = None
    try:
        import cv2
        import numpy as np
        img = cv2.imread(path)
        if img is None:
            raise ValueError(f'无法读取图片: {path}')
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        if binarize:
            gray = cv2.threshold(gray, binarize, 255, cv2.THRESH_BINARY)[1]
        if scale > 1:
            gray = cv2.resize(gray, None, fx=scale, fy=scale,
                              interpolation=cv2.INTER_NEAREST)
        det = cv2.QRCodeDetector()
        try:
            ok, decoded, _, _ = det.detectAndDecodeMulti(gray)
            if ok:
                results += [('cv2-multi', d) for d in decoded if d]
        except Exception:
            pass
        if not results:
            data, _, _ = det.detectAndDecode(gray)
            if data:
                results.append(('cv2', data))
    except ImportError:
        pass
    if not results:
        try:
            from pyzbar.pyzbar import decode as zbar_decode
            from PIL import Image
            im = Image.open(path).convert('L')
            if scale > 1:
                im = im.resize((im.width * scale, im.height * scale), Image.NEAREST)
            if binarize:
                im = im.point(lambda p: 255 if p > binarize else 0)
            for item in zbar_decode(im):
                results.append(('pyzbar', item.data.decode('utf-8', errors='replace')))
        except ImportError:
            pass
    return results


def main():
    ap = argparse.ArgumentParser(description='二维码解码')
    ap.add_argument('image', nargs='?')
    ap.add_argument('--binarize', type=int, default=0, help='二值化阈值(0=不处理)')
    ap.add_argument('--scale', type=int, default=1, help='放大倍数')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        try:
            import qrcode  # noqa: F401
            import cv2  # noqa: F401
        except ImportError as e:
            print(f'缺少依赖: pip install qrcode opencv-python ({e})')
            sys.exit(2)
        import qrcode
        import os
        msg = 'flag{qr_roundtrip}'
        img = qrcode.make(msg)
        img.save('_test_qr.png')
        results = decode_image('_test_qr.png')
        got = [d for _, d in results]
        good = msg in got
        print(f"[{'OK' if good else 'FAIL'}] 解码: {results}")
        os.remove('_test_qr.png')
        sys.exit(0 if good else 1)

    if not args.image:
        ap.error('需要图片路径(或 --selftest)')
    results = decode_image(args.image, args.binarize, args.scale)
    if not results:
        print('未解出; 尝试 --binarize 阈值 / --scale 放大 / 拼图修复后重试')
        sys.exit(1)
    for engine, data in results:
        print(f'[{engine}] {data}')


if __name__ == '__main__':
    main()
