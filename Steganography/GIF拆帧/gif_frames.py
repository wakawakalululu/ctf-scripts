# -*- coding: utf-8 -*-
"""gif_frames.py — GIF 拆帧导出(帧序列/帧延迟分析, 图片隐写高频题型)

用途: 把 GIF 逐帧导出为 PNG(隐写常把 flag 藏在某一帧或帧延迟里),
      同时打印每帧延迟(单位 ms, 1000/延迟 即秒), 配合
      Steganography/GIF帧时间隐写/ 使用。

依赖:
    pip install pillow

用法:
    python gif_frames.py anim.gif                 # 导出帧到 anim_frames/
    python gif_frames.py anim.gif -o outdir       # 指定输出目录
    python gif_frames.py anim.gif --info          # 只看帧数与延迟不导出
    python gif_frames.py --selftest               # 内置自测
"""
import argparse
import os
import sys

from PIL import Image


def frames_info(path):
    im = Image.open(path)
    n, durations = 0, []
    try:
        while True:
            durations.append(im.info.get('duration', 0))
            n += 1
            im.seek(im.tell() + 1)
    except EOFError:
        pass
    return n, durations


def export(path, outdir):
    im = Image.open(path)
    os.makedirs(outdir, exist_ok=True)
    i = 0
    while True:
        frame = im.convert('RGBA')
        out = os.path.join(outdir, 'frame_%03d.png' % i)
        frame.save(out)
        i += 1
        try:
            im.seek(im.tell() + 1)
        except EOFError:
            break
    print('已导出 %d 帧 -> %s' % (i, outdir))
    return i


def selftest():
    import io
    import tempfile
    # 内存合成 3 帧 GIF
    buf = io.BytesIO()
    frames = [Image.new('RGB', (32, 32), (255, 0, 0)),
              Image.new('RGB', (32, 32), (0, 255, 0)),
              Image.new('RGB', (32, 32), (0, 0, 255))]
    frames[0].save(buf, format='GIF', save_all=True,
                   append_images=frames[1:], duration=100, loop=0)
    fd, gifpath = tempfile.mkstemp(suffix='.gif')
    os.close(fd)
    with open(gifpath, 'wb') as f:
        f.write(buf.getvalue())
    outdir = gifpath + '_frames'
    n = export(gifpath, outdir)
    n2, durations = frames_info(gifpath)
    saved = len(os.listdir(outdir))
    # 清理
    for fn in os.listdir(outdir):
        os.unlink(os.path.join(outdir, fn))
    os.rmdir(outdir)
    os.unlink(gifpath)
    ok = n == 3 and n2 == 3 and saved == 3 and all(d == 100 for d in durations)
    print('GIF 拆帧/帧延迟:', 'OK' if ok else 'FAIL (n=%r n2=%r saved=%r dur=%r)' % (n, n2, saved, durations))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='GIF 拆帧导出')
    ap.add_argument('gif', nargs='?', help='GIF 文件')
    ap.add_argument('-o', '--outdir', help='输出目录(默认 <gif名>_frames)')
    ap.add_argument('--info', action='store_true', help='只显示帧数与延迟')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.gif:
        ap.error('需要 GIF 文件参数(或 --selftest)')
    n, durations = frames_info(args.gif)
    print('帧数: %d' % n)
    print('延迟(ms): %s' % durations)
    if not args.info:
        outdir = args.outdir or os.path.splitext(args.gif)[0] + '_frames'
        export(args.gif, outdir)


if __name__ == '__main__':
    main()
