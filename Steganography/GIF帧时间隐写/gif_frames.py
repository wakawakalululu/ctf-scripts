# -*- coding: utf-8 -*-
"""gif_frames GIF 帧分离 / 帧延时分析

用途: Misc 题把 flag 藏在某一帧, 或用帧延时(长短)编码信息时, 分离帧并输出延时表。

用法:
    python gif_frames.py --selftest                       # 自测
    python gif_frames.py -f anim.gif                      # 打印每帧延时
    python gif_frames.py -f anim.gif --save frames_dir/   # 逐帧导出 PNG
    python gif_frames.py -f anim.gif --odd                # 只列出延时为异常值(离群)的帧
"""
import argparse
import sys


def frame_info(path):
    from PIL import Image
    img = Image.open(path)
    frames = []
    idx = 0
    try:
        while True:
            dur = img.info.get('duration', 0)   # 毫秒
            frames.append((idx, dur, img.convert('RGB').copy()))
            idx += 1
            img.seek(img.tell() + 1)
    except EOFError:
        pass
    return frames


def outliers(durs):
    """离群延时: 与中位数差超过 3 倍中位绝对偏差的帧。"""
    import statistics
    if len(durs) < 3:
        return set()
    med = statistics.median(durs)
    mad = statistics.median([abs(d - med) for d in durs]) or 1
    return {i for i, d in enumerate(durs) if abs(d - med) > 3 * mad}


def main():
    ap = argparse.ArgumentParser(description='GIF 帧分离/延时分析')
    ap.add_argument('-f', '--file', help='gif 文件')
    ap.add_argument('--save', metavar='DIR', help='逐帧导出 PNG 到目录')
    ap.add_argument('--odd', action='store_true', help='只显示延时离群的帧')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        import io
        import os
        import tempfile
        from PIL import Image
        ok = True
        frames = [Image.new('RGB', (16, 16), (i * 40, 0, 0)) for i in range(4)]
        durs = [100, 100, 800, 100]
        buf = io.BytesIO()
        frames[0].save(buf, format='GIF', save_all=True,
                       append_images=frames[1:], duration=durs, loop=0)
        with open('_test.gif', 'wb') as f:
            f.write(buf.getvalue())
        info = frame_info('_test.gif')
        got_durs = [d for _, d, _ in info]
        good = len(info) == 4 and got_durs == durs
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 帧数/延时: {got_durs}")
        odd = outliers(got_durs)
        good2 = odd == {2}
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] 离群帧: {sorted(odd)}")
        os.remove('_test.gif')
        sys.exit(0 if ok else 1)

    if not args.file:
        ap.error('需要 -f(或 --selftest)')
    frames = frame_info(args.file)
    durs = [d for _, d, _ in frames]
    odd = outliers(durs)
    for idx, dur, _img in frames:
        mark = '  <-- 离群' if idx in odd and args.odd else ''
        if not args.odd or idx in odd:
            print(f'frame {idx}: duration={dur}ms{mark}')
    if args.save:
        import os
        os.makedirs(args.save, exist_ok=True)
        for idx, _dur, img in frames:
            img.save(os.path.join(args.save, f'frame_{idx:03d}.png'))
        print(f'已导出 {len(frames)} 帧 -> {args.save}')


if __name__ == '__main__':
    main()
