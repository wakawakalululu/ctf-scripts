# -*- coding: utf-8 -*-
"""maze_run 迷宫路线方向键记录器(GUI)

来源: https://github.com/SourceLizi/ctf-toolbox (py3 完善)
用途: 逆向/Misc 题中符号组成迷宫时, 用方向键沿迷宫走一遍, 自动记录方向序列(wasd)。

用法:
    python maze_run.py                    # 打开 GUI, 方向键行走, Esc 清空
    python maze_run.py --out path.txt     # 关闭窗口时把记录写入文件
    python maze_run.py --chars wasd       # 自定义四方向字符(默认 wasd)
记录内容在窗口顶部输入框中实时显示, 也可直接手动复制。
"""
import argparse
import sys

try:
    import tkinter
except ImportError:
    print('缺少 tkinter(Windows 自带; Linux: sudo apt install python3-tk)')
    sys.exit(2)

WIN_WIDTH = 60


def main():
    ap = argparse.ArgumentParser(description='迷宫路线方向键记录器')
    ap.add_argument('--chars', default='wasd',
                    help='上下左右对应字符, 默认 wasd(顺序: 上 下 左 右)')
    ap.add_argument('--out', default='', help='关闭窗口时保存记录到文件')
    args = ap.parse_args()
    if len(args.chars) != 4:
        ap.error('--chars 需要 4 个字符')
    up_c, down_c, left_c, right_c = args.chars

    mwin = tkinter.Tk()
    mwin.title("maze_runner")
    move_log = tkinter.StringVar(mwin)

    entry = tkinter.Entry(mwin, textvariable=move_log, width=WIN_WIDTH)
    entry.pack()

    def _add(ch):
        move_log.set(move_log.get() + ch)

    def clear_event(_event):
        move_log.set("")

    text = tkinter.Text(mwin, width=WIN_WIDTH)
    text.bind("<KeyPress-Up>", lambda e: _add(up_c))
    text.bind("<KeyPress-Down>", lambda e: _add(down_c))
    text.bind("<KeyPress-Left>", lambda e: _add(left_c))
    text.bind("<KeyPress-Right>", lambda e: _add(right_c))
    text.bind("<KeyPress-Escape>", clear_event)
    text.pack()
    text.focus_set()

    written = [False]   # 写盘标志: 原版 on_close 与 mainloop 后的兜底会写两次,
                        # 第二次先 open('w') 截断再 get() 已销毁窗口, 会把文件清空

    def write_out():
        if written[0]:
            return
        written[0] = True
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(move_log.get())

    if args.out:
        def on_close():
            write_out()
            mwin.destroy()
        mwin.protocol("WM_DELETE_WINDOW", on_close)

    mwin.mainloop()
    if args.out and not written[0]:  # 异常退出(Ctrl+C 等)时兜底写盘
        try:
            write_out()
        except Exception:
            pass
    print("记录:", move_log.get())


if __name__ == '__main__':
    main()
