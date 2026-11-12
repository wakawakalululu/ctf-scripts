# -*- coding: utf-8 -*-
"""robot_maze 迷宫求解(py3 移植完善版)

来源: https://github.com/0xaww/robot_maze (原 py2)
完善: py3 移植(整除/print)、pic2array 周期检测修复(跳过一路同色到边缘的采样点,
格子宽 = min(p2+p3) - 1, 原版 -1 是对的)、二值化去抖动、数组越界修复、
argparse 负坐标(--end -2,-2)兼容、新增 CLI 与自测。

用法:
    python robot_maze.py --selftest                        # 自测(生成迷宫→求解→验证)
    python robot_maze.py --solve maze.txt                  # 求解文本迷宫(默认墙# 路' '起* 终D)
    python robot_maze.py --solve maze.txt --move UDLR --wall 0 --path 1 --begin 2 --end 3
    python robot_maze.py --pic maze.png --start 1,1 --end 19,19   # 图片迷宫
    python robot_maze.py --gen 21 --out maze.txt           # 生成随机迷宫(字符迷宫)
    python robot_maze.py --gen 21 --out maze.png --picgen  # 生成图片迷宫

类 API(交互式探索模式, 适合边交互边探路):
    from robot_maze import Robot
    robot = Robot(mode="all", move={"up":"U","down":"D","left":"L","right":"R"})
    while not robot.all_finish:
        step = robot.next_step()          # 下一步方向序列
        if 命中终点: robot.set_point(8)
        elif 撞墙:   robot.set_point(0)
        else:        robot.set_point(1)
    print(robot.min_output)               # 起点到终点最短路径
"""
import argparse
import os
import random
import sys


def _int_div(a, b):
    return a // b


class Robot(object):

    def __init__(self, mode="all", size=400,
                 move=None, debug=False, scan_mode="dst", pic_debug=False,
                 wall="#", path=" ", begin="*", dst="D", pic_counter=50):
        if move is None:
            move = {"up": "u", "down": "d", "left": "l", "right": "r"}
        self.mode = mode
        self.start_time = self.end_time = 0.0
        self.x_size = size
        self.y_size = size
        self.array = [[9] * self.x_size for _ in range(self.y_size)]
        self.begin_x = _int_div(self.x_size, 4)
        self.begin_y = _int_div(self.y_size, 4)
        self.now_x = self.begin_x
        self.now_y = self.begin_y
        self.array[self.now_y][self.now_x] = 7
        self.next_x = 0
        self.next_y = 0
        self.last = [self.begin_x, self.begin_y]
        self.lastoutput = []
        self.next_output = []
        self.now_output = []
        self.output = []
        self.all_output = []
        self.min_output = []
        self.point_finish = 0
        self.next_exit = []
        self.forks = []
        self.dst_finish = 0
        self.all_finish = 0
        self.wall = wall
        self.path = path
        self.dst = dst
        self.begin = begin
        self.move = move
        self.counter = 0
        self.debug = debug
        self.scan_mode = scan_mode
        self.pic_debug = pic_debug
        self.pic_counter = pic_counter
        self.directions = {
            "up": ["right", "up", "left", "down"],
            "down": ["left", "down", "right", "up"],
            "left": ["up", "left", "down", "right"],
            "right": ["down", "right", "up", "left"],
        }
        self.exits = self.directions["up"]
        self.round = {}

    def help(self):
        print(__doc__)

    def exception(self, e="robot failed", func_name="unknown"):
        print(func_name + " has a problem:")
        print(str(e))
        if self.pic_debug:
            self.save_pic()
        raise

    # ---------- 表示转换 ----------
    def str2array(self, string):
        array = []
        for line in string.replace("\r\n", "\n").strip("\n").split("\n"):
            array.append(list(line))
        return array

    def pic2array(self, file="./array2pic.png", point_debug=False, wall=0, path=1):
        from PIL import Image

        def four_ways(x, y, pic, limit):
            # 返回左右/上下首个异色像素的距离之和(= 格子边长 + 1);
            # 某方向一路同色到图片边缘时无法测周期, 返回 None 让调用方跳过该采样点
            p1 = pic.getpixel((x, y))
            p2 = p3 = p4 = p5 = -1
            for block in range(1, limit):
                if p2 == -1 and p1 != pic.getpixel((min(x + block, pic.size[0] - 1), y)):
                    p2 = block
                if p3 == -1 and p1 != pic.getpixel((max(x - block, 0), y)):
                    p3 = block
                if p4 == -1 and p1 != pic.getpixel((x, min(y + block, pic.size[1] - 1))):
                    p4 = block
                if p5 == -1 and p1 != pic.getpixel((x, max(y - block, 0),)):
                    p5 = block
                if p2 != -1 and p3 != -1 and p4 != -1 and p5 != -1:
                    return p2 + p3, p4 + p5
            return None

        pic = Image.open(file)
        check_pic = pic.copy()
        # 经 L 无抖动阈值二值化, 避免抗锯齿灰阶被抖动成椒盐噪声
        pic = pic.convert("L").convert("1", dither=Image.Dither.NONE)
        x_size, y_size = pic.size
        limit = max(pic.size)
        x_list, y_list = [], []
        for i in range(1, 10):
            for j in range(1, 10):
                r = four_ways(x_size * j // 10, y_size * i // 10, pic, limit)
                if r is not None:
                    x_list.append(r[0])
                    y_list.append(r[1])
        if len(x_list) < 10:
            raise ValueError("未检测到色块周期(图片可能不是分块迷宫)")
        # p2+p3 是"相邻两个异色像素的间距" = 格子边长 + 1, 故需再减 1
        x_block, y_block = min(x_list) - 1, min(y_list) - 1
        if min(x_block, y_block) < 1:
            raise ValueError("检测到异常格子周期: %dx%d" % (x_block, y_block))
        if point_debug:
            print("block:", x_block, y_block)
        array = []
        for y in range(0, y_size // y_block + 1):
            tmp = []
            for x in range(0, x_size // x_block + 1):
                cx = x_block // 2 + x_block * x
                cy = y_block // 2 + y_block * y
                if cx >= x_size or cy >= y_size:
                    continue
                out = pic.getpixel((cx, cy))
                check_pic.putpixel([cx, cy], (0, 255, 127))
                if out == 0:
                    tmp.append(wall)
                elif out == 255:
                    tmp.append(path)
            if tmp:
                array.append(tmp)
        if point_debug:
            check_pic.save("check_point.png")
        return array

    def array2pic(self, array, wall=0, path=1, dst=8, begin=7, file="./array2pic.png"):
        from PIL import Image
        pic = Image.new("RGB", (len(array[0]), len(array)))
        for y in range(len(array)):
            for x in range(len(array[0])):
                if array[y][x] == path:
                    pic.putpixel([x, y], (255, 255, 255))
                elif array[y][x] == wall:
                    pic.putpixel([x, y], (0, 0, 0))
                elif array[y][x] == begin:
                    pic.putpixel([x, y], (255, 0, 0))
                elif array[y][x] == dst:
                    pic.putpixel([x, y], (125, 255, 127))
        pic = pic.resize((len(array[0]) * 10, len(array) * 10), Image.NEAREST)
        pic.save(file)
        return file

    def array2maze(self, array, wall_ori=0, path_ori=1, begin_ori=7, dst_ori=8,
                   wall="#", path=" ", dst="D", begin="*"):
        out = []
        for i in range(len(array)):
            row = ""
            for j in range(len(array[0])):
                if array[i][j] == wall_ori:
                    row += wall
                elif array[i][j] == path_ori:
                    row += path
                elif array[i][j] == begin_ori:
                    row += begin
                elif array[i][j] == dst_ori:
                    row += dst
                else:
                    row += "?"
            out.append(row)
        return "\n".join(out)

    def make_maze(self, width=11, height=11, wall=0, path=1, dst=8, begin=7, debug=False):
        assert width >= 5 and height >= 5, "宽高必须大于 5"
        width = (width // 2) * 2 + 1
        height = (height // 2) * 2 + 1
        start = [1, 1]
        destination = [height - 2, width - 2]
        matrix = [[-1] * width for _ in range(height)]

        def check(row, col):
            temp_sum = 0
            for d in [[0, 1], [0, -1], [1, 0], [-1, 0]]:
                temp_sum += matrix[row + d[0]][col + d[1]]
            return temp_sum < -3

        queue = []
        # 修正原版越界: 随机奇数行/列必须落在 1..height-2 / 1..width-2
        row = (random.randint(0, height - 2) // 2) * 2 + 1
        col = (random.randint(0, width - 2) // 2) * 2 + 1
        queue.append((row, col, -1, -1))
        while queue:
            row, col, r_, c_ = queue.pop(random.randint(0, len(queue) - 1))
            if check(row, col):
                matrix[row][col] = 0
                if r_ != -1 and row == r_:
                    matrix[row][min(col, c_) + 1] = 0
                elif r_ != -1 and col == c_:
                    matrix[min(row, r_) + 1][col] = 0
                for d in [[0, 2], [0, -2], [2, 0], [-2, 0]]:
                    row_, col_ = row + d[0], col + d[1]
                    if 0 < row_ < height - 1 and 0 < col_ < width - 1 and matrix[row_][col_] == -1:
                        queue.append((row_, col_, row, col))
        matrix[start[0]][start[1]] = 7
        matrix[destination[0]][destination[1]] = 8
        new_array = []
        for yline in matrix:
            tmp = []
            for x in yline:
                if x == 0:
                    tmp.append(path)
                elif x == -1:
                    tmp.append(wall)
                elif x == 7:
                    tmp.append(begin)
                elif x == 8:
                    tmp.append(dst)
            new_array.append(tmp)
        if debug:
            print(self.array2maze(new_array, wall, path, begin, dst))
        return new_array

    # ---------- 内部机制 ----------
    def save_pic(self, file="save_pic.png"):
        from PIL import Image
        min_x, min_y = len(self.array[0]), len(self.array)
        max_x = max_y = 0
        for y in range(len(self.array)):
            for x in range(len(self.array[0])):
                if self.array[y][x] != 9:
                    max_x = max(max_x, x)
                    min_x = min(min_x, x)
                    max_y = max(max_y, y)
                    min_y = min(min_y, y)
        if max_x < min_x or max_y < min_y:
            return
        pic = Image.new("RGB", (max_x - min_x + 1, max_y - min_y + 1))
        for y in range(min_y, max_y + 1):
            for x in range(min_x, max_x + 1):
                v = self.array[y][x]
                if v == 1:
                    pic.putpixel([x - min_x, y - min_y], (255, 255, 255))
                elif v == 0:
                    pic.putpixel([x - min_x, y - min_y], (0, 0, 0))
                elif v == 8:
                    pic.putpixel([x - min_x, y - min_y], (0, 255, 127))
                elif v == 7:
                    pic.putpixel([x - min_x, y - min_y], (255, 0, 0))
        for steps, color in ((self.min_output, (0, 255, 127)), (self.output, (255, 0, 0))):
            x, y = self.begin_x - min_x, self.begin_y - min_y
            pic.putpixel([x, y], color)
            for step in steps:
                if step == self.move["right"]:
                    x += 1
                elif step == self.move["down"]:
                    y += 1
                elif step == self.move["left"]:
                    x -= 1
                elif step == self.move["up"]:
                    y -= 1
                pic.putpixel([x, y], color)
        pic.save(file)

    def resize_array(self):
        if self.now_x in (0, self.x_size - 1) or self.now_y in (0, self.y_size - 1):
            old_begin_x, old_begin_y = self.begin_x, self.begin_y
            self.x_size *= 4
            self.y_size *= 4
            array_new = [[9] * self.x_size for _ in range(self.y_size)]
            self.begin_x = _int_div(self.x_size, 4)
            self.begin_y = _int_div(self.y_size, 4)
            self.now_x = self.begin_x + self.now_x - old_begin_x
            self.now_y = self.begin_y + self.now_y - old_begin_y
            self.next_x = self.begin_x + self.next_x - old_begin_x
            self.next_y = self.begin_y + self.next_y - old_begin_y
            for y, y_list in enumerate(self.array):
                for x, value in enumerate(y_list):
                    array_new[self.begin_y + y - old_begin_y][self.begin_x + x - old_begin_x] = value
            self.array = array_new
            for num in range(len(self.forks)):
                self.forks[num]["next_position"] = [
                    self.forks[num]["next_position"][0] + self.begin_x - old_begin_x,
                    self.forks[num]["next_position"][1] + self.begin_y - old_begin_y]
                self.forks[num]["before_position"] = [
                    self.forks[num]["before_position"][0] + self.begin_x - old_begin_x,
                    self.forks[num]["before_position"][1] + self.begin_y - old_begin_y]

    def get_point_round(self):
        if self.mode == "all":
            self.resize_array()
            if self.array[self.now_y + 1][self.now_x] == 9:
                self.next_x, self.next_y = self.now_x, self.now_y + 1
                self.next_output = [self.move["down"]]
                self.output = self.now_output + self.next_output
            elif self.array[self.now_y][self.now_x + 1] == 9:
                self.next_x, self.next_y = self.now_x + 1, self.now_y
                self.next_output = [self.move["right"]]
                self.output = self.now_output + self.next_output
            elif self.array[self.now_y][self.now_x - 1] == 9:
                self.next_x, self.next_y = self.now_x - 1, self.now_y
                self.next_output = [self.move["left"]]
                self.output = self.now_output + self.next_output
            elif self.array[self.now_y - 1][self.now_x] == 9:
                self.next_x, self.next_y = self.now_x, self.now_y - 1
                self.next_output = [self.move["up"]]
                self.output = self.now_output + self.next_output
            else:
                self.point_finish = 1

    def set_point(self, value=0):
        if self.mode == "right":
            # 右手法则: value 传 {"up":0/1/8, "down":..., "left":..., "right":...}
            self.resize_array()
            if isinstance(value, dict):
                self.round = value
            self.array[self.now_y - 1][self.now_x] = self.round.get("up", 0)
            self.array[self.now_y + 1][self.now_x] = self.round.get("down", 0)
            self.array[self.now_y][self.now_x - 1] = self.round.get("left", 0)
            self.array[self.now_y][self.now_x + 1] = self.round.get("right", 0)
            for exit_dir in self.exits:
                v = self.round.get(exit_dir, 0)
                if v == 8:
                    self.all_finish = 1
                if v >= 1 and not self.all_finish:
                    if exit_dir == "left":
                        self.now_x -= 1
                    elif exit_dir == "right":
                        self.now_x += 1
                    elif exit_dir == "down":
                        self.now_y += 1
                    elif exit_dir == "up":
                        self.now_y -= 1
                    self.output = self.move[exit_dir]
                    self.exits = self.directions[exit_dir]
                    break
            self.counter += 1
            if self.pic_debug and self.counter >= self.pic_counter:
                self.save_pic()
                self.counter = 0
            return
        if value == 0:
            self.array[self.next_y][self.next_x] = 0
        elif value == 1:
            self.array[self.next_y][self.next_x] = 1
            self.next_exit.append({"next_position": [self.next_x, self.next_y],
                                   "before_position": [self.now_x, self.now_y],
                                   "output": self.output})
        elif value == 8:
            self.array[self.next_y][self.next_x] = 8
            self.min_output = self.output
            self.all_output = self.output
            self.dst_finish = 1
            if self.scan_mode == "dst":
                self.all_finish = 1
            if self.pic_debug:
                self.save_pic()
        self.counter += 1
        if self.counter >= self.pic_counter:
            if self.pic_debug:
                self.save_pic()
            self.counter = 1

    def next_step(self):
        if self.mode == "right":
            opp = {self.move["right"]: self.move["left"],
                   self.move["left"]: self.move["right"],
                   self.move["up"]: self.move["down"],
                   self.move["down"]: self.move["up"]}
            back = opp.get(self.output, self.output)
            if self.min_output and back == self.min_output[-1]:
                self.min_output.pop(-1)     # 回溯: 弹出栈顶
            else:
                self.min_output.append(self.output)
            self.all_output.append(self.output)
            return self.output
        while True:
            self.get_point_round()
            if self.point_finish == 0:
                return self.output
            if len(self.next_exit) >= 2:
                for nxt in self.next_exit[1:]:
                    self.forks.append(nxt)
            elif len(self.next_exit) == 0:
                if not self.forks:
                    self.all_finish = 1
                    return self.output
                self.next_exit.append(self.forks.pop(-1))
            self.now_x = self.next_exit[0]["next_position"][0]
            self.now_y = self.next_exit[0]["next_position"][1]
            self.now_output = self.next_exit[0]["output"]
            self.next_exit = []
            self.point_finish = 0

    # ---------- 一键求解 ----------
    def array2solve(self, array, wall=0, path=1, begin=7, dst=8,
                    move=None, max_steps=1000000):
        """对已知二维数组迷宫求解, 返回 (起点→终点最短路径, 全遍历路径)。"""
        if move is None:
            move = {"up": "u", "down": "d", "left": "l", "right": "r"}
        robot = Robot(move=move, scan_mode="dst", pic_debug=False)
        begin_x = begin_y = end_x = end_y = -1
        for y in range(len(array)):
            for x in range(len(array[0])):
                if array[y][x] == dst:
                    end_x, end_y = x, y
                elif array[y][x] == begin:
                    begin_x, begin_y = x, y
        if min(begin_x, begin_y, end_x, end_y) < 0:
            raise ValueError("未在数组中找到起点/终点标记")
        steps = 0
        while not robot.all_finish and steps < max_steps:
            seq = robot.next_step()
            x, y = begin_x, begin_y
            for ch in seq:
                if ch == move["right"]:
                    x += 1
                elif ch == move["down"]:
                    y += 1
                elif ch == move["left"]:
                    x -= 1
                elif ch == move["up"]:
                    y -= 1
            if x < 0 or y < 0 or y >= len(array) or x >= len(array[0]) \
                    or array[y][x] == wall:
                robot.set_point(0)
            elif array[y][x] == dst:
                robot.set_point(8)
            else:
                robot.set_point(1)
            steps += 1
        if not robot.all_finish:
            raise ValueError("遍历超限仍未找到终点")
        return robot.min_output, robot.all_output


# ---------- CLI ----------
def _parse_xy(s, size=None):
    """解析 'X,Y' 坐标; 负数表示从末尾倒数, 需传 size=(宽, 高) 转为正坐标。"""
    x, y = s.split(",")
    x, y = int(x), int(y)
    if size:
        w, h = size
        if x < 0:
            x += w
        if y < 0:
            y += h
    return x, y


def _join_neg_args(argv):
    """argparse 的负数判定只认纯数字, '-2,-2' 会被当成选项报
    'expected one argument'; 统一改写成 --start=.../--end=... 形式规避。"""
    out, i = [], 0
    while i < len(argv):
        if argv[i] in ("--start", "--end") and i + 1 < len(argv):
            out.append("%s=%s" % (argv[i], argv[i + 1]))
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return out


def _solve_from_text(text, move_map, wall, path, begin, dst, start, end):
    r = Robot()
    array = r.str2array(text)
    h, w = len(array), len(array[0])
    begin_x = begin_y = end_x = end_y = -1
    for y in range(h):
        for x in range(w):
            if array[y][x] == dst:
                end_x, end_y = x, y
            elif array[y][x] == begin:
                begin_x, begin_y = x, y
    if start:
        begin_x, begin_y = _parse_xy(start, (w, h))
        array[begin_y][begin_x] = begin
    if end:
        end_x, end_y = _parse_xy(end, (w, h))
        array[end_y][end_x] = dst
    if not (0 <= begin_x < w and 0 <= begin_y < h and 0 <= end_x < w and 0 <= end_y < h):
        raise ValueError("起点/终点坐标越界或未找到, 请用 --start/--end 指定(支持负数倒数)")
    print("迷宫尺寸: %dx%d, 起点(%d,%d) 终点(%d,%d)"
          % (w, h, begin_x, begin_y, end_x, end_y))
    min_path, all_path = r.array2solve(array, wall=wall, path=path,
                                       begin=begin, dst=dst, move=move_map)
    return min_path, all_path


def main():
    ap = argparse.ArgumentParser(description="robot_maze 迷宫求解(py3)")
    ap.add_argument("--solve", metavar="TXT", help="求解文本迷宫")
    ap.add_argument("--pic", metavar="PNG", help="求解图片迷宫(需 --start/--end)")
    ap.add_argument("--start", metavar="X,Y", help="起点坐标(如 1,1)")
    ap.add_argument("--end", metavar="X,Y", help="终点坐标(如 -2,-2 表示倒数)")
    ap.add_argument("--gen", type=int, metavar="SIZE", help="生成 SIZE x SIZE 随机迷宫")
    ap.add_argument("--out", default="", help="生成输出文件")
    ap.add_argument("--picgen", action="store_true", help="--gen 时输出 PNG(需 --out)")
    ap.add_argument("--move", default="UDLR", help="输出方向字符, 默认 UDLR(上左下右顺序无关)")
    ap.add_argument("--wall", default="#", help="墙字符")
    ap.add_argument("--path", default=" ", help="路字符")
    ap.add_argument("--begin", default="*", help="起点字符")
    ap.add_argument("--dst", default="D", help="终点字符")
    ap.add_argument("--selftest", action="store_true", help="内置自测")
    args = ap.parse_args(_join_neg_args(sys.argv[1:]))

    move_map = {"up": args.move[0], "down": args.move[1],
                "left": args.move[2], "right": args.move[3]}

    if args.selftest:
        r = Robot()
        ok = True
        for size in (11, 21, 31):
            array = r.make_maze(size, size)          # 数字迷宫 0墙 1路 7起 8终
            min_path, all_path = r.array2solve(array)
            # 走一遍最短路径验证: 不到墙外、每步是通道、终点到达
            x = y = 1
            good = array[1][1] == 7
            for ch in min_path:
                if ch == "u":
                    y -= 1
                elif ch == "d":
                    y += 1
                elif ch == "l":
                    x -= 1
                elif ch == "r":
                    x += 1
                if array[y][x] in (0,):
                    good = False
                    break
            good = good and array[y][x] == 8
            ok &= good
            print(f"[{'OK' if good else 'FAIL'}] {size}x{size} 最短路 {len(min_path)} 步到达终点")
        # 字符迷宫
        text = r.array2maze(array, 0, 1, 7, 8, wall="#", path=" ", dst="D", begin="*")
        min2, _ = _solve_from_text(text, move_map, "#", " ", "*", "D", None, None)
        good = len(min2) == len(min_path)
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 字符迷宫求解步数一致({len(min2)})")
        # 图片迷宫往返: 生成 PNG -> pic2array 识别 -> 再求解
        import tempfile
        png = os.path.join(tempfile.gettempdir(), "robot_maze_selftest.png")
        r.array2pic(array, 0, 1, 8, 7, png)
        parsed = r.pic2array(png, wall=0, path=1)
        good = len(parsed) == len(array) and len(parsed[0]) == len(array[0])
        if good:
            for y in range(len(array)):
                for x in range(len(array[0])):
                    if array[y][x] == 7:   # 起点红像素二值化后是黑, 识别为墙属正常
                        continue
                    if parsed[y][x] != (1 if array[y][x] in (1, 8) else 0):
                        good = False
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 图片迷宫识别内容一致({len(parsed[0])}x{len(parsed)})")
        parsed[1][1] = 7
        parsed[len(parsed) - 2][len(parsed[0]) - 2] = 8
        min3, _ = r.array2solve(parsed)
        good = len(min3) == len(min_path)
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 图片迷宫求解步数一致({len(min3)})")
        sys.exit(0 if ok else 1)

    if args.gen:
        r = Robot()
        array = r.make_maze(args.gen, args.gen)
        if args.picgen:
            if not args.out:
                ap.error("--picgen 需要 --out 指定 PNG 路径")
            r.array2pic(array, 0, 1, 8, 7, args.out)
            print("已生成:", args.out)
        else:
            out = args.out or "maze.txt"
            with open(out, "w", encoding="utf-8") as f:
                f.write(r.array2maze(array, 0, 1, 7, 8,
                                     wall="#", path=" ", dst="D", begin="*") + "\n")
            print("已生成:", out)
        return

    if args.pic:
        from PIL import Image
        r = Robot()
        img = Image.open(args.pic)
        array = r.pic2array(args.pic, wall=0, path=1)
        w, h = len(array[0]), len(array)
        print("识别迷宫尺寸: %dx%d" % (w, h))
        sx, sy = _parse_xy(args.start or "1,1", (w, h))
        ex, ey = _parse_xy(args.end or f"{w - 2},{h - 2}", (w, h))
        if not (0 <= sx < w and 0 <= sy < h and 0 <= ex < w and 0 <= ey < h):
            ap.error("起点/终点坐标越界: (%d,%d)-(%d,%d), 迷宫尺寸 %dx%d"
                     % (sx, sy, ex, ey, w, h))
        array[sy][sx] = 7
        array[ey][ex] = 8
        min_path, _ = r.array2solve(array)
        print("最短路径(%d 步): %s" % (len(min_path), "".join(min_path)))
        return

    if args.solve:
        with open(args.solve, "r", encoding="utf-8") as f:
            text = f.read()
        min_path, all_path = _solve_from_text(
            text, move_map, args.wall, args.path, args.begin, args.dst,
            args.start, args.end)
        print("最短路径(%d 步): %s" % (len(min_path), "".join(min_path)))
        return

    ap.print_help()


if __name__ == "__main__":
    main()
