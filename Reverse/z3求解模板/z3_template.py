# -*- coding: utf-8 -*-
"""z3 约束求解 CTF 模板(补充题型: Reverse)

用途:
    逆向题把算法逆不出时, 把校验逻辑翻译成 z3 约束, 直接解出 flag。
    模板给出三种最常见模式:
      A. Int 方程组   (明文运算校验)
      B. BitVec 逐字节校验 (常见 x[i] ^ K[i] == enc[i], 带前缀已知)
      C. 带顺序约束的排列/等式 (sum/取模校验)

依赖:
    pip install z3-solver

用法:
    python z3_template.py                 # 跑三种模式的内置示例
实战:
    把示例中的常数/数组换成题目数据, 改约束即可。
"""
import sys

try:
    from z3 import (BitVec, Int, Solver, sat, Sum, Or)
except ImportError:
    print('缺少依赖: pip install z3-solver')
    sys.exit(2)


def demo_int_system():
    """A. Int 方程组: x + y = 10, x * y = 21 -> x=3, y=7"""
    x, y = Int('x'), Int('y')
    s = Solver()
    s.add(x + y == 10, x * y == 21, x > 0, y > 0)
    assert s.check() == sat
    m = s.model()
    return m[x], m[y]


def demo_bitvec_xor(target=bytes([0x3c, 0x36, 0x3b, 0x3d]), prefix=b'flag'):
    """B. BitVec 逐字节: 已知密文(=明文xor 0x5a)与部分明文前缀, 求整段明文。"""
    n = len(target)
    flag = [BitVec(f'b{i}', 8) for i in range(n)]
    s = Solver()
    for i, c in enumerate(prefix):        # 已知前缀约束
        s.add(flag[i] == c)
    for i in range(n):                    # 每字节 xor 0x5a 后等于密文
        s.add(flag[i] ^ 0x5a == target[i])
    # 限定可打印, 缩小解空间
    for f in flag:
        s.add(Or(*[f == c for c in range(0x20, 0x7f)]))
    assert s.check() == sat
    m = s.model()
    return bytes(m[f].as_long() for f in flag)


def demo_sum_mod():
    """C. 求和/取模: 四个字节 sum==300, 每 byte < 100, 首字节是 'G'"""
    b = [Int(f'k{i}') for i in range(4)]
    s = Solver()
    s.add(Sum(b) == 300)
    for v in b:
        s.add(v >= 32, v <= 126)
    s.add(b[0] == ord('G'))
    assert s.check() == sat
    m = s.model()
    return ''.join(chr(m[v].as_long()) for v in b)


def main():
    ok = True
    x, y = demo_int_system()
    # 约束对 (3,7)/(7,3) 对称, z3 返回哪个解无保证, 用集合比较
    good = {x.as_long(), y.as_long()} == {3, 7}
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] Int 方程组: x={x}, y={y}")

    flag = demo_bitvec_xor()
    good = all(flag[i] == c for i, c in enumerate(b'flag'))
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] BitVec XOR: {flag!r} (前缀校验通过)")

    out = demo_sum_mod()
    good = sum(map(ord, out)) == 300 and out[0] == 'G'
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] Sum/Mod: {out!r} sum={sum(map(ord, out))}")
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
