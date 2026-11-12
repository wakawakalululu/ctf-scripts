# -*- coding: utf-8 -*-
"""angr 符号执行 CTF 模板(补充题型: Reverse)

题型特征:
    题目校验一大串 if/else 或循环比较, 手逆费劲; angr 从 main 跑符号执行,
    指定 "成功分支(find)" 与 "失败分支(avoid)", 自动解出输入。

依赖:
    pip install angr   (建议 Linux/WSL; Windows 建议用 WSL 或 Docker)

用法:
    把路径/地址改成题目二进制的实际值后:
    python angr_template.py ./crackme          # 本地运行模板
    python angr_template.py --demo             # 不装 angr 也能看模板说明
"""
import sys

START_ADDR = None           # 如 0x401234; None 表示从 main 自动开始
FIND_ADDR = 0x4012A0        # ← "Correct!" 分支地址
AVOID_ADDR = 0x401280       # ← "Wrong!" 分支地址
FLAG_LEN = 16               # ← flag 长度(决定符号变量位宽)


def solve(binary_path: str) -> str:
    import angr
    import claripy

    proj = angr.Project(binary_path, auto_load_libs=False)
    flag = claripy.BVS('flag', FLAG_LEN * 8)

    state = proj.factory.entry_state(
        stdin=flag,
        args=[binary_path],
        add_options=angr.options.unicorn,
    )
    sim = proj.factory.simulation_manager(state)
    sim.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    if sim.found:
        found = sim.found[0]
        data = found.solver.eval(flag, cast_to=bytes)
        return data.rstrip(b'\x00').decode(errors='replace')
    raise RuntimeError('未找到满足 find 分支的解, 调整 find/avoid 或加大 timeout')


def main():
    if '--demo' in sys.argv or len(sys.argv) == 1:
        print(__doc__)
        print('--- 模板要点 ---')
        print('1. find/avoid 地址来自 objdump -d 或 IDA (成功/失败分支)')
        print('2. entry_state(stdin=符号变量) 适合 scanf 读输入的题')
        print('3. 若输入从 argv 来: args=[b_path, flag]')
        print('4. 探索太慢: 先 s.active 查看状态, 用 expl.stash["found"] 交互')
        print('5. 内存范围太大时: 探索前 state.solver.add(约束缩小范围)')
        return
    # 运行模式: sys.argv[1] = 目标 ELF (上面的分支已处理完 --demo/无参, 此处必达)
    try:
        import angr  # noqa: F401
    except ImportError:
        print('未安装 angr: pip install angr (建议 WSL/Linux)')
        sys.exit(2)
    print('解得:', solve(sys.argv[1]))


if __name__ == '__main__':
    main()
