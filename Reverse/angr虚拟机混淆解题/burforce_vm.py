# -*- coding: utf-8 -*-
"""burforce_vm angr 爆破虚拟机混淆题目

来源: https://github.com/SourceLizi/ctf-toolbox (完善: 地址参数化、stdin/stdout dump)
用途: VM 混淆类 pwn/reverse 题——手逆 VM 解释器成本高时, 让 angr 直接探索到成功分支。

依赖:
    pip install angr   (建议 Linux/WSL)

用法:
    python burforce_vm.py ./SimpleVM --find 0x080488BB --avoid 0x08048907,0x080486E1
    python burforce_vm.py ./crackme64 --find 0x401234 --stdin          # 解出的输入写入 stdin 文件
    成功分支/失败分支地址来自 IDA 或 objdump -d。
"""
import argparse
import sys


def solve(binary, find, avoid, dump_stdin=None):
    import angr
    p = angr.Project(binary, auto_load_libs=False)
    st = p.factory.entry_state()
    sm = p.factory.simulation_manager(st)
    sm.explore(find=find, avoid=list(avoid) if avoid else None)
    if not sm.found:
        raise RuntimeError('未找到 find 分支, 检查地址或改用 angr求解模板/ 的 stdin 注入方式')
    flag = sm.found[0].posix.dumps(0)          # stdin
    out = sm.found[0].posix.dumps(1)           # stdout
    if dump_stdin:
        with open(dump_stdin, 'wb') as f:
            f.write(flag)
        print('输入已写入:', dump_stdin)
    return flag, out


def _fix_neg(argv):
    """argparse 只认纯数字为负数, '-0x123'/'-0x1,-0x2' 会被当选项报
    'expected one argument'; 统一改写成 --find=... 形式(同 robot_maze 的修法)。"""
    out, i = [], 0
    while i < len(argv):
        if argv[i] in ('--find', '--avoid') and i + 1 < len(argv):
            out.append('%s=%s' % (argv[i], argv[i + 1]))
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return out


def main():
    ap = argparse.ArgumentParser(description='angr VM 混淆爆破')
    ap.add_argument('binary', help='目标 ELF')
    ap.add_argument('--find', required=True, type=lambda s: int(s, 0), help='成功分支地址')
    ap.add_argument('--avoid', default='', help='失败分支地址, 逗号分隔')
    ap.add_argument('--stdin', metavar='FILE', help='把解出的输入保存到文件')
    args = ap.parse_args(_fix_neg(sys.argv[1:]))
    avoid = [int(x, 0) for x in args.avoid.split(',') if x.strip()]
    try:
        import angr  # noqa: F401
    except ImportError:
        print('缺少依赖: pip install angr (建议 WSL/Linux)')
        sys.exit(2)
    flag, out = solve(args.binary, args.find, avoid, args.stdin)
    print('flag/stdin :', flag)
    print('stdout     :', out)


if __name__ == '__main__':
    main()
