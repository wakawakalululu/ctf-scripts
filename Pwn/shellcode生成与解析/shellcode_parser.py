# -*- coding: utf-8 -*-
r"""shellcode_parser 从 .s 源码汇编出 ELF 并提取 .text 中的 shellcode

来源: https://github.com/SourceLizi/ctf-toolbox (完善: 工具缺失时给出提示、修复 \\xNN 补零)
依赖: pwntools + 系统 nasm、ld (Linux/WSL)

用法:
    python shellcode_parser.py                    # 汇编当前目录 shellcode.s -> 提取 shellcode
    python shellcode_parser.py -s mysc.s          # 指定源文件(生成 mysc ELF)
    生成的 ELF 可直接 gdb 调试, 打印的 \xNN 串可直接放进 exp。
"""
import argparse
import os
import shutil
import subprocess
import sys


def str_to_hex(shellcode: bytes) -> str:
    return ''.join('\\x%02x' % c for c in shellcode)


def main():
    ap = argparse.ArgumentParser(description='shellcode.s -> ELF -> shellcode 提取')
    ap.add_argument('-s', '--src', default='shellcode.s', help='汇编源文件(默认 shellcode.s)')
    args = ap.parse_args()
    base = args.src[:-2] if args.src.endswith('.s') else args.src

    for tool in ('nasm', 'ld'):
        if shutil.which(tool) is None:
            print(f'缺少系统工具 {tool}: Linux/WSL 安装 sudo apt install nasm binutils')
            sys.exit(2)
    if not os.path.exists(args.src):
        print(f'源文件不存在: {args.src}')
        sys.exit(1)

    for cmd in (
        ['nasm', '-f', 'elf', args.src, '-o', base + '.o'],
        ['ld', '-m', 'elf_i386', '-o', base, base + '.o'],
    ):
        print('>>', ' '.join(cmd))
        r = subprocess.run(cmd)
        if r.returncode != 0:
            print('命令失败:', ' '.join(cmd))
            sys.exit(1)

    try:
        from pwn import ELF
    except ImportError:
        print('缺少依赖: pip install pwntools')
        sys.exit(2)
    elf = ELF(base, checksec=False)
    shellcode = elf.section('.text')
    print("Read shellcode from elf, len:%d" % len(shellcode))
    print(str_to_hex(shellcode))


if __name__ == '__main__':
    main()
