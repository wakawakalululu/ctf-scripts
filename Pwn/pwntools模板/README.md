# pwntools 解题模板

> 参考社区通用 exp 写法整理(Gallopsled/pwntools 文档与常见 CTF writeup 模板风格)。
> 两个模板覆盖 Pwn 新手赛最常见两类题; 其余题型(shellcode/canary 绕过/堆)在此思路上变体。

## 安装

```bash
pip install pwntools          # Linux/WSL 建议用 pwndbg + pwntools
```

Windows 下 pwntools 不支持 `process()`, 只能 `remote()` 打远程或用 WSL。

## 模板清单

| 文件 | 题型 | 关键点 |
|------|------|--------|
| [ret2libc_exp.py](ret2libc_exp.py) | 栈溢出 + 无后门(64位) | 两段式: 泄露 puts@got → 算 libc base → system("/bin/sh") |
| [fmtstr_exp.py](fmtstr_exp.py) | 格式化字符串 | FmtStr 测偏移; fmtstr_payload 任意写 GOT |
| [simple_template.py](simple_template.py) | 32 位简单栈溢出 | 最小骨架, 填 4 处标记即可打(来源 [SourceLizi/ctf-toolbox](https://github.com/SourceLizi/ctf-toolbox)) |
| [libc_leak_template.py](libc_leak_template.py) | 32 位 write 泄露 libc | write(1,got,4) 泄露 + DynELF 无 libc 备选(来源同上) |

## 常用武器链

```bash
checksec ./pwn                       # 保护: NX/PIE/Canary/RELRO
python -c "from pwn import *; print(cyclic(200, n=8))"   # 测 64 位偏移
cyclic -l 0x6161616161616200         # 由回显算 OFFSET
ROPgadget --binary pwn | grep "pop rdi"   # 64 位 gadget
one_gadget ./libc.so.6               # 一把梭后门
strings -tx libc.so.6 | grep "/bin/sh"
```

## 64 位栈对齐坑

`system` 内部 `movaps` 要求 16 字节对齐, 段错误时在 ROP 链里塞一个 `ret` gadget(见模板 `ret_gadget`)。
