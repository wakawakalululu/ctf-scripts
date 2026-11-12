# -*- coding: utf-8 -*-
"""arm_dbg 基于 unicorn 的 ARM 模拟调试器

来源: https://github.com/SourceLizi/ctf-toolbox (完善: 移除 hexdump 依赖、demo 改为 --demo)
用途: 不限平台的 ARM 二进制/固件片段模拟调试(THUMB 变量处放入待调试代码)。

依赖:
    pip install unicorn capstone

用法:
    python arm_dbg.py --demo     # 运行内置 Thumb 示例并进入调试器
    实战: 修改文件底部 main() 中 THUMB 变量与内存映射后运行 python arm_dbg.py

调试命令(交互界面内):
    set reg <reg> <value>     写寄存器        set bpt <addr>     下断点
    s                         单步            n                  跳过子函数
    r                         运行到断点      dump <addr> <size> 查看内存
    list bpt / del bpt <addr> 断点管理        stop               退出
    a / t                     ARM/THUMB 反汇编切换            f  显示最近指令流
"""
import sys

try:
    from unicorn import *
    from unicorn import arm_const
    from unicorn.arm_const import *
    import capstone as cp
except ImportError:
    print('缺少依赖: pip install unicorn capstone')
    sys.exit(2)

BPT_EXECUTE = 1
BPT_MEMREAD = 2
UDBG_MODE_ALL = 1
UDBG_MODE_FAST = 2

REG_ARM = {arm_const.UC_ARM_REG_R0: "R0",
           arm_const.UC_ARM_REG_R1: "R1",
           arm_const.UC_ARM_REG_R2: "R2",
           arm_const.UC_ARM_REG_R3: "R3",
           arm_const.UC_ARM_REG_R4: "R4",
           arm_const.UC_ARM_REG_R5: "R5",
           arm_const.UC_ARM_REG_R6: "R6",
           arm_const.UC_ARM_REG_R7: "R7",
           arm_const.UC_ARM_REG_R8: "R8",
           arm_const.UC_ARM_REG_R9: "R9",
           arm_const.UC_ARM_REG_R10: "R10",
           arm_const.UC_ARM_REG_R11: "R11",
           arm_const.UC_ARM_REG_R12: "R12",
           arm_const.UC_ARM_REG_R13: "R13",
           arm_const.UC_ARM_REG_R14: "R14",
           arm_const.UC_ARM_REG_R15: "R15",
           arm_const.UC_ARM_REG_PC: "PC",
           arm_const.UC_ARM_REG_SP: "SP",
           arm_const.UC_ARM_REG_LR: "LR"
           }

REG_TABLE = {UC_ARCH_ARM: REG_ARM}


def str2int(s):
    if s.startswith('0x') or s.startswith("0X"):
        return int(s[2:], 16)
    return int(s)


def advance_dump(data, base):
    """自实现 hexdump(替代原版 hexdump 库依赖)。"""
    retstr = ''
    for addr in range(0, len(data), 16):
        d = data[addr:addr + 16]
        line = '%08X: ' % (base + addr)
        dumpstr = ' '.join('%02X' % c for c in d)
        line += dumpstr[:8 * 3]
        if len(d) > 8:
            line += ' ' + dumpstr[8 * 3:]
        pad = 2
        if len(d) < 16:
            pad += 3 * (16 - len(d))
        if len(d) <= 8:
            pad += 1
        line += ' ' * pad
        for byte in d:
            line += chr(byte) if 0x20 <= byte <= 0x7E else '.'
        retstr += line + '\n'
    return retstr


def _dbg_trace(mu, address, size, self):
    self._tracks.append(address)
    if not self._is_step and self._tmp_bpt == 0:
        if address not in self._list_bpt:
            return
    if self._tmp_bpt != address and self._tmp_bpt != 0:
        return
    return _dbg_trace_internal(mu, address, size, self)


def _dbg_memory(mu, access, address, length, value, self):
    pc = mu.reg_read(arm_const.UC_ARM_REG_PC)
    print("memory error: pc: %x access: %x address: %x length: %x value: %x" %
          (pc, access, address, length, value))
    _dbg_trace_internal(mu, pc, 4, self)
    mu.emu_stop()
    return True


def _dbg_trace_internal(mu, address, size, self):
    self._is_step = False
    print("======================= Registers =======================")
    self.dump_reg()
    print("======================= Disassembly =====================")
    self.dump_asm(address, size * self.dis_count)

    while True:
        raw_command = input(">")
        if raw_command == '':
            raw_command = self._last_command
        self._last_command = raw_command
        command = [c for c in raw_command.split(" ") if c != ""]
        try:
            if command[0] == 'set':
                if command[1] == 'reg':
                    self.write_reg(command[2], str2int(command[3]))
                elif command[1] == 'bpt':
                    self.add_bpt(str2int(command[2]))
                else:
                    print("[Debugger Error]command error see help.")
            elif command[0] in ('s', 'step'):
                self._tmp_bpt = 0
                self._is_step = True
                break
            elif command[0] in ('n', 'next'):
                self._tmp_bpt = address + size
                self._is_step = False
                break
            elif command[0] in ('r', 'run'):
                self._tmp_bpt = 0
                self._is_step = False
                break
            elif command[0] == 'dump':
                nsize = str2int(command[2]) if len(command) >= 3 else 4 * 16
                self.dump_mem(str2int(command[1]), nsize)
            elif command[0] == 'list' and command[1] == 'bpt':
                self.list_bpt()
            elif command[0] == 'del' and command[1] == 'bpt':
                self.del_bpt(str2int(command[2]))
            elif command[0] == 'stop':
                sys.exit(0)
            elif command[0] == 't':
                self._capstone = self._capstone_thumb
                self.dump_asm(address, size * self.dis_count)
            elif command[0] == 'a':
                self._capstone = self._capstone_arm
                self.dump_asm(address, size * self.dis_count)
            elif command[0] == 'f':
                print(" == recent ==")
                for i in self._tracks[-10:-1]:
                    print(self.sym_handler(i))
            else:
                print("Command Not Found!")
        except (IndexError, ValueError):
            print("[Debugger Error]command error see help.")


class UnicornDebugger:
    def __init__(self, mu, mode=UDBG_MODE_ALL):
        self._tracks = []
        self._mu = mu
        self._arch = mu._arch
        self._mode = mu._mode
        self._list_bpt = []
        self._tmp_bpt = 0
        self._error = ''
        self._last_command = ''
        self.dis_count = 5
        self._is_step = False
        self.sym_handler = self._default_sym_handler
        self._capstone_arm = None
        self._capstone_thumb = None

        if self._arch != UC_ARCH_ARM:
            mu.emu_stop()
            raise RuntimeError("arch:%d is not supported! " % self._arch)

        self._capstone_thumb = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_THUMB)
        self._capstone_arm = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_ARM)
        self._capstone = self._capstone_thumb

        if mode == UDBG_MODE_ALL:
            mu.hook_add(UC_HOOK_CODE, _dbg_trace, self)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, _dbg_memory, self)
        mu.hook_add(UC_HOOK_MEM_FETCH_PROT, _dbg_memory, self)
        self._regs = REG_TABLE[self._arch]

    def dump_mem(self, addr, size):
        data = self._mu.mem_read(addr, size)
        print(advance_dump(data, addr))

    def dump_asm(self, addr, size):
        md = self._capstone
        code = self._mu.mem_read(addr, size)
        count = 0
        for ins in md.disasm(code, addr):
            if count >= self.dis_count:
                break
            print("%s:\t%s\t%s" % (self.sym_handler(ins.address), ins.mnemonic, ins.op_str))
            count += 1

    def dump_reg(self):
        result_format = ''
        count = 0
        for rid in self._regs:
            rname = self._regs[rid]
            value = self._mu.reg_read(rid)
            if count < 4:
                result_format = result_format + '  ' + rname + '=' + hex(value)
                count += 1
            else:
                count = 0
                result_format += '\n' + rname + '=' + hex(value)
        print(result_format)

    def write_reg(self, reg_name, value):
        for rid in self._regs:
            rname = self._regs[rid]
            if rname == reg_name:
                self._mu.reg_write(rid, value)
                return
        print("[Debugger Error] Reg not found:%s " % reg_name)

    def list_bpt(self):
        for idx in range(len(self._list_bpt)):
            print("[%d] %s" % (idx, self.sym_handler(self._list_bpt[idx])))

    def add_bpt(self, addr):
        self._list_bpt.append(addr)

    def del_bpt(self, addr):
        self._list_bpt.remove(addr)

    def get_tracks(self):
        return self._tracks

    def set_symbol_name_handler(self, handler):
        self.sym_handler = handler

    def _default_sym_handler(self, address):
        return hex(address)


def run_demo():
    """内置 Thumb 示例: R1 = R2 + R0, R0=0x37, R2=0x6789, 预期 R1=0x67c0。"""
    # 原版字节是 ARM 编码(mov r0,#0x37 的 ARM 编码 0xE3A00037), 但 emu 用
    # UC_MODE_THUMB 按 16 位Thumb 解码成了一串垃圾指令; 换成真 Thumb 编码:
    # movs r0,#0x37 = 0x2037, adds r1,r2,r0 = 0x1811(0001100 rm rn rd)
    THUMB = b"\x37\x20\x11\x18"   # movs r0,#0x37 ; adds r1,r2,r0
    print("Emulate Thumb code")
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    ADDRESS = 0x10000
    mu.mem_map(ADDRESS, 2 * 0x100000)
    mu.mem_write(ADDRESS, THUMB)
    mu.reg_write(UC_ARM_REG_SP, 0x1234)
    mu.reg_write(UC_ARM_REG_R2, 0x6789)
    udbg = UnicornDebugger(mu)
    udbg.add_bpt(ADDRESS)
    # unicorn 2.x 忽略 UC_MODE_THUMB, 需要起始地址带 thumb 位(addr|1)才按 16 位解码;
    # 原版直接 emu_start(ADDRESS) 会按 ARM 指令解码, 条件码不满足全部被跳过
    mu.emu_start(ADDRESS | 1, ADDRESS + len(THUMB))
    print(">>> SP = 0x%x" % mu.reg_read(UC_ARM_REG_SP))
    print(">>> R1 = 0x%x" % mu.reg_read(UC_ARM_REG_R1))


if __name__ == '__main__':
    if '--demo' in sys.argv:
        run_demo()
    else:
        print(__doc__)
        print('将待调试代码写入 run_demo() 的 THUMB 变量后: python arm_dbg.py --demo')
