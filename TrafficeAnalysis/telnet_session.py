# -*- coding: utf-8 -*-
"""
telnet_session.py — Telnet 流量还原(题型:telnet 明文口令/命令找flag)

思路:telnet(23)是明文协议,但流量里混着 IAC 协商字节(0xFF 开头的
3字节序列),直接 follow tcp stream 会看到 ^FF^FA... 噪声。
脚本剥离 IAC 序列后按包序交错还原"服务端提示 / 客户端输入",
并把 login:/Password: 提示词与下一次客户端输入配对成凭据。

用法: python telnet_session.py <pcap>
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

TELNET_PORT = 23


def strip_iac(data):
    """剥离 telnet IAC(255)协商序列。"""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b == 0xFF:                      # IAC
            if i + 1 >= n:
                break
            cmd = data[i + 1]
            if cmd in (0xFB, 0xFC, 0xFD, 0xFE):   # WILL/WONT/DO/DONT + 选项
                i += 3
            elif cmd == 0xFA:                     # SB ... IAC SE
                j = data.find(b'\xff\xf0', i)
                i = n if j < 0 else j + 2
            elif cmd == 0xFF:                     # 转义的 0xFF
                out.append(0xFF)
                i += 2
            else:
                i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


def analyze(path):
    """返回 [(会话号, 交错文本, 凭据列表)]"""
    lt, pkts = pcaplib.read_pcap(path)
    sessions = []
    for i, st in enumerate(pcaplib.build_streams(pkts, lt)):
        if TELNET_PORT not in (st.client[1], st.server[1]):
            continue
        cip = st.client
        # 按包序交错: '> ' 客户端输入, '< ' 服务端输出
        lines = []           # (方向, 文本)
        for (src, _dst, _seq, _fl, payload, ts, idx) in st.packets:
            if not payload:
                continue
            txt = pcaplib.printable(strip_iac(payload), keep_newline=True)
            if not txt.strip():
                continue
            lines.append(('>' if src == cip else '<', txt))
        # 凭据配对:服务端出现 xxx: 提示词后的第一个客户端输入
        creds = []
        pending = None
        for d, txt in lines:
            if d == '<':
                for m in re.finditer(r'(?:login|user(?:name)?|account)\s*:\s*$',
                                     txt.strip(), re.I):
                    pending = ('user', m.group(0).strip())
                for m in re.finditer(r'password\s*:\s*$', txt.strip(), re.I):
                    pending = ('pass', m.group(0).strip())
            else:
                val = txt.replace('\r', '').replace('\n', '').strip()
                if pending and val:
                    creds.append((pending[0], val))
                    pending = None
        text = ''.join(('%s%s' % (d, t)) for d, t in lines)
        sessions.append((i, text, creds))
    return sessions


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else default_sample()
    if not path or not os.path.exists(path):
        print('用法: python telnet_session.py <pcap>')
        sys.exit(1)
    print('[*] 分析 %s' % path)
    sessions = analyze(path)
    if not sessions:
        print('[-] 未发现 telnet(23端口)会话')
        return
    all_creds = []
    for i, text, creds in sessions:
        print('==== Telnet 会话 #%d ====' % (i + 1))
        print(pcaplib.shorten(text, 3000))
        print()
        for kind, v in creds:
            print('    [凭据] %s = %s' % (kind, v))
        all_creds += creds
    flags = set()
    for i, text, _creds in sessions:
        flags |= set(pcaplib.find_flags(text))
    if all_creds:
        print('[+] 答案(凭据线索):')
        for kind, v in all_creds:
            print('    %s = %s' % (kind, v))
    for f in flags:
        print('[+] 答案(flag): %s' % f)


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, 'samples/telnet.pcap')
    return p if os.path.exists(p) else None


if __name__ == '__main__':
    main()
