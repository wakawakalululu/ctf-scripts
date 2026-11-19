# -*- coding: utf-8 -*-
"""
solve.py — 一键流量分析:自动识别流量类型,调用对应脚本出解(总入口)

识别规则(按优先级):
  USB 链路层(usbmon/USBPcap)      -> usb_keyboard.py + usb_mouse.py
  HTTP 端口流量                    -> find_scanner / find_admin_url / find_login
                                     / find_webshell / extract_objects
  SMTP/POP3 端口流量               -> smtp_mail.py
  Telnet 端口流量                  -> telnet_session.py
  ICMP echo 流量(无其他常见端口)   -> icmp_data.py
  任意类型                         -> 全文 flag 正则 + base64 候选搜索

用法: python solve.py <pcap>
      python solve.py               # 默认分析 samples/ 下最新生成的包
"""
import os
import re
import sys
import base64
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

HERE = os.path.dirname(os.path.abspath(__file__))


def pick_script(kind, pcap):
    return {
        'usb': ['usb_keyboard.py', 'usb_mouse.py'],
        'web': ['find_scanner.py', 'find_admin_url.py', 'find_login.py',
                'find_webshell.py', 'extract_objects.py'],
        'mail': ['smtp_mail.py'],
        'telnet': ['telnet_session.py'],
        'icmp': ['icmp_data.py'],
    }.get(kind, [])


def icmp_strip(data, linktype):
    """链路层剥头(与 icmp_data.py 一致), 用于 ICMP 计数。"""
    if linktype == pcaplib.LINKTYPE_ETHERNET:
        return pcaplib.parse_ether(data)
    if linktype == pcaplib.LINKTYPE_NULL:
        import struct
        af = struct.unpack('<I', data[:4])[0] if len(data) >= 4 else 2
        return ('ipv4' if af in (2, 0x02000000) else 'ipv6'), data[4:]
    if linktype == pcaplib.LINKTYPE_RAW:
        return ('ipv4' if data and data[0] >> 4 == 4 else 'ipv6'), data
    if linktype == pcaplib.LINKTYPE_SLL:
        import struct
        if len(data) < 16:
            return None, b''
        et = struct.unpack('>H', data[14:16])[0]
        return {0x0800: 'ipv4', 0x86dd: 'ipv6'}.get(et), (data[16:] if et in (0x0800, 0x86dd) else b'')
    return None, b''


def detect(pcap):
    """返回 (流量类型, 说明)"""
    lt, pkts = pcaplib.read_pcap(pcap)
    if lt in (pcaplib.LINKTYPE_USB_LINUX, pcaplib.LINKTYPE_USBPCAP):
        return 'usb', '链路层=%s (USB)' % pcaplib.get_linktype_name(lt)
    # 端口统计
    ports = {}
    icmp_cnt = 0
    for p in pkts:
        # ICMP(proto=1) 不在 l4_packets(TCP/UDP) 统计里, 单独数
        nl, l4 = icmp_strip(p.data, lt)
        if nl == 'ipv4':
            ip = pcaplib.parse_ipv4(l4)
            if ip and ip['proto'] == 1:
                icmp_cnt += 1
    for (src, sp, dst, dp, proto, seq, fl, pl, ts, idx) in pcaplib.l4_packets(pkts, lt):
        for p in (sp, dp):
            ports[p] = ports.get(p, 0) + 1
    if icmp_cnt and not any(p in (80, 8080, 8000, 8001, 8081) for p in ports):
        return 'icmp', '发现 %d 个 ICMP 包' % icmp_cnt
    if ports.get(23, 0) > 0:
        return 'telnet', '发现 %d 个 telnet(23) 包' % ports[23]
    if ports.get(25, 0) or ports.get(110, 0) or ports.get(587, 0):
        n = ports.get(25, 0) + ports.get(110, 0) + ports.get(587, 0)
        return 'mail', '发现 %d 个邮件协议(25/110/587) 包' % n
    if any(p in (80, 8080, 8000, 8081) for p in ports):
        http_pkts = sum(c for p, c in ports.items() if p in (80, 8080, 8000, 8081))
        return 'web', '发现 %d 个 HTTP 端口包' % http_pkts
    return 'raw', '未知类型,仅做全文搜索'


def run_script(script, pcap):
    print('\n' + '=' * 64)
    print('>>> 运行 %s' % script)
    print('=' * 64)
    r = subprocess.run([sys.executable, os.path.join(HERE, script), pcap],
                       capture_output=True, text=True, encoding='utf-8', errors='replace',
                       cwd=HERE, timeout=600)
    out = (r.stdout or '') + (('\n[stderr] ' + r.stderr) if r.stderr.strip() else '')
    print(out.rstrip())
    return out


def global_search(pcap):
    print('\n' + '=' * 64)
    print('>>> 全文 flag / base64 候选搜索')
    print('=' * 64)
    lt, pkts = pcaplib.read_pcap(pcap)
    blob = b''
    for p in pkts:
        blob += p.data
    flags = pcaplib.find_flags(blob)
    for f in flags:
        print('[+] flag: %s' % f)
    # base64 候选
    cands = set()
    for m in re.finditer(rb'[A-Za-z0-9+/]{12,}={0,2}', blob):
        s = m.group(0)
        try:
            dec = base64.b64decode(s + b'=' * (-len(s) % 4))
            txt = dec.decode('utf-8')
            if len(txt) >= 4 and all(31 < ord(c) < 127 or c in '\r\n\t' for c in txt):
                cands.add(txt)
        except Exception:
            pass
    interesting = [c for c in cands if re.search(r'key|pass|flag|ctf|{', c, re.I)]
    for c in list(interesting)[:20]:
        print('[base64] %s' % pcaplib.shorten(c, 200))
    return flags


def main():
    if len(sys.argv) > 1:
        pcap = sys.argv[1]
    else:
        sdir = os.path.join(HERE, 'samples')
        pcap = None
        if os.path.isdir(sdir):
            cands = sorted((os.path.join(sdir, f) for f in os.listdir(sdir)
                            if f.endswith(('.pcap', '.cap'))),
                           key=os.path.getmtime, reverse=True)
            pcap = cands[0] if cands else None
    if not pcap or not os.path.exists(pcap):
        print(__doc__)
        sys.exit(1)

    print('[*] solve.py 一键分析: %s' % pcap)
    try:
        kind, why = detect(pcap)
    except Exception as e:
        print('[!] 文件无法直接解析(%s),先尝试 pcapfix.py ...' % e)
        fixed = os.path.splitext(pcap)[0] + '_fixed.pcap'
        run_script('pcapfix.py', pcap)
        if os.path.exists(fixed):
            pcap = fixed
            kind, why = detect(pcap)
        else:
            return
    print('[*] 识别流量类型: %s (%s)' % (kind, why))

    all_flags = set()
    for script in pick_script(kind, pcap):
        out = run_script(script, pcap)
        all_flags |= set(pcaplib.find_flags(out))

    all_flags |= set(global_search(pcap))

    print('\n' + '=' * 64)
    if all_flags:
        print('[★] 最终答案(flag): %s' % ' , '.join(all_flags))
    else:
        print('[*] 全文搜索未直接发现 flag,请查看上面各脚本的输出')
    print('=' * 64)


if __name__ == '__main__':
    main()
