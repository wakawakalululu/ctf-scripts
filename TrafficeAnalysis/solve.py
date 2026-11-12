# -*- coding: utf-8 -*-
"""
solve.py — 一键流量分析:自动识别流量类型,调用对应脚本出解(总入口)

识别规则(按优先级):
  USB 链路层(usbmon/USBPcap)      -> usb_keyboard.py + usb_mouse.py
  HTTP 端口流量                    -> find_scanner / find_admin_url / find_login
                                     / find_webshell / extract_objects
  SMTP/POP3 端口流量               -> smtp_mail.py
  Telnet 端口流量                  -> telnet_session.py
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
    }.get(kind, [])


def detect(pcap):
    """返回 (流量类型, 说明)"""
    lt, pkts = pcaplib.read_pcap(pcap)
    if lt in (pcaplib.LINKTYPE_USB_LINUX, pcaplib.LINKTYPE_USBPCAP):
        return 'usb', '链路层=%s (USB)' % pcaplib.get_linktype_name(lt)
    # 端口统计
    ports = {}
    for (src, sp, dst, dp, proto, seq, fl, pl, ts, idx) in pcaplib.l4_packets(pkts, lt):
        for p in (sp, dp):
            ports[p] = ports.get(p, 0) + 1
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
