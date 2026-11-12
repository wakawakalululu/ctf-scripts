# -*- coding: utf-8 -*-
"""
extract_objects.py — 从流量中提取传输的文件(通用技能)

支持:
  1. HTTP 响应/请求体:按魔数(PNG/JPG/GIF/PDF/ZIP/RAR/7z/EXE/ELF)或
     Content-Disposition 识别文件并导出
  2. HTTP multipart 上传的文件
  3. FTP 明文传输(STOR/RETR 时代码混在流里,按魔数切割)
导出的文件可直接交给 binwalk/foremost/steghide 继续分析。

用法: python extract_objects.py <pcap> [输出目录]
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

# 文件魔数表
MAGICS = [
    (b'\x89PNG\r\n\x1a\n', '.png'),
    (b'\xff\xd8\xff', '.jpg'),
    (b'GIF87a', '.gif'),
    (b'GIF89a', '.gif'),
    (b'%PDF-', '.pdf'),
    (b'PK\x03\x04', '.zip'),
    (b'Rar!\x1a\x07', '.rar'),
    (b'7z\xbc\xaf\x27\x1c', '.7z'),
    (b'MZ', '.exe'),
    (b'\x7fELF', '.elf'),
    (b'\x1f\x8b', '.gz'),
    (b'BM', '.bmp'),
]


def sniff_ext(data):
    for magic, ext in MAGICS:
        if data.startswith(magic):
            return ext
    return None


def carve_multi(data, outdir, prefix):
    """更稳妥:依次尝试所有魔数,记录所有命中并按位置去重。"""
    hits = []
    for magic, ext in MAGICS:
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            hits.append((i, magic, ext))
            start = i + len(magic)
    hits.sort()
    saved = []
    used = []
    for i, magic, ext in hits:
        if any(i < u for u in used):
            continue
        chunk = data[i:i + 5 * 1024 * 1024]
        used.append(i + len(chunk))
        out = os.path.join(outdir, '%s_%d%s' % (prefix, len(saved) + 1, ext))
        with open(out, 'wb') as f:
            f.write(chunk)
        saved.append(out)
    return saved


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else default_sample()
    outdir = sys.argv[2] if len(sys.argv) > 2 else 'exported'
    if not path or not os.path.exists(path):
        print('用法: python extract_objects.py <pcap> [输出目录]')
        sys.exit(1)
    os.makedirs(outdir, exist_ok=True)
    print('[*] 分析 %s, 导出到 %s/' % (path, outdir))
    lt, pkts = pcaplib.read_pcap(path)
    saved = []

    # 1) HTTP 对象(请求体 + 响应体)
    n_obj = 0
    for i, msg, st in pcaplib.iter_http(pkts, lt):
        bodies = []
        if isinstance(msg, pcaplib.HttpResponse):
            ct = msg.header('content-type')
            cd = msg.header('content-disposition')
            bodies.append((msg.body, 'http%d_resp' % (i + 1), ct, cd))
        elif isinstance(msg, pcaplib.HttpRequest) and msg.method == 'POST':
            bodies.append((msg.body, 'http%d_req' % (i + 1), msg.header('content-type'), ''))
        for body, tag, ct, cd in bodies:
            if not body:
                continue
            m = re.search(r'filename="([^"]+)"', cd)
            ext = sniff_ext(body)
            if m:
                out = os.path.join(outdir, os.path.basename(m.group(1)))
                with open(out, 'wb') as f:
                    f.write(body)
                saved.append(out)
            elif ext and (ct and 'html' not in ct or True) and len(body) > 100:
                n_obj += 1
                out = os.path.join(outdir, '%s_%d%s' % (tag, n_obj, ext))
                with open(out, 'wb') as f:
                    f.write(body)
                saved.append(out)
            # multipart 上传
            if 'multipart/form-data' in (ct or ''):
                mm = re.search(r'boundary=([^;]+)', ct)
                if mm:
                    for part in body.split(b'--' + mm.group(1).encode()):
                        mf = re.search(rb'filename="([^"]+)"', part)
                        if not mf:
                            continue
                        content = part.split(b'\r\n\r\n', 1)[-1]
                        content = content.rsplit(b'\r\n', 1)[0]
                        out = os.path.join(outdir, os.path.basename(mf.group(1).decode('utf-8', 'replace')))
                        with open(out, 'wb') as f:
                            f.write(content)
                        saved.append(out)

    # 2) 全流量按魔数兜底切割
    raw = b''.join(p.data for p in pkts) if lt not in (
        pcaplib.LINKTYPE_USB_LINUX, pcaplib.LINKTYPE_USBPCAP) else b''
    if raw:
        saved += ['(carve) ' + s for s in carve_multi(raw, outdir, 'carve')]

    if saved:
        print('[+] 共导出 %d 个文件:' % len(saved))
        for s in saved:
            print('    %s' % s)
        flags = set()
        for s in saved:
            if os.path.exists(s.split('(carve) ')[-1]):
                p = s.split('(carve) ')[-1]
                with open(p, 'rb') as f:
                    flags |= set(pcaplib.find_flags(f.read()))
        for f in flags:
            print('[+] 顺带发现 flag: %s' % f)
    else:
        print('[-] 未发现可导出的文件对象')


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, 'samples/web_attack.pcap')
    return p if os.path.exists(p) else None


if __name__ == '__main__':
    main()
