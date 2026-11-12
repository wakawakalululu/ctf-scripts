# -*- coding: utf-8 -*-
"""
smtp_mail.py — SMTP/POP3 邮件流量分析(题型:邮件里藏flag/附件)

思路:SMTP(25/465/587)明文对话中 DATA 段就是邮件原文;
POP3(110) 的 RETR 响应也是邮件原文。脚本:
  1. 重组端口 25/110/587 的 TCP 流
  2. 解析 MIME:头(From/To/Subject)+ 正文(base64/QP 解码)
  3. 导出附件并全局搜 flag

用法: python smtp_mail.py <pcap> [导出目录]
"""
import os
import re
import sys
import base64
import quopri
from email import message_from_bytes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

MAIL_PORTS = {25, 110, 465, 587, 995, 2525}


def iter_mail_streams(packets, linktype):
    for i, st in enumerate(pcaplib.build_streams(packets, linktype)):
        if st.client[1] in MAIL_PORTS or st.server[1] in MAIL_PORTS:
            yield i, st


def extract_mail(text):
    """从流文本里提取邮件(DATA 正文)。返回 [MIME message]。"""
    mails = []

    def _clean(raw):
        # 去掉 SMTP 的点填充
        raw = re.sub(r'(^|\r?\n)\.\.', r'\1.', raw)
        # DATA 段前可能混有服务器提示行(如 354 ...),切到第一个真正的邮件头
        lines = raw.split('\r\n')
        for i, ln in enumerate(lines):
            if re.match(r'[A-Za-z][A-Za-z0-9-]*:\s', ln):
                raw = '\r\n'.join(lines[i:])
                break
        return raw

    # SMTP: DATA -> 单独一行 '.' 结束(DATA 标记必须存在)
    for m in re.finditer(r'(?:^|\r?\n)DATA\r?\n(.*?)\r?\n\.\r?\n', text,
                         re.S):
        raw = _clean(m.group(1))
        try:
            mails.append(message_from_bytes(raw.encode('latin1', 'replace')))
        except Exception:
            pass
    for m in re.finditer(r'\+OK[^\r\n]*\r\n', text):
        seg = text[m.end():]
        end = seg.find('\r\n.\r\n')
        if end > 0:
            raw = _clean(seg[:end])
            try:
                mails.append(message_from_bytes(raw.encode('latin1', 'replace')))
            except Exception:
                pass
    return mails


def walk_parts(msg, depth=0):
    """生成 (filename, content_type, decoded_bytes)"""
    out = []
    if msg.is_multipart():
        for part in msg.get_payload():
            out += walk_parts(part, depth + 1)
        return out
    ct = msg.get_content_type()
    payload = msg.get_payload(decode=True)
    fname = msg.get_filename()
    out.append((fname, ct, payload if payload is not None else
                str(msg.get_payload()).encode('utf-8', 'replace')))
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else default_sample()
    outdir = sys.argv[2] if len(sys.argv) > 2 else 'mail_export'
    if not path or not os.path.exists(path):
        print('用法: python smtp_mail.py <pcap> [导出目录]')
        sys.exit(1)
    print('[*] 分析 %s' % path)
    lt, pkts = pcaplib.read_pcap(path)
    found = 0
    flags = set()
    for i, st in iter_mail_streams(pkts, lt):
        text = pcaplib.printable(st.client_stream() + st.server_stream())
        # 会话中的账号密码
        for m in re.finditer(r'(USER|AUTH LOGIN|MAIL FROM:)\s*:?\s*([^\r\n]+)', text, re.I):
            print('  [会话] %s %s' % (m.group(1), m.group(2)))
        for m in re.finditer(r'(PASS|PASSWORD)\s+:?\s*([^\r\n]+)', text, re.I):
            print('  [会话] PASS %s' % m.group(2))
        mails = extract_mail(text)
        for msg in mails:
            found += 1
            print('  == 邮件 #%d ==' % found)
            for h in ('From', 'To', 'Subject', 'Date'):
                v = msg.get(h)
                if v:
                    # RFC2047 编码的主题解码
                    try:
                        from email.header import decode_header
                        parts = decode_header(v)
                        v = ''.join(p.decode(cs or 'utf-8') if isinstance(p, bytes) else p
                                    for p, cs in parts)
                    except Exception:
                        pass
                    print('     %s: %s' % (h, v))
            for fname, ct, content in walk_parts(msg):
                if not content:
                    continue
                print('     [部分] type=%s name=%s size=%d' % (ct, fname, len(content)))
                is_att = fname is not None or ct not in ('text/plain',)
                if is_att and fname:
                    os.makedirs(outdir, exist_ok=True)
                    out = os.path.join(outdir, os.path.basename(fname))
                    with open(out, 'wb') as f:
                        f.write(content)
                    print('       -> 附件已导出: %s' % out)
                flags |= set(pcaplib.find_flags(content))
                flags |= set(pcaplib.find_flags(str(msg)))
    if not found:
        print('[-] 未发现邮件原文(可能为加密端口或无邮件)')
    print()
    if flags:
        print('[+] 答案(flag): %s' % ' , '.join(flags))


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, 'samples/mail.pcap')
    return p if os.path.exists(p) else None


if __name__ == '__main__':
    main()
