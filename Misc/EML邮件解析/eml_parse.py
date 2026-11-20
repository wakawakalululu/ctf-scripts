# -*- coding: utf-8 -*-
"""eml_parse.py — .eml 邮件解析(头字段/正文/附件导出, 取证+Misc 高频题型)

用途: 解析 EML(取证题常把 flag 藏在附件/HTML 正文/收发件头里):
      1. 打印 From/To/Subject/Date 与全部自定义头(X- 开头优先);
      2. 正文 text/plain、text/html 解码输出(带 flag 正则高亮);
      3. 附件自动导出到 --outdir(自动识别文件名, 重名加序号)。

用法:
    python eml_parse.py mail.eml                    # 概览+正文
    python eml_parse.py mail.eml --attach outdir    # 导出附件
    python eml_parse.py mail.eml --raw-header       # 打印完整原始头
    python eml_parse.py --selftest                  # 内置自测
"""
import argparse
import os
import re
import sys

from email import policy
from email.parser import BytesParser

FLAG_RE = re.compile(r'(?:flag|key|ctf)\{[^}]{0,120}\}', re.I)


def parse(path):
    with open(path, 'rb') as f:
        return BytesParser(policy=policy.default).parse(f)


def show_headers(msg, raw=False):
    if raw:
        print(msg.as_string().split('\r\n\r\n')[0].split('\n\n')[0])
        return
    for k in ('From', 'To', 'Cc', 'Subject', 'Date'):
        if msg.get(k):
            print('%s: %s' % (k, msg[k]))
    for k, v in msg.items():
        if k.lower().startswith('x-'):
            print('%s: %s' % (k, v))


def find_flags(text):
    return FLAG_RE.findall(text) if text else []


def walk_parts(msg, outdir=None):
    """遍历部件, 返回(文本块列表, 附件文件名列表)。"""
    texts, attachments = [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        fname = part.get_filename()
        if fname:
            payload = part.get_payload(decode=True) or b''
            if outdir:
                os.makedirs(outdir, exist_ok=True)
                base = re.sub(r'[\\/:*?"<>|]', '_', fname)
                dst, i = os.path.join(outdir, base), 1
                while os.path.exists(dst):
                    root, ext = os.path.splitext(base)
                    dst = os.path.join(outdir, '%s_%d%s' % (root, i, ext))
                    i += 1
                with open(dst, 'wb') as f:
                    f.write(payload)
                print('[附件] %s -> %s (%d 字节)' % (fname, dst, len(payload)))
            else:
                print('[附件] %s (%d 字节, 加 --attach 导出)' % (fname, len(payload)))
            attachments.append(fname)
        elif ctype in ('text/plain', 'text/html'):
            try:
                body = part.get_content()
            except Exception:
                body = (part.get_payload(decode=True) or b'').decode('utf-8', 'replace')
            texts.append((ctype, body))
    return texts, attachments


def selftest():
    import tempfile
    from email.message import EmailMessage
    m = EmailMessage()
    m['From'] = 'a@ctf.local'
    m['To'] = 'b@ctf.local'
    m['Subject'] = 'test flag mail'
    m.set_content('the flag{eml_ok_123} is here')
    m.add_attachment(b'attachment-bytes', maintype='application',
                     subtype='octet-stream', filename='secret.txt')
    fd, path = tempfile.mkstemp(suffix='.eml')
    os.close(fd)
    with open(path, 'wb') as f:
        f.write(bytes(m))
    msg = parse(path)
    texts, atts = walk_parts(msg)
    flags = [x for _, body in texts for x in find_flags(body)]
    os.unlink(path)
    ok = atts == ['secret.txt'] and 'flag{eml_ok_123}' in flags
    print('EML 解析/附件/flag提取:', 'OK' if ok else 'FAIL (%r %r)' % (atts, flags))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='.eml 邮件解析')
    ap.add_argument('file', nargs='?', help='.eml 文件')
    ap.add_argument('--attach', metavar='DIR', help='附件导出目录')
    ap.add_argument('--raw-header', action='store_true', help='打印完整原始头')
    ap.add_argument('--body-only', action='store_true', help='只输出正文')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.file:
        ap.error('需要 .eml 文件参数(或 --selftest)')
    msg = parse(args.file)
    if not args.body_only:
        show_headers(msg, args.raw_header)
        print('-' * 50)
    texts, _ = walk_parts(msg, args.attach)
    for ctype, body in texts:
        print('== 正文(%s) ==' % ctype)
        print(body[:2000])
        for fl in find_flags(body):
            print('>>> 疑似 flag:', fl)


if __name__ == '__main__':
    main()
