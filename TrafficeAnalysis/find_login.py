# -*- coding: utf-8 -*-
"""
find_login.py — 后台账号爆破分析(题型:黑客使用了什么账号密码登录了web后台?)

思路:登录都是 POST。把所有 POST 请求的账号密码参数解出来,
再根据登录后的响应(302 跳转 / 200 内容变化 / Set-Cookie)判断哪一组是"成功"的。

等价 tshark: http.request.method=="POST" && http contains "admin"
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

# 常见账号/密码参数名
USER_KEYS = ['username', 'user', 'name', 'account', 'email', 'login', 'uname', 'uid', 'userid']
PASS_KEYS = ['password', 'passwd', 'pass', 'pwd', 'pw', 'userpass', 'login_password']
SUCCESS_MARK = ('302', '301')          # 登录成功常见跳转
COOKIE_MARK = 'set-cookie'


def analyze(path):
    lt, pkts = pcaplib.read_pcap(path)
    attempts = []      # dict(user, pwd, path, host, next_status, next_loc, has_cookie)
    streams = pcaplib.build_streams(pkts, lt)
    for st in streams:
        reqs = [r for r in pcaplib.parse_http_stream(st.client_stream(), is_request=True)
                if isinstance(r, pcaplib.HttpRequest)]
        resps = [r for r in pcaplib.parse_http_stream(st.server_stream(), is_request=False)
                 if isinstance(r, pcaplib.HttpResponse)]
        for j, req in enumerate(reqs):
            if req.method != 'POST':
                continue
            ct = req.header('content-type')
            is_multipart = 'multipart/form-data' in ct
            form = {} if is_multipart else req.form()
            user = pwd = None
            for k, v in form.items():
                kl = k.lower()
                if user is None and any(kl == x or x in kl for x in USER_KEYS):
                    user = v
                elif pwd is None and any(kl == x or x in kl for x in PASS_KEYS):
                    pwd = v
            # multipart 登录/JSON 兜底:直接在 body 里找(纯文件上传的 multipart 跳过)
            if user is None and pwd is None and not is_multipart:
                txt = req.body.decode('utf-8', 'replace')
                import re
                mu = re.search(r'(?:user|name|account|email|login)"?\s*[:=]\s*"?([^&"\'\r\n,}]+)', txt, re.I)
                mp = re.search(r'(?:pass\w*)"?\s*[:=]\s*"?([^&"\'\r\n,}]+)', txt, re.I)
                if mu:
                    user = mu.group(1)
                if mp:
                    pwd = mp.group(1)
            if user is None and pwd is None:
                continue
            rec = {'user': user, 'pwd': pwd, 'path': req.path,
                   'host': req.header('host') or '%s:%d' % st.server,
                   'status': '', 'location': '', 'cookie': False, 'body': ''}
            if j < len(resps):
                r = resps[j]
                rec['status'] = r.status
                rec['location'] = r.header('location')
                rec['cookie'] = COOKIE_MARK in r.headers or bool(r.header('set-cookie'))
                rec['body'] = r.body
            # 302 之后的下一个 200 响应体也看一下(判断是否进入了后台)
            if j + 1 < len(resps):
                rec['body_after'] = resps[j + 1].body
            attempts.append(rec)
    return attempts


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else default_sample()
    if not path or not os.path.exists(path):
        print('用法: python find_login.py <pcap>')
        sys.exit(1)
    print('[*] 分析 %s' % path)
    attempts = analyze(path)
    if not attempts:
        print('[-] 未发现带账号密码参数的 POST 请求')
        return
    print('[*] 共发现 %d 次登录尝试:' % len(attempts))
    for i, a in enumerate(attempts, 1):
        mark = ''
        if a['status'] in SUCCESS_MARK or (a['status'] == '200' and a['cookie']):
            mark = '   <== 疑似登录成功(响应 %s%s%s)' % (
                a['status'],
                ' -> %s' % a['location'] if a['location'] else '',
                ' +Set-Cookie' if a['cookie'] else '')
        print('    [%d] POST %s  user=%s  pwd=%s  resp=%s%s' % (
            i, a['path'], a['user'], a['pwd'], a['status'] or '?', mark))

    ok = [a for a in attempts if a['status'] in SUCCESS_MARK or
          (a['status'] == '200' and a['cookie'])]
    if ok:
        a = ok[-1]
        print()
        print('[+] 答案(成功登录的账号密码): %s / %s' % (a['user'], a['pwd']))
    else:
        # 兜底:爆破流量里最后一个不同的账号通常是成功的
        a = attempts[-1]
        print()
        print('[~] 未发现明确的成功响应,最后一组登录参数最可能是正确的: %s / %s' % (a['user'], a['pwd']))

    flags = pcaplib.find_flags(b' '.join((a.get('body') or b'') + (a.get('body_after') or b'')
                                         for a in attempts))
    for f in flags:
        print('[+] 响应中搜到 flag: %s' % f)


def default_sample():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, 'samples/web_attack.pcap')
    return p if os.path.exists(p) else None


if __name__ == '__main__':
    main()
