# -*- coding: utf-8 -*-
"""idna_unicode_bypass.py IDNA Unicode 字符绕过探测([SUCTF 2019]Pythonginx)

来源: WP 汇总/[SUCTF 2019]Pythonginx(BlackHat us-19 HostSplit 论文 tricks)
用途: 遍历 U+0080~U+FFFF 的 Unicode 字符, 找出 encode('idna') 后仍映射为
      ASCII 的字符 —— 在过滤了 `.` `/` 等字符时, 用这些"形近字符"绕过
      URL 域名/路径校验(比如把 `/` 换成某个 idna 后变 `.` 的字符)。

用法:
    python idna_unicode_bypass.py --selftest                 # 自测(小范围扫描有结果)
    python idna_unicode_bypass.py                            # 全量扫描(默认 128~65537)
    python idna_unicode_bypass.py --start 128 --end 8192     # 指定范围
"""
import argparse
import sys


def scan(start, end):
    """返回 [(unicode字符, ascii结果, 码点)], 只保留映射中含 '-' 之外的可用项。"""
    results = []
    for i in range(start, end):
        tmp = chr(i)
        try:
            res = tmp.encode('idna').decode('utf-8')
        except Exception:
            continue
        if '-' in res:
            continue
        results.append((tmp, res, i))
    return results


def selftest():
    ok = True
    results = scan(128, 8192)  # 小范围即可稳定命中
    ok &= len(results) > 0
    for tmp, res, i in results[:10]:
        print('U:{}    A:{}      ascii:{} '.format(tmp, res, i))
    print('[%s] idna_unicode_bypass.py 自测(共 %d 条)'
          % ('OK' if ok else 'FAIL', len(results)))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='IDNA Unicode 绕过字符探测')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    ap.add_argument('--start', type=int, default=128, help='起始码点(默认 128)')
    ap.add_argument('--end', type=int, default=65537, help='结束码点(默认 65537)')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    for tmp, res, i in scan(args.start, args.end):
        print('U:{}    A:{}      ascii:{} '.format(tmp, res, i))
    return 0


if __name__ == '__main__':
    sys.exit(main())
