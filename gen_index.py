# -*- coding: utf-8 -*-
"""gen_index 全库脚本索引生成器

用途:
    扫描本仓库全部 .py 脚本, 提取模块 docstring 首行作为说明、第三方依赖与自测能力,
    自动生成 SCRIPTS-INDEX.md 全量索引(README 里的分类表只覆盖代表性脚本,
    本索引覆盖每一个 .py)。新增脚本后重新运行即可刷新文档。

用法:
    python gen_index.py            # 生成/覆盖 SCRIPTS-INDEX.md
    python gen_index.py --stdout   # 只打印不写文件
    python gen_index.py --check    # 校验索引是否过期(过期则退出码 1, 可用于 CI)
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys

# import 名 -> pip 包名(与 check_env.py 保持一致)
PIP_NAME = {
    'PIL': 'pillow', 'Crypto': 'pycryptodome', 'cv2': 'opencv-python',
    'z3': 'z3-solver', 'pwn': 'pwntools', 'claripy': 'angr',
    'scapy': 'scapy', 'gmpy2': 'gmpy2', 'libnum': 'libnum', 'sympy': 'sympy',
    'pyzipper': 'pyzipper', 'pyzbar': 'pyzbar', 'qrcode': 'qrcode',
    'numpy': 'numpy', 'requests': 'requests', 'unicorn': 'unicorn',
    'capstone': 'capstone', 'angr': 'angr', 'LibcSearcher': 'LibcSearcher',
    'owiener': 'owiener', 'pyshark': 'pyshark', 'ds_store': 'ds_store',
    'rsa': 'rsa',
}

# 顶级目录 -> 类别说明(顺序即索引中的展示顺序)
CATEGORIES = [
    ('Crypto', '密码学:RSA 全家桶 / 古典密码 / 对称加密 / 哈希'),
    ('Encoding', '编码转换:Base 系列 / hex / 二进制 / 字符统计'),
    ('Steganography', '隐写:图片 / 音频 / 零宽字符 / 二维码'),
    ('TrafficeAnalysis', '流量分析:USB / WEB / 邮件 / Telnet / 修复(一键入口 solve.py)'),
    ('LogAnalysis', '日志分析'),
    ('Web', 'Web 安全:SQLi / SSTI / JWT / 反序列化 / 信息泄露'),
    ('Pwn', '二进制漏洞利用:pwntools 模板 / shellcode'),
    ('Reverse', '逆向:z3 / angr / pyc 修复 / ARM 模拟'),
    ('Misc', '杂项:压缩包 / 文件修复 / CRC32 / 迷宫 / Brainfuck'),
]

INDEX_FILE = 'SCRIPTS-INDEX.md'
ROOT_FILES_TITLE = '仓库工具(根目录)'


def module_docstring_first_line(path):
    """取模块 docstring 的首个非空行; 没有 docstring 返回 None。"""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            src = f.read()
    except OSError:
        return None
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return None
    doc = ast.get_docstring(tree)
    if not doc:
        return None
    for line in doc.splitlines():
        line = line.strip()
        if line:
            return line
    return None


def third_party_deps(path):
    """AST 解析 import, 映射出第三方依赖的 pip 包名列表。"""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            tree = ast.parse(f.read())
    except (OSError, SyntaxError):
        return []
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split('.')[0])
    deps = sorted({PIP_NAME[m] for m in mods if m in PIP_NAME})
    return deps


def scan_scripts(root='.'):
    """返回 {顶级目录: [ (相对路径, 说明, 依赖, 有自测, 行数) ]}。"""
    result = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ('.git', '__pycache__')]
        for fn in filenames:
            if not fn.endswith('.py'):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace('\\', '/')
            top = rel.split('/')[0]
            try:
                with open(full, 'r', encoding='utf-8', errors='replace') as f:
                    src = f.read()
                lines = src.count('\n') + 1
            except OSError:
                lines = 0
            desc = module_docstring_first_line(full)
            deps = third_party_deps(full)
            selftest = bool(re.search(
                r"add_argument\(\s*['\"]--selftest", src))
            result.setdefault(top, []).append((rel, desc, deps, selftest, lines))
    for items in result.values():
        items.sort(key=lambda x: x[0].lower())
    return result


def github_slug(text):
    """按 GitHub 的 anchor 规则生成目录锚点: 小写、去标点、空格转连字符。"""
    keep = []
    for ch in text.lower():
        if ch.isalnum() or '\u4e00' <= ch <= '\u9fff':
            keep.append(ch)
        elif ch in ' -_':
            keep.append('-')
    return ''.join(keep).strip('-')


def render_index(scripts):
    """把扫描结果渲染成 markdown 文本。"""
    n_total = sum(len(v) for v in scripts.values())
    # 根目录工具脚本单独列出(scan_scripts 以文件名作为顶级 key)
    root_items = []
    for name in ('check_env.py', 'gen_index.py'):
        root_items.extend(scripts.get(name, []))
    out = []
    out.append('# SCRIPTS-INDEX — 全量脚本索引')
    out.append('')
    out.append('> 由 `gen_index.py` 自动生成, 覆盖仓库内**每一个 .py 脚本**'
               f'(共 {n_total} 个)。新增/修改脚本后运行 '
               '`python gen_index.py` 刷新本文件; '
               '`python gen_index.py --check` 可校验是否过期。')
    out.append('>')
    out.append('> 说明列取自脚本模块 docstring 首行; 标"—"为早期收集的老脚本, '
               '用法见 README 对应分类表或脚本内注释。')
    out.append('> 依赖列只列**第三方包**(安装: `pip install -r requirements.txt`, '
               '环境自检: `python check_env.py`)。')
    out.append('')

    # 目录
    out.append('## 目录')
    out.append('')
    for top, desc in CATEGORIES:
        if top in scripts:
            head = f'{top} — {desc.split(":")[0]} ({len(scripts[top])})'
            out.append(f'- [{head}](#{github_slug(head)})')
    root_head = f'{ROOT_FILES_TITLE} ({len(root_items)})'
    out.append(f'- [{root_head}](#{github_slug(root_head)})')
    out.append('')

    for top, desc in CATEGORIES:
        items = scripts.get(top)
        if not items:
            continue
        out.append(f'## {top} — {desc.split(":")[0]} ({len(items)})')
        out.append('')
        out.append(f'> {desc}')
        out.append('')
        out.append('| 脚本 | 说明 | 依赖 | 自测 | 行数 |')
        out.append('|---|---|---|---|---|')
        for rel, d, deps, st, n in items:
            show = rel[len(top) + 1:] or rel  # 去掉顶级前缀, 缩短表格
            desc_cell = (d or '—').replace('|', '\\|')
            deps_cell = ', '.join(deps) if deps else '—'
            st_cell = '✅ `--selftest`' if st else '—'
            out.append(f'| `{show}` | {desc_cell} | {deps_cell} | {st_cell} | {n} |')
        out.append('')

    if root_items:
        out.append(f'## {ROOT_FILES_TITLE} ({len(root_items)})')
        out.append('')
        out.append('| 脚本 | 说明 | 依赖 | 自测 | 行数 |')
        out.append('|---|---|---|---|---|')
        for rel, d, deps, st, n in root_items:
            desc_cell = (d or '—').replace('|', '\\|')
            deps_cell = ', '.join(deps) if deps else '—'
            st_cell = '✅ `--selftest`' if st else '—'
            out.append(f'| `{rel}` | {desc_cell} | {deps_cell} | {st_cell} | {n} |')
        out.append('')

    out.append('---')
    out.append('')
    out.append('*本文件由 gen_index.py 自动生成, 请勿手工编辑; 用法说明的'
               '人工版见 [README.md](README.md) 与 '
               '[TrafficeAnalysis/README.md](TrafficeAnalysis/README.md)。*')
    return '\n'.join(out) + '\n'


def main():
    ap = argparse.ArgumentParser(description='生成全量脚本索引 SCRIPTS-INDEX.md')
    ap.add_argument('--stdout', action='store_true', help='打印到标准输出而不写文件')
    ap.add_argument('--check', action='store_true',
                    help='校验现有索引是否为最新(过期退出码 1)')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    scripts = scan_scripts('.')
    text = render_index(scripts)

    if args.stdout:
        sys.stdout.write(text)
        return 0

    old = None
    if os.path.exists(INDEX_FILE):
        try:
            with open(INDEX_FILE, 'r', encoding='utf-8') as f:
                old = f.read()
        except OSError:
            old = None
    if args.check:
        if old == text:
            print(f'[OK] {INDEX_FILE} 已是最新')
            return 0
        print(f'[过期] {INDEX_FILE} 与当前脚本集不一致, 请运行: python gen_index.py')
        return 1

    with open(INDEX_FILE, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    n = sum(len(v) for v in scripts.values())
    print(f'[OK] 已生成 {INDEX_FILE}: {n} 个脚本, '
          f'{len([k for k in scripts if k in dict(CATEGORIES)])} 个分类')
    return 0


if __name__ == '__main__':
    sys.exit(main())
