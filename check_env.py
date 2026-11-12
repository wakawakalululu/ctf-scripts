# -*- coding: utf-8 -*-
"""check_env 脚本库环境自检

用途: 扫描本目录全部 .py 脚本, 报告每个脚本的 Python 版本要求、第三方依赖与安装状态,
     并给出可直接复制的 pip 安装命令。运行前先自检当前解释器版本。

用法:
    python check_env.py                # 全库扫描 + 环境报告
    python check_env.py --missing      # 只看缺依赖/有问题的脚本
    python check_env.py --deps         # 只看依赖汇总与安装命令
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import os
import sys

# import 名 -> pip 包名
PIP_NAME = {
    'PIL': 'pillow', 'Crypto': 'pycryptodome', 'cv2': 'opencv-python',
    'z3': 'z3-solver', 'pwn': 'pwntools', 'claripy': 'angr',
    'scapy': 'scapy', 'gmpy2': 'gmpy2', 'libnum': 'libnum', 'sympy': 'sympy',
    'pyzipper': 'pyzipper', 'pyzbar': 'pyzbar', 'qrcode': 'qrcode',
    'numpy': 'numpy', 'requests': 'requests', 'unicorn': 'unicorn',
    'capstone': 'capstone', 'angr': 'angr', 'LibcSearcher': 'LibcSearcher',
    'owiener': 'owiener',
}
# 平台受限依赖 -> 运行环境建议
PLATFORM_NOTE = {
    'pwn': 'Windows 不支持 process(), 仅 remote; 本地调试用 WSL/Linux',
    'angr': '建议 WSL/Linux 安装',
    'unicorn': 'Windows 有 wheel, 复杂固件建议 Linux',
    'pyzbar': 'Windows 需另装 VC++ 运行库(zbar dll)',
}
try:
    STDLIB = set(sys.stdlib_module_names)          # py3.10+
except AttributeError:                             # py3.8/3.9 兜底: 按安装路径判断
    import importlib.util
    import sysconfig
    _stdlib_dir = sysconfig.get_paths()['stdlib']
    _cache = {}

    def _is_stdlib(name):
        if name in _cache:
            return _cache[name]
        try:
            spec = importlib.util.find_spec(name)
        except Exception:
            spec = None
        origin = getattr(spec, 'origin', None)
        ok = bool(origin) and (origin in ('built-in', 'frozen')
                               or origin.startswith(_stdlib_dir))
        _cache[name] = ok
        return ok

    class _StdlibSet(set):
        def __contains__(self, item):
            return set.__contains__(self, item) or _is_stdlib(item)

    STDLIB = _StdlibSet(sys.builtin_module_names)


def analyze(path):
    """返回 (label, deps): label ∈ PY3_OK / PY3_10 / PY2_OR_BROKEN"""
    import warnings
    try:
        src = open(path, 'rb').read().decode('utf-8', errors='replace')
    except Exception:
        return 'PY2_OR_BROKEN', []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            tree = ast.parse(src)
    except SyntaxError:
        return 'PY2_OR_BROKEN', []
    min_py10 = False
    deps = set()
    # PEP 563: 延迟注解使 `int | None` 在 3.7+ 运行时不求值, 静态豁免
    has_future_annotations = any(
        isinstance(n, ast.ImportFrom) and n.module == '__future__'
        and any(a.name == 'annotations' for a in n.names)
        for n in tree.body)

    def is_pep604(a):
        return isinstance(a, ast.BinOp) and isinstance(a.op, ast.BitOr)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = list(node.args.args) + list(node.args.kwonlyargs)
            for extra in (node.args.vararg, node.args.kwarg):
                if extra:
                    args.append(extra)
            anns = [a.annotation for a in args if a.annotation]
            if node.returns:
                anns.append(node.returns)
            if not has_future_annotations and any(is_pep604(a) for a in anns):
                min_py10 = True
        elif isinstance(node, ast.AnnAssign):
            if not has_future_annotations and is_pep604(node.annotation):
                min_py10 = True
        elif isinstance(node, ast.Match):
            min_py10 = True
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split('.')[0] not in STDLIB:
                    deps.add(a.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split('.')[0] not in STDLIB:
                deps.add(node.module.split('.')[0])
    if min_py10:
        return 'PY3_10', sorted(deps)
    return 'PY3_OK', sorted(deps)


def is_local_module(dep, script_dir):
    """同目录/父目录存在同名 .py 则视为本地模块而非第三方库。"""
    for d in (script_dir, os.path.dirname(script_dir)):
        if os.path.exists(os.path.join(d, dep + '.py')) \
                or os.path.isdir(os.path.join(d, dep)):
            return True
    return False


def installed(mod):
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


def main():
    ap = argparse.ArgumentParser(description='CTF 脚本库环境自检')
    ap.add_argument('--missing', action='store_true', help='只显示有问题的脚本')
    ap.add_argument('--deps', action='store_true', help='只显示依赖汇总')
    args = ap.parse_args()

    py = sys.version_info
    print(f'Python: {py.major}.{py.minor}.{py.micro}', end='  ')
    if (py.major, py.minor) >= (3, 8):
        print('[OK] 满足全库基线(>=3.8)')
    else:
        print('[警告] 低于 3.8, 部分脚本无法运行, 建议 >=3.10')

    root = os.path.dirname(os.path.abspath(__file__))
    files = []
    for cur, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('.git', '__pycache__')]
        for n in names:
            if n.endswith('.py') and n != 'check_env.py':
                files.append(os.path.join(cur, n))

    rows, missing_pkgs = [], {}
    for f in sorted(files):
        label, deps = analyze(f)
        real_deps = []
        for d in deps:
            if is_local_module(d, os.path.dirname(f)):
                continue
            real_deps.append(d)
            if not installed(d):
                missing_pkgs.setdefault(PIP_NAME.get(d, d), []).append(f)
        rows.append((f, label, real_deps))

    n_bad = sum(1 for _, l, _ in rows if l != 'PY3_OK')
    print(f'脚本总数: {len(rows)} | py3 兼容: {len(rows) - n_bad} | '
          f'需 python2/语法异常: {n_bad}')
    print()

    if not args.deps:
        print('===== 脚本状态 =====')
        for f, label, deps in rows:
            if args.missing and label == 'PY3_OK' and not deps:
                continue
            rel = os.path.relpath(f, root)
            if label == 'PY2_OR_BROKEN':
                print(f'[需python2] {rel}')
            elif label == 'PY3_10':
                print(f'[需>=3.10] {rel}')
            else:
                miss = [d for d in deps if not installed(d)]
                tag = '缺依赖:' + ','.join(miss) if miss else 'OK'
                print(f'[{tag}] {rel}' if miss else f'[OK] {rel}'
                      + (f'  ({",".join(deps)})' if deps else ''))
        print()

    print('===== 缺失依赖汇总 =====')
    if not missing_pkgs:
        print('全部依赖已安装 ✓')
    else:
        for pkg, fs in sorted(missing_pkgs.items()):
            pip_name = PIP_NAME.get(pkg, pkg)
            note = PLATFORM_NOTE.get(pkg, '')
            print(f'pip install {pip_name}   # 影响 {len(fs)} 个脚本'
                  + (f'  [{note}]' if note else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
