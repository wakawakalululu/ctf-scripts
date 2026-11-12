# -*- coding: utf-8 -*-
"""栅栏密码(Rail Fence Cipher) 加解密与爆破(补充题型: Crypto/古典密码)

用途:
    W 形栅栏密码(2~N 栏)加解密; 栏数未知时一键爆破全部栏数并按可读性排序。

用法:
    python railfence.py                        # 自测(内置用例)
    python railfence.py -e "HELLOWORLD" -r 3   # 编码(3栏)
    python railfence.py -d "HORELLOLWD" -r 3   # 解码(3栏)
    python railfence.py -d "HORELLOLWD"        # 爆破 2~len 栏, 打印所有候选
    python railfence.py -d "..." --flag flag{  # 爆破时优先显示含 flag 的结果
"""
import argparse
import re
import sys


def _pattern(n: int, rails: int):
    """返回每个明文字符落在第几栏(0 基)。"""
    if rails <= 1:
        return [0] * n
    pat, r, d = [], 0, 1
    for _ in range(n):
        pat.append(r)
        if r == rails - 1:
            d = -1
        elif r == 0:
            d = 1
        r += d
    return pat


def encrypt(text: str, rails: int) -> str:
    pat = _pattern(len(text), rails)
    rows = [[] for _ in range(rails)]
    for ch, r in zip(text, pat):
        rows[r].append(ch)
    return ''.join(''.join(row) for row in rows)


def decrypt(cipher: str, rails: int) -> str:
    pat = _pattern(len(cipher), rails)
    from collections import Counter
    cnt = Counter(pat)
    chars_by_rail, idx = {}, 0
    for r in range(rails):
        chars_by_rail[r] = list(cipher[idx:idx + cnt[r]])
        idx += cnt[r]
    pos = {r: 0 for r in range(rails)}
    out = []
    for r in pat:
        out.append(chars_by_rail[r][pos[r]])
        pos[r] += 1
    return ''.join(out)


def crack(cipher: str, marker: str = '', max_rails: int = 0):
    """爆破栏数。返回 (命中列表, 全部候选); marker 非空时用正则筛命中。"""
    max_rails = max_rails or max(2, len(cipher))
    hits, allc = [], []
    pat_re = re.compile(re.escape(marker)) if marker else None
    for rails in range(2, max_rails + 1):
        cand = decrypt(cipher, rails)
        allc.append((rails, cand))
        if pat_re and pat_re.search(cand):
            hits.append((rails, cand))
    return hits, allc


def _fix_neg(argv):
    """密文可能以 '-' 开头, argparse 会把 '-...' 当选项; 统一改写成 = 连接形式。"""
    out, i = [], 0
    while i < len(argv):
        if argv[i] in ('-e', '-d', '--encode', '--decode') and i + 1 < len(argv):
            out.append('%s=%s' % (argv[i], argv[i + 1]))
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return out


def main():
    ap = argparse.ArgumentParser(description='栅栏密码(W形)加解密/爆破')
    ap.add_argument('-e', '--encode', metavar='TEXT')
    ap.add_argument('-d', '--decode', metavar='CIPHER')
    ap.add_argument('-r', '--rails', type=int, default=0, help='栏数(默认0=爆破)')
    ap.add_argument('--flag', default='flag', help='爆破时的标记关键字')
    args = ap.parse_args(_fix_neg(sys.argv[1:]))

    if args.encode:
        if args.rails < 2:
            ap.error('编码需要 -r 指定栏数(>=2)')
        print(encrypt(args.encode, args.rails))
    elif args.decode:
        if args.rails >= 2:
            print(decrypt(args.decode, args.rails))
        else:
            hits, allc = crack(args.decode, marker=args.flag)
            if hits:
                print('== 命中 ==')
                for rails, cand in hits:
                    print(f'rails={rails}: {cand}')
            else:
                print('== 未命中, 全部候选 ==')
                for rails, cand in allc:
                    print(f'rails={rails}: {cand}')
    else:
        ok = True
        for text, rails in [('HELLOWORLD', 3), ('FLAG{RA1LF3NC3}', 4), ('AB', 2)]:
            e = encrypt(text, rails)
            back = decrypt(e, rails)
            good = back == text
            ok &= good
            print(f"[{'OK' if good else 'FAIL'}] {text!r} rails={rails}: {e!r} -> {back!r}")
        # 爆破验证
        cipher = encrypt('FLAG{FENC3_CRACK}', 5)
        hits, _ = crack(cipher, marker='FLAG{')
        good = any(cand == 'FLAG{FENC3_CRACK}' for _, cand in hits)
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 爆破: {cipher!r} -> 命中 {[c for _, c in hits]}")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
