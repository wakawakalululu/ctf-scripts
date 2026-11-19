# -*- coding: utf-8 -*-
"""vigenere_brute.py — 维吉尼亚密码密钥爆破(重合指数 + 卡方频率分析)

用途: 拿到密文不知道密钥时的自动爆破:
      1. 密钥长度: 对 len 1..--maxlen 逐列算重合指数 IC, 取均值最高者
      2. 每列移位: 英文字母频率卡方检验, 取最优移位 -> 每列一位密钥
      3. 输出密钥 + 明文; --crib 明文片段筛选(避免频率法偶发偏差),
         可再配 Crypto/维吉尼亚加密/exp.py 用已知密钥精修。
      支持 --keylen 指定长度跳过估计。英文题面效果最好; 密文越长约稳。

用法:
    python vigenere_brute.py cipher.txt                     # 文件密文
    python vigenere_brute.py -c "RIJVSUYVGLNQM..."          # 命令行密文
    python vigenere_brute.py cipher.txt --keylen 6          # 已知长度直破
    python vigenere_brute.py cipher.txt --crib flag{        # 按明文片段筛
    python vigenere_brute.py --selftest                     # 内置自测
"""
import argparse
import re
import sys

EN_FREQ = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
           0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
           0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
           0.00978, 0.02360, 0.00150, 0.01974, 0.00074]
A = ord('A')


def normalize(text):
    """只保留大写字母(小写转大写, 其余丢弃), 另返回(原文, 位置映射)备用。"""
    return re.sub(r'[^A-Za-z]', '', text).upper()


def index_of_coincidence(seq):
    n = len(seq)
    if n < 2:
        return 0.0
    cnt = [seq.count(chr(A + i)) for i in range(26)]
    return sum(c * (c - 1) for c in cnt) / (n * (n - 1))


def best_keylen(cipher, maxlen):
    scores = []
    for kl in range(1, min(maxlen, len(cipher)) + 1):
        cols = [cipher[i::kl] for i in range(kl)]
        avg_ic = sum(index_of_coincidence(c) for c in cols) / kl
        scores.append((avg_ic, kl))
    # 英文单列 IC≈0.0667, 随机≈0.0385: 排序取 IC 最高, 同分取短密钥
    scores.sort(key=lambda x: (-x[0], x[1]))
    return scores[:5], scores[0][1]


def chi2_shift(col):
    """对一列做 26 个移位的卡方检验, 返回 (最优移位, 明文列)。"""
    n = len(col)
    best_shift, best_chi = 0, float('inf')
    for s in range(26):
        cnt = [0] * 26
        for ch in col:
            cnt[(ord(ch) - A - s) % 26] += 1
        chi = sum((cnt[i] - EN_FREQ[i] * n) ** 2 / (EN_FREQ[i] * n)
                  for i in range(26) if EN_FREQ[i] * n > 0)
        if chi < best_chi:
            best_chi, best_shift = chi, s
    plain = ''.join(chr((ord(c) - A - best_shift) % 26 + A) for c in col)
    return best_shift, plain


def break_cipher(cipher, keylen=None, maxlen=16):
    """返回 (key, plaintext, 判定长度, 长度候选表)。"""
    cands, auto_kl = best_keylen(cipher, maxlen)
    if keylen is None:
        keylen = auto_kl
    cols = [cipher[i::keylen] for i in range(keylen)]
    shifts, plains = [], []
    for col in cols:
        s, p = chi2_shift(col)
        shifts.append(s)
        plains.append(p)
    key = ''.join(chr(s + A) for s in shifts)
    # 明文重排回列序
    out = [''] * len(cipher)
    idx = 0
    for i in range(keylen):
        for j in range(i, len(cipher), keylen):
            out[j] = plains[i][idx]
            idx += 1
        idx = 0
    return key, ''.join(out), keylen, cands


def encrypt(plain, key):
    """加密(自测用): 标准维吉尼亚, 非字母跳过不进位。"""
    key = normalize(key)
    out, i = [], 0
    for ch in plain:
        if ch.isalpha():
            k = ord(key[i % len(key)]) - A
            base = 'A' if ch.isupper() else 'a'
            out.append(chr((ord(ch) - ord(base) + k) % 26 + ord(base)))
            i += 1
        else:
            out.append(ch)
    return ''.join(out)


SAMPLE_EN = ('The quick brown fox jumps over the lazy dog. '
             'In classical cryptography the Vigenere cipher was long '
             'believed to be unbreakable until Kasiski published his '
             'attack on repeated key sequences. The index of coincidence '
             'measures how likely two randomly chosen letters of a text '
             'are equal, which differs greatly between natural language '
             'and random letters. Breaking the cipher uses column wise '
             'frequency analysis to recover the key step by step.')


def selftest():
    key = 'SECRET'
    cipher = encrypt(SAMPLE_EN, key)
    got_key, plain, kl, cands = break_cipher(normalize(cipher))
    ok = got_key == key
    ok &= normalize(plain) == normalize(SAMPLE_EN)
    ok &= kl == len(key)
    # crib 筛选路径
    ok &= 'QUICK' in normalize(plain)
    print('判定密钥长度: %d (真值 %d)' % (kl, len(key)))
    print('候选长度(IC 前3): %s' % [
        '%d:%.4f' % (c[1], c[0]) for c in cands[:3]])
    print('爆破密钥: %s (真值 %s)' % (got_key, key))
    print('明文前 60 字符: %s...' % plain[:60])
    print('[%s] vigenere_brute.py 自测' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='维吉尼亚密钥爆破(IC+卡方)')
    ap.add_argument('file', nargs='?', help='密文文件')
    ap.add_argument('-c', '--cipher', help='命令行密文')
    ap.add_argument('--keylen', type=int, help='已知密钥长度(跳过自动判定)')
    ap.add_argument('--maxlen', type=int, default=16, help='自动判定最大长度(默认16)')
    ap.add_argument('--crib', help='明文片段筛选(命中才打印)')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()

    if args.cipher:
        raw = args.cipher
    elif args.file:
        with open(args.file, 'r', encoding='utf-8', errors='replace') as f:
            raw = f.read()
    else:
        print('用法: python vigenere_brute.py cipher.txt | -c "密文" [--keylen N --crib flag{]')
        print('      python vigenere_brute.py --selftest')
        return 1

    cipher = normalize(raw)
    if len(cipher) < 40:
        print('[!] 密文太短(%d 字母), 频率分析不可靠; 建议先手动试 --keylen' % len(cipher))
    key, plain, kl, cands = break_cipher(cipher, args.keylen, args.maxlen)
    print('判定密钥长度: %d' % kl)
    print('长度候选(IC 排序前5): %s' % ['%d:%.4f' % (c[1], c[0]) for c in cands[:5]])
    print('密钥: %s' % key)
    print('明文(归一化): %s' % (plain if len(plain) <= 400 else plain[:400] + '...'))
    if args.crib and args.crib.upper() not in plain:
        print('[!] 明文中没有出现 %r, 试其他候选长度:' % args.crib)
        for _, cand_kl in [(0, c[1]) for c in cands[:5]]:
            k2, p2, _, _ = break_cipher(cipher, cand_kl)
            if args.crib.upper() in p2:
                print('    长度 %d -> 密钥 %s -> %s...' % (cand_kl, k2, p2[:80]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
