# -*- coding: utf-8 -*-
"""hash_identify.py — 哈希类型识别 + hashcat/john 破解命令速查(通用工具)

识别: 按长度(32=MD5/NTLM, 40=SHA1, 56=SHA224, 64=SHA256, 96=SHA384,
      128=SHA512)与 $xxx$ 前缀(bcrypt/sha512crypt/md5crypt 等)给出候选,
      并输出 hashcat 模式号与 john 格式名; 支持 --dict 用字典快速爆破
      MD5/SHA 系列, 支持批量识别。

用法:
    python hash_identify.py e10adc3949ba59abbe56e057f20f883e
    python hash_identify.py hashes.txt --batch     # 批量识别
    python hash_identify.py <hash> --dict wordlist.txt   # 字典爆破
    python hash_identify.py --selftest             # 内置自测
"""
import argparse
import hashlib
import sys

BY_LEN = {
    32: [('MD5', '0', 'raw-md5'), ('NTLM', '1000', 'nt'), ('MD4', '900', 'md4')],
    40: [('SHA1', '100', 'raw-sha1'), ('MySQL5', '200', 'mysql-sha1')],
    56: [('SHA224', '1300', 'raw-sha224')],
    64: [('SHA256', '1400', 'raw-sha256'), ('SHA3-256', '16600', 'raw-sha3-256')],
    96: [('SHA384', '10800', 'raw-sha384')],
    128: [('SHA512', '1700', 'raw-sha512'), ('Whirlpool', '6100', 'whirlpool')],
}
BY_PREFIX = {
    '$2': ('bcrypt', '3200', 'bcrypt'),
    '$6$': ('sha512crypt', '1800', 'sha512crypt'),
    '$5$': ('sha256crypt', '7400', 'sha256crypt'),
    '$1$': ('md5crypt', '500', 'md5crypt'),
    '$apr1$': ('Apache md5crypt', '500', 'md5crypt'),
    '$argon2': ('Argon2', '16000', 'argon2 (john: Argon2)'),
    '$pbkdf2': ('PBKDF2', '12000', 'pbkdf2-hmac-sha256'),
    '$NT$': ('NTLM', '1000', 'nt'),
    '$P$': ('phpass', '400', 'phpass'),
}
FAST = {  # --dict 可直接爆破的类型
    'MD5': hashlib.md5, 'SHA1': hashlib.sha1, 'SHA224': hashlib.sha224,
    'SHA256': hashlib.sha256, 'SHA384': hashlib.sha384, 'SHA512': hashlib.sha512,
}


def identify(h):
    h = h.strip()
    cands = []
    if h.startswith('$'):
        for pref, info in BY_PREFIX.items():
            if h.startswith(pref):
                cands.append(info)
        parts = h.split('$')
        if not cands and len(parts) > 1 and '$%s$' % parts[1] in BY_PREFIX:
            cands.append(BY_PREFIX['$%s$' % parts[1]])
    if not cands and len(h) in BY_LEN and all(c in '0123456789abcdefABCDEF' for c in h):
        cands = BY_LEN[len(h)]
    return cands


def dict_crack(h, dict_path):
    fn = None
    for name, f in FAST.items():
        if name in [c[0] for c in identify(h)]:
            fn = f
            break
    if fn is None:
        print('该类型不支持内置字典爆破, 请用 hashcat/john')
        return False
    for line in open(dict_path, 'rb'):
        w = line.strip()
        if fn(w).hexdigest() == h.lower():
            print('[+] 命中: %s' % w.decode('utf-8', 'replace'))
            return True
    print('[-] 字典未命中')
    return False


def selftest():
    ok1 = any(c[0] == 'MD5' for c in identify('d41d8cd98f00b204e9800998ecf8427e'))
    ok2 = any(c[0] == 'SHA256' for c in identify('A' * 64))
    ok3 = any('bcrypt' in c[0] for c in identify('$2b$12$' + 'x' * 53))
    import tempfile, os
    tf = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
    tf.write(b'password123\nother\n')
    tf.close()
    hit = dict_crack(hashlib.md5(b'password123').hexdigest(), tf.name)
    os.unlink(tf.name)
    ok = ok1 and ok2 and ok3 and hit
    print('哈希识别/字典爆破:', 'OK' if ok else 'FAIL (%r %r %r %r)' % (ok1, ok2, ok3, hit))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='哈希类型识别与破解速查')
    ap.add_argument('hash', nargs='?', help='哈希值')
    ap.add_argument('--batch', action='store_true', help='按文件批量识别')
    ap.add_argument('--dict', help='字典文件(配合 --dict 爆破 MD5/SHA 系列)')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.hash:
        ap.error('需要哈希参数(或 --selftest)')
    if args.dict:
        sys.exit(0 if dict_crack(args.hash, args.dict) else 1)
    lines = open(args.hash, encoding='utf-8', errors='replace').read().splitlines() if args.batch else [args.hash]
    for line in lines:
        if not line.strip():
            continue
        cands = identify(line)
        if not cands:
            print('%-20s  [?] 未知类型' % line[:20])
            continue
        for name, mode, jf in cands:
            print('%-20s  %s  hashcat -m %s  john --format=%s' %
                  (line[:20], name, mode, jf))


if __name__ == '__main__':
    main()
