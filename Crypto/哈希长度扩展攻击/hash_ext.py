# -*- coding: utf-8 -*-
"""hash_ext 哈希长度扩展攻击(md5/sha1)

参考: https://github.com/iagox86/hash_extender (hashpumpy 的纯 py3 实现)
用途: Web/Crypto 题形如 sig = md5(SECRET + data), 已知 sig/data/SECRET长度,
      追加任意内容并伪造出新签名, 无需知道 SECRET。

用法:
    python hash_ext.py --selftest                       # 自测
    python hash_ext.py -f md5 -d "?user=guest" -s <sig> -a "&user=admin" --list 8,20,32
    python hash_ext.py -f sha1 -d "..." -s <sig> -a "..." -l 16
    成功后把 tail 附加到原 data 后提交(通常需 URL 编码 %00%00..)。
"""
import argparse
import hashlib
import math
import struct
import sys

# ---------------- MD5 核心 ----------------
_MD5_K = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]
_MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
_MD5_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]


def _rotl(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def _pad_md5(msg_len):
    out = b'\x80'
    out += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    out += struct.pack('<Q', msg_len * 8)
    return out


def md5_compress(state, block):
    a0, b0, c0, d0 = state
    M = struct.unpack('<16I', block)
    A, B, C, D = a0, b0, c0, d0
    for i in range(64):
        if i < 16:
            F, g = (B & C) | (~B & D & 0xFFFFFFFF), i
        elif i < 32:
            F, g = (D & B) | (~D & C & 0xFFFFFFFF), (5 * i + 1) % 16
        elif i < 48:
            F, g = B ^ C ^ D, (3 * i + 5) % 16
        else:
            F, g = C ^ (B | (~D & 0xFFFFFFFF)), (7 * i) % 16
        F = (F + A + _MD5_K[i] + M[g]) & 0xFFFFFFFF
        A, D, C = D, C, B
        B = (B + _rotl(F, _MD5_S[i])) & 0xFFFFFFFF
    return [(a0 + A) & 0xFFFFFFFF, (b0 + B) & 0xFFFFFFFF,
            (c0 + C) & 0xFFFFFFFF, (d0 + D) & 0xFFFFFFFF]


def md5_full(data: bytes) -> bytes:
    state = list(_MD5_IV)
    padded = data + _pad_md5(len(data))
    for i in range(0, len(padded), 64):
        state = md5_compress(state, padded[i:i + 64])
    return struct.pack('<4I', *state)


# ---------------- SHA1 核心 ----------------
_SHA1_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]


def _pad_sha1(msg_len):
    out = b'\x80'
    out += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    out += struct.pack('>Q', msg_len * 8)
    return out


def sha1_compress(state, block):
    w = list(struct.unpack('>16I', block))
    for t in range(16, 80):
        w.append(_rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))
    a, b, c, d, e = state
    for t in range(80):
        if t < 20:
            f = (b & c) | ((~b & 0xFFFFFFFF) & d)
            k = 0x5A827999
        elif t < 40:
            f, k = b ^ c ^ d, 0x6ED9EBA1
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f, k = b ^ c ^ d, 0xCA62C1D6
        tmp = (_rotl(a, 5) + f + e + k + w[t]) & 0xFFFFFFFF
        a, b, c, d, e = tmp, a, _rotl(b, 30), c, d
    return [(s + v) & 0xFFFFFFFF for s, v in zip(state, [a, b, c, d, e])]


def sha1_full(data: bytes) -> bytes:
    state = list(_SHA1_IV)
    padded = data + _pad_sha1(len(data))
    for i in range(0, len(padded), 64):
        state = sha1_compress(state, padded[i:i + 64])
    return struct.pack('>5I', *state)


FUNCS = {
    'md5': (md5_full, md5_compress, _pad_md5, _MD5_IV, '<4I', 4),
    'sha1': (sha1_full, sha1_compress, _pad_sha1, _SHA1_IV, '>5I', 5),
}


def extend(func_name: str, digest_hex: str, append: bytes,
           secret_len: int, orig_len: int):
    """返回 (新签名hex, 附加到原data之后的 tail 字节)。

    digest 对应 state = 已压缩完 (secret||data) 的原补齐块;
    glue = 对 (secret||data) 总长度的补齐; 新消息续压 append + 终填充。
    """
    _, compress, pad, _, word_fmt, _ = FUNCS[func_name]
    digest = bytes.fromhex(digest_hex)
    state = list(struct.unpack(word_fmt, digest))
    glue = pad(secret_len + orig_len)
    base_len = secret_len + orig_len + len(glue) + len(append)
    suffix = append + pad(base_len)
    for i in range(0, len(suffix), 64):
        state = compress(state, suffix[i:i + 64])
    return struct.pack(word_fmt, *state).hex(), glue + append


def main():
    ap = argparse.ArgumentParser(description='哈希长度扩展攻击(md5/sha1)')
    ap.add_argument('-f', '--func', choices=['md5', 'sha1'], default='md5')
    ap.add_argument('-d', '--data', default='', help='已知的 data(不带secret)')
    ap.add_argument('-s', '--sig', default='', help='已知的 md5(secret+data) 签名hex')
    ap.add_argument('-a', '--append', default='', help='要追加的内容')
    ap.add_argument('-l', '--secret-len', type=int, help='SECRET 字节长度(已知时)')
    ap.add_argument('--list', default='1,2,3,4,6,8,10,12,16,20,24,32,48,64',
                    help='未知长度时依次尝试的列表')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        ok = True
        # 核心正确性
        for name, full in (('md5', md5_full), ('sha1', sha1_full)):
            ref = hashlib.new(name)
            ref.update(b'abc')
            mine = full(b'abc')
            good = mine == ref.digest()
            ok &= good
            print(f"[{'OK' if good else 'FAIL'}] {name} 核心 vs hashlib: {mine.hex()}")
            for data in (b'', b'A' * 55, b'B' * 56, b'C' * 64, b'D' * 200):
                ref = hashlib.new(name)
                ref.update(data)
                if full(data) != ref.digest():
                    ok = False
                    print(f"[FAIL] {name} 长度 {len(data)}")
                    break
        # 攻击正确性: 与真实 md5(secret+data+tail) 对照
        secret = b'SUPER_SECRET_KEY!!'      # len = 18
        data = b'?user=guest'
        sig = hashlib.md5(secret + data).hexdigest()
        append = b'&user=admin&debug=1'
        new_sig, tail = extend('md5', sig, append, len(secret), len(data))
        truth = hashlib.md5(secret + data + tail).hexdigest()
        good2 = new_sig == truth
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] md5 扩展伪造命中: {new_sig}")
        sig1 = hashlib.sha1(secret + data).hexdigest()
        new_sig1, tail1 = extend('sha1', sig1, append, len(secret), len(data))
        truth1 = hashlib.sha1(secret + data + tail1).hexdigest()
        good3 = new_sig1 == truth1
        ok &= good3
        print(f"[{'OK' if good3 else 'FAIL'}] sha1 扩展伪造命中: {new_sig1}")
        sys.exit(0 if ok else 1)

    full, _, _, _, _, _ = FUNCS[args.func]
    if not (args.data and args.sig and args.append):
        ap.error('-d/-s/-a 为实战模式必填(自测用 --selftest)')
    data_bytes = args.data.encode()
    appends = args.append.encode()
    lens = [args.secret_len] if args.secret_len else [int(x) for x in args.list.split(',')]
    for sl in lens:
        try:
            new_sig, tail = extend(args.func, args.sig, appends, sl, len(data_bytes))
        except Exception as e:
            print(f'secret_len={sl}: 失败 {e}')
            continue
        print(f'secret_len={sl}')
        print('  sig  =', new_sig)
        print('  tail =', tail.hex())
        print('  data 提交格式: <原data> + tail (URL编码后拼接)')


if __name__ == '__main__':
    main()
