# -*- coding: utf-8 -*-
"""AES 加解密通用模板(补充题型: Crypto/对称加密)

用途:
    CTF 常见 AES(ECB/CBC, PKCS7) 加解密; 密文自动识别 hex / base64。

依赖:
    pip install pycryptodome

用法:
    python aes_template.py                     # 自测(内置回环用例)
    python aes_template.py -m ecb -a d -k 00112233445566778899aabbccddeeff -c "<hex或b64>"
    python aes_template.py -m cbc -a e -k mykey123 -i 16bytesIV1234 --text "hello"
参数:
    -m 模式: ecb / cbc(默认 ecb, cbc 需 -i)
    -a 动作: e=加密 d=解密(默认 d)
    -k 密钥: 字符串或 hex(自动判断, 16/24/32 字节)
    -i IV:   CBC 模式的初始向量, 同样自动判断
    -c 密文/明文: 省略时从 --text 取
"""
import argparse
import base64
import binascii
import re
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print('缺少依赖: pip install pycryptodome')
    sys.exit(2)

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$', re.IGNORECASE)


def _auto_decode(data: str) -> bytes:
    """字符串自动转 bytes: 优先按 hex 解, 失败再按 base64, 最后按 utf-8。"""
    data = data.strip()
    if _HEX_RE.fullmatch(data) and len(data) % 2 == 0:
        try:
            return binascii.unhexlify(data)
        except (binascii.Error, ValueError):
            pass
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return data.encode('utf-8')


def _make_key(key: str) -> bytes:
    # 纯 hex 串优先按 hex 解: 否则 32 字符 hex(= AES-128 的 16 字节密钥,
    # 见文档示例 -k 00112233..eeff)会被当成 32 字节 ASCII 口令用作 AES-256
    ks = key.strip()
    if _HEX_RE.fullmatch(ks) and len(ks) % 2 == 0:
        try:
            b = binascii.unhexlify(ks)
            if len(b) in (16, 24, 32):
                return b
        except (binascii.Error, ValueError):
            pass
    raw = key.encode('utf-8')
    if len(raw) in (16, 24, 32):
        return raw
    b = _auto_decode(key)
    if len(b) in (16, 24, 32):
        return b
    raise ValueError(f'密钥长度 {len(raw)} 字节不合法, 需要 16/24/32 (AES-128/192/256)')


def aes_decrypt(mode: str, key: bytes, data: bytes, iv: bytes = b'') -> bytes:
    if mode == 'ecb':
        pt = AES.new(key, AES.MODE_ECB).decrypt(data)
    else:
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    try:
        return unpad(pt, AES.block_size)
    except ValueError:
        return pt  # 无标准填充时返回原文


def aes_encrypt(mode: str, key: bytes, data: bytes, iv: bytes = b'') -> bytes:
    data = pad(data, AES.block_size)
    if mode == 'ecb':
        return AES.new(key, AES.MODE_ECB).encrypt(data)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def main():
    ap = argparse.ArgumentParser(description='AES ECB/CBC 加解密模板')
    ap.add_argument('-m', '--mode', choices=['ecb', 'cbc'], default='ecb')
    ap.add_argument('-a', '--action', choices=['e', 'd'], default='d')
    ap.add_argument('-k', '--key', required=True)
    ap.add_argument('-i', '--iv', default='')
    ap.add_argument('-c', '--ciphertext', default='')
    ap.add_argument('--text', default='', help='加密时的明文')
    args = ap.parse_args()

    key = _make_key(args.key)
    iv = _auto_decode(args.iv) if args.iv else b''
    if args.mode == 'cbc' and len(iv) != 16:
        ap.error('CBC 模式需要 16 字节 IV (-i)')

    if args.action == 'e':
        data = (args.text or args.ciphertext).encode('utf-8')
        out = aes_encrypt(args.mode, key, data, iv)
        print('hex    :', out.hex())
        print('base64 :', base64.b64encode(out).decode())
    else:
        if not args.ciphertext:
            ap.error('解密需要 -c 提供密文')
        data = _auto_decode(args.ciphertext)
        print(aes_decrypt(args.mode, key, data, iv).decode('utf-8', errors='replace'))
    return


if __name__ == '__main__':
    # 先自测: 无参数时跑回环用例; 带参数走命令行
    if len(sys.argv) == 1:
        ok = True
        key = b'0123456789abcdef'
        iv = b'0102030405060708'
        msg = b'flag{aes_ctr_not_used}'
        for mode, ivv in [('ecb', b''), ('cbc', iv)]:
            ct = aes_encrypt(mode, key, msg, ivv)
            back = aes_decrypt(mode, key, ct, ivv)
            good = back == msg
            ok &= good
            print(f"[{'OK' if good else 'FAIL'}] AES-{mode.upper()}: {ct.hex()} -> {back!r}")
        # hex/base64 自动识别
        ct = aes_encrypt('ecb', key, msg)
        back = aes_decrypt('ecb', key, _auto_decode(base64.b64encode(ct).decode()))
        good = back == msg
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] base64 密文自动识别: -> {back!r}")
        sys.exit(0 if ok else 1)
    main()
