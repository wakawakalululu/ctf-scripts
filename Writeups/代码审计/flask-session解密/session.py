# -*- coding: utf-8 -*-
"""session.py Flask session cookie 解密(明文查看)

来源: WP 汇总/Flask 题通用辅助(与 Web/JWT伪造/jwt_forge.py 同场景)
用途: Flask 的 session cookie 只是 base64+签名, 拿到 cookie 即可**无密钥解出明文**
      (伪造才需要密钥, 伪造配合爆破见 jwt_forge.py 或 flask-unsign)。
      兼容 3 段式带时间戳 cookie 与 zlib 压缩形态。
      装了 flask 时用其完整 TaggedJSONSerializer(tuple/datetime 等标签类型可还原);
      未装 flask 时回退纯 json 解析(常规 dict session 足够)。

依赖:
    pip install itsdangerous     # 必需
    pip install flask            # 可选: 支持标签类型完整还原

用法:
    python session.py --selftest                          # 自测(本地造 cookie 再解)
    python session.py "ey...jg==.ey...ok.sig"             # 位置参数传 cookie
"""
import argparse
import json
import sys
import zlib

from itsdangerous import URLSafeTimedSerializer, base64_decode

try:  # 有 flask: 用其完整 TaggedJSONSerializer
    from flask.sessions import session_json_serializer as serializer
except ImportError:  # 无 flask: 纯 json 解析兜底
    serializer = json


def decryption(payload):
    """解出 Flask session cookie 的明文 JSON(参数为 bytes)。"""
    payload, sig = payload.rsplit(b'.', 1)
    payload, timestamp = payload.rsplit(b'.', 1)

    decompress = False
    if payload.startswith(b'.'):
        payload = payload[1:]
        decompress = True

    try:
        payload = base64_decode(payload)
    except Exception:
        raise Exception('Could not base64 decode the payload because of '
                        'an exception')

    if decompress:
        try:
            payload = zlib.decompress(payload)
        except Exception:
            raise Exception('Could not zlib decompress the payload before '
                            'decoding the payload')

    return serializer.loads(payload)


def selftest():
    """本地用 URLSafeTimedSerializer 造一个 cookie, 解密后比对。"""
    ok = True
    s = URLSafeTimedSerializer('test-secret')
    cookie = s.dumps({'username': 'admin', 'is_admin': True})
    got = decryption(cookie.encode())
    ok &= (got == {'username': 'admin', 'is_admin': True})
    # 压缩形态
    cookie2 = s.dumps({'a': 'x' * 300})
    ok &= (decryption(cookie2.encode()) == {'a': 'x' * 300})
    print('decoded : %r' % (got,))
    print('[%s] session.py 自测' % ('OK' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='Flask session cookie 明文解密')
    ap.add_argument('--selftest', action='store_true', help='运行内置自测')
    ap.add_argument('cookie', nargs='?', help='Flask session cookie 字符串')
    args = ap.parse_args()

    if getattr(sys.stdout, 'reconfigure', None):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if args.selftest:
        return selftest()
    if not args.cookie:
        ap.error('请提供 cookie, 或使用 --selftest')
    print(decryption(args.cookie.encode()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
