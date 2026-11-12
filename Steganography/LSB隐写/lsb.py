# -*- coding: utf-8 -*-
"""PNG LSB 隐写 嵌入/提取(补充题型: Misc/图片隐写)

用途:
    按 R,G,B 每像素最低位逐位嵌入/提取数据(行优先)。数据以 4 字节长度头 + 内容 存储。
    适合两种场景:
      1) 题目让隐藏文本, 直接 -e/-x 提取
      2) 题目给多张小图拼位图(每图 1bit), 用 -m auto 试试整图提取

用法:
    python lsb.py -e cover.png "flag{lsb_steg}" -o out.png    # 嵌入
    python lsb.py -x out.png                                   # 提取文本
    python lsb.py -x stego.png -b payload.bin                  # 提取为文件
    python lsb.py                                              # 自测
"""
import argparse
import struct
import sys


def _iter_pixels(img):
    """逐像素产出 (x, y)。"""
    w, h = img.size
    for y in range(h):
        for x in range(w):
            yield x, y


def embed_image(img, data: bytes):
    """把 data 嵌入 PIL Image 的 LSB, 返回新 Image(需 RGB)。"""
    img = img.convert('RGB')
    w, h = img.size
    capacity = w * h * 3  # bit 数
    payload = struct.pack('>I', len(data)) + data
    need = len(payload) * 8
    if need > capacity:
        raise ValueError(f'容量不足: 需要 {need} bit, 只有 {capacity} bit '
                         f'(图片至少需要 {need // 3 // (w or 1) + 1} 行)')
    bits = ''.join(f'{b:08b}' for b in payload)
    px = img.load()
    idx = 0
    for x, y in _iter_pixels(img):
        r, g, b = px[x, y]
        if idx < len(bits):
            r = (r & 0xFE) | int(bits[idx]); idx += 1
        if idx < len(bits):
            g = (g & 0xFE) | int(bits[idx]); idx += 1
        if idx < len(bits):
            b = (b & 0xFE) | int(bits[idx]); idx += 1
        px[x, y] = (r, g, b)
        if idx >= len(bits):
            break
    return img


def extract_image(img) -> bytes:
    img = img.convert('RGB')
    px = img.load()
    w, h = img.size
    bits = []
    length = None
    for x, y in _iter_pixels(img):
        r, g, b = px[x, y]
        bits.extend([r & 1, g & 1, b & 1])
        if length is None and len(bits) >= 32:
            length = struct.unpack('>I', bytes(
                int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, 32, 8)))[0]
            if length == 0:
                return b''
            need = 32 + length * 8
            if need > w * h * 3:
                raise ValueError('长度头非法(超出容量), 可能不是本工具嵌入的数据')
        if length is not None and len(bits) >= 32 + length * 8:
            break
    total = ''.join(map(str, bits))
    body = total[32:32 + length * 8]
    return bytes(int(body[i:i + 8], 2) for i in range(0, len(body), 8))


def main():
    ap = argparse.ArgumentParser(description='PNG LSB 隐写')
    ap.add_argument('-e', '--embed', nargs=2, metavar=('IMG', 'TEXT'))
    ap.add_argument('-x', '--extract', metavar='IMG')
    ap.add_argument('-o', '--out', metavar='OUT', help='嵌入输出路径')
    ap.add_argument('-b', '--binary', metavar='FILE', help='提取内容写入文件')
    args = ap.parse_args()

    try:
        from PIL import Image
    except ImportError:
        print('缺少依赖: pip install pillow')
        sys.exit(2)

    if args.embed:
        img_path, text = args.embed
        img = Image.open(img_path)
        out = embed_image(img, text.encode('utf-8'))
        out_path = args.out or 'lsb_out.png'
        out.save(out_path, 'PNG')
        print('已嵌入', len(text), '字节 ->', out_path)
    elif args.extract:
        data = extract_image(Image.open(args.extract))
        if args.binary:
            with open(args.binary, 'wb') as f:
                f.write(data)
            print(f'已提取 {len(data)} 字节 -> {args.binary}')
        else:
            print(data.decode('utf-8', errors='replace'))
    else:
        # 自测
        ok = True
        img = Image.new('RGB', (64, 64))
        msg = 'flag{lsb_1s_b4sic}'
        stego = embed_image(img, msg.encode())
        got = extract_image(stego).decode()
        good = got == msg
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] 回环: {got!r}")
        # 大小写无关: 保存为 PNG 再读回(PNG 无损, 应保持)
        import io
        buf = io.BytesIO()
        stego.save(buf, 'PNG')
        got2 = extract_image(Image.open(buf)).decode()
        good2 = got2 == msg
        ok &= good2
        print(f"[{'OK' if good2 else 'FAIL'}] PNG 存取后提取: {got2!r}")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
