# -*- coding: utf-8 -*-
"""audio_morse 音频摩斯码解析(wav)

用途: Misc 音频题——wav 中以音调长短携带摩斯码(常见 600~1000Hz 单音), 解出明文。
实现: 纯标准库 wave, 按窗口 RMS 提取通/断时长 -> 点/划 -> 摩斯表 -> 明文。

用法:
    python audio_morse.py secret.wav                  # 解码输出明文
    python audio_morse.py secret.wav --unit 0.06      # 指定单位时长(点=1单位, 秒)
    python audio_morse.py secret.wav --freq 800       # 只统计中心频率附近能量(可选, 快速判定)
    python audio_morse.py                             # 自测(生成含SOS的wav并解码)
"""
import argparse
import math
import struct
import sys
import wave

MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
}
REVERSE = {v: k for k, v in MORSE.items()}


def read_wav(path):
    with wave.open(path, 'rb') as w:
        n_channels, sampwidth, framerate, nframes = w.getparams()[:4]
        raw = w.readframes(nframes)
    if sampwidth == 2:
        samples = [s / 32768.0 for (s,) in struct.iter_unpack('<h', raw)]
    elif sampwidth == 1:
        samples = [(b - 128) / 128.0 for b in raw]
    else:
        raise ValueError(f'不支持位深 {sampwidth * 8} bit')
    # 多声道取平均
    if n_channels > 1:
        samples = [sum(samples[i:i + n_channels]) / n_channels
                   for i in range(0, len(samples), n_channels)]
    return samples, framerate


def envelope(samples, framerate, win_sec=0.005):
    """分窗 RMS 能量。"""
    win = max(1, int(framerate * win_sec))
    env = []
    for i in range(0, len(samples) - win + 1, win):
        chunk = samples[i:i + win]
        env.append(math.sqrt(sum(x * x for x in chunk) / len(chunk)))
    return env, win / framerate


def runs(env, sec_per_win):
    """按阈值切成 on/off 游程: [(on?, 时长秒), ...]。"""
    peak = max(env)
    if peak <= 0:
        raise ValueError('静音音频')
    threshold = peak * 0.4
    out = []
    cur_on = env[0] >= threshold
    count = 1
    for v in env[1:]:
        on = v >= threshold
        if on == cur_on:
            count += 1
        else:
            out.append((cur_on, count * sec_per_win))
            cur_on, count = on, 1
    out.append((cur_on, count * sec_per_win))
    return out


def morse_from_runs(run_list, unit=None):
    """通/断游程 -> 摩斯字符串(以 ' ' 分隔字母, ' / ' 分隔单词)。
    unit 可显式指定点时长(秒); 缺省取最短通游程自动判定。"""
    on_durs = [d for on, d in run_list if on]
    if not on_durs:
        return ''
    if unit is None:
        unit = min(on_durs)      # 点时长 = 最短通
    letters, cur = [], ''
    for on, d in run_list:
        n = d / unit
        if on:
            cur += '.' if n < 2.5 else '-'
        else:
            if n >= 5:
                if cur:
                    letters.append(cur)
                    cur = ''
                letters.append('/')      # 词间
            elif n >= 1.8 and cur:
                letters.append(cur)
                cur = ''
    if cur:
        letters.append(cur)
    return ' '.join(letters)


def morse_to_text(morse):
    words = morse.split(' / ')
    out = []
    for w in words:
        out.append(''.join(MORSE.get(tok, '?') for tok in w.split() if tok))
    return ' '.join(out)


def decode_file(path, unit_hint=None):
    samples, rate = read_wav(path)
    env, sec_per_win = envelope(samples, rate)
    run_list = runs(env, sec_per_win)
    if unit_hint:
        # 原版先按 unit_hint 缩放时长, morse_from_runs 内部又用 min() 归一化,
        # 两者抵消导致 --unit 完全无效; 改为直接把单位传入切分函数
        morse = morse_from_runs(run_list, unit=unit_hint)
    else:
        morse = morse_from_runs(run_list)
    return morse, morse_to_text(morse)


# ---------- 自测用: 生成摩斯 wav ----------
def make_test_wav(path, text='SOS', freq=800, unit=0.06, rate=8000):
    tokens = []
    for c in text:
        if c == ' ':
            tokens.append('/')          # 词间
        elif c in REVERSE:
            tokens.append(REVERSE[c])
    samples = []
    for tok in tokens:
        if tok == '/':
            samples += [0.0] * int(rate * 7 * unit)
            continue
        for j, sym in enumerate(tok):
            n = int(rate * (unit if sym == '.' else 3 * unit))
            samples += [0.6 * math.sin(2 * math.pi * freq * i / rate) for i in range(n)]
            gap = unit if j < len(tok) - 1 else 3 * unit
            samples += [0.0] * int(rate * gap)
    with wave.open(path, 'wb') as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b''.join(struct.pack('<h', int(s * 32767)) for s in samples))


def main():
    ap = argparse.ArgumentParser(description='音频摩斯码解析')
    ap.add_argument('file', nargs='?', help='wav 文件')
    ap.add_argument('--unit', type=float, help='单位时长(秒), 自动判定失准再指定')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        import os
        make_test_wav('_test_morse.wav', 'SOS SOS')
        morse, text = decode_file('_test_morse.wav')
        good = text == 'SOS SOS'
        print(f"[{'OK' if good else 'FAIL'}] 解码: morse={morse!r} -> {text!r}")
        make_test_wav('_test_morse2.wav', 'FLAG2026')
        _, text2 = decode_file('_test_morse2.wav')
        good2 = text2.replace(' ', '') == 'FLAG2026'
        print(f"[{'OK' if good2 else 'FAIL'}] 解码: {text2!r}")
        os.remove('_test_morse.wav')
        os.remove('_test_morse2.wav')
        sys.exit(0 if (good and good2) else 1)

    if not args.file:
        ap.error('需要 wav 文件(或 --selftest)')
    morse, text = decode_file(args.file, args.unit)
    print('摩斯 :', morse)
    print('明文 :', text)


if __name__ == '__main__':
    main()
