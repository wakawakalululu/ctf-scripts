# -*- coding: utf-8 -*-
"""audio_spectrogram.py — WAV 音频转频谱图(音频隐写高频题型)

用途: 读 WAV(16bit PCM, 标准库 wave)分帧做 FFT, 输出频谱图 PNG;
      音频里把 flag 画进频谱是常见出题套路, 看图即可读出内容。
      支持 --peak 报告能量最高频率, 方便定位"频率隐写"(如 19kHz 附近)。

依赖:
    pip install numpy pillow

用法:
    python audio_spectrogram.py sound.wav                  # 生成 sound_spec.png
    python audio_spectrogram.py sound.wav -o spec.png      # 指定输出
    python audio_spectrogram.py sound.wav --peak           # 附带主峰频率分析
    python audio_spectrogram.py --selftest                 # 内置自测
"""
import argparse
import os
import struct
import sys
import wave

import numpy as np
from PIL import Image

NFFT = 1024
HOP = 256


def read_wav(path):
    w = wave.open(path, 'rb')
    nch, rate, n = w.getnchannels(), w.getframerate(), w.getnframes()
    raw = w.readframes(n)
    w.close()
    data = np.array(struct.unpack('<%dh' % (n * nch), raw), dtype=np.float32)
    if nch > 1:
        data = data.reshape(-1, nch).mean(axis=1)
    return data, rate


def spectrogram(data, rate):
    n_frames = max(1, (len(data) - NFFT) // HOP + 1)
    mag = np.zeros((n_frames, NFFT // 2 + 1), dtype=np.float32)  # rfft 有 NFFT/2+1 个频点
    win = np.hanning(NFFT)
    for i in range(n_frames):
        seg = data[i * HOP:i * HOP + NFFT]
        if len(seg) < NFFT:
            seg = np.pad(seg, (0, NFFT - len(seg)))
        spec = np.abs(np.fft.rfft(seg * win))
        mag[i] = 20 * np.log10(spec + 1e-9)
    # 归一化 0-255, 频率轴翻转(低频在下)
    mag = np.clip((mag - mag.min()) / (mag.max() - mag.min() + 1e-9) * 255, 0, 255)
    return np.flipud(mag.T).astype(np.uint8), mag, rate


def save_png(img, path):
    im = Image.fromarray(img, 'L')
    im.save(path)
    print('频谱图已保存 -> %s (%d 帧x%d 频点)' % (path, img.shape[1], img.shape[0]))


def peak_freq(raw_mag, rate):
    """每帧最响的频率(Hz)列表(必须在未翻转的幅度矩阵上取)。"""
    bin_hz = rate / NFFT
    peaks = raw_mag.argmax(axis=1) * bin_hz
    return peaks


def selftest():
    import io, tempfile
    # 合成 0.5s 440Hz 正弦 16bit 单声道
    rate = 8000
    t = np.linspace(0, 0.5, int(rate * 0.5), False)
    sig = (np.sin(2 * np.pi * 440 * t) * 20000).astype(np.int16)
    fd, wavpath = tempfile.mkstemp(suffix='.wav')
    os.close(fd)
    w = wave.open(wavpath, 'wb')
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(rate)
    w.writeframes(sig.tobytes())
    w.close()
    data, r = read_wav(wavpath)
    img, raw, _ = spectrogram(data, r)
    peaks = peak_freq(raw, r)
    main_peak = float(np.median(peaks))
    os.unlink(wavpath)
    ok = abs(main_peak - 440) < 30  # 主峰应接近 440Hz
    print('频谱图主峰定位(440Hz 合成音):',
          'OK' if ok else 'FAIL (主峰=%.1fHz)' % main_peak)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description='WAV 转频谱图')
    ap.add_argument('wav', nargs='?', help='WAV 文件')
    ap.add_argument('-o', '--output', help='输出 PNG(默认 <wav名>_spec.png)')
    ap.add_argument('--peak', action='store_true', help='输出每帧主峰频率')
    ap.add_argument('--selftest', action='store_true', help='内置自测')
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.wav:
        ap.error('需要 WAV 文件参数(或 --selftest)')
    data, rate = read_wav(args.wav)
    img, raw, _ = spectrogram(data, rate)
    out = args.output or os.path.splitext(args.wav)[0] + '_spec.png'
    save_png(img, out)
    if args.peak:
        peaks = peak_freq(raw, rate)
        print('主峰频率(Hz): %s' % np.round(peaks[::max(1, len(peaks)//20)]).astype(int))


if __name__ == '__main__':
    main()
