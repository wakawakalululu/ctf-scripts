# SCRIPTS-INDEX — 全量脚本索引

> 由 `gen_index.py` 自动生成, 覆盖仓库内**每一个 .py 脚本**(共 195 个)。新增/修改脚本后运行 `python gen_index.py` 刷新本文件; `python gen_index.py --check` 可校验是否过期。
>
> 说明列取自脚本模块 docstring 首行; “(老脚本) 目录名”表示早期收集的无 docstring 脚本, 按目录题型理解, 用法见 README 对应分类表或脚本内注释。
> 依赖列只列**第三方包**(安装: `pip install -r requirements.txt`, 环境自检: `python check_env.py`)。

## 目录

- [Crypto — 密码学 (53)](#crypto--密码学-53)
- [Encoding — 编码转换 (31)](#encoding--编码转换-31)
- [Steganography — 隐写 (19)](#steganography--隐写-19)
- [TrafficeAnalysis — 流量分析 (24)](#trafficeanalysis--流量分析-24)
- [LogAnalysis — 日志分析 (3)](#loganalysis--日志分析-3)
- [Web — Web 安全 (13)](#web--web-安全-13)
- [Pwn — 二进制漏洞利用 (6)](#pwn--二进制漏洞利用-6)
- [Reverse — 逆向 (7)](#reverse--逆向-7)
- [Misc — 杂项 (26)](#misc--杂项-26)
- [Writeups — WP 实战做题脚本 (11)](#writeups--wp-实战做题脚本-11)
- [仓库工具(根目录) (2)](#仓库工具根目录-2)

## Crypto — 密码学 (53)

> 密码学:RSA 全家桶 / 古典密码 / 对称加密 / 哈希

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `26键盘密码-手机键盘密码/jianpan.py` | (老脚本) 26键盘密码-手机键盘密码 | — | — | 17 |
| `AES加解密模板/aes_template.py` | AES 加解密通用模板(补充题型: Crypto/对称加密) | pycryptodome | — | 138 |
| `DES_Python-master/des.py` | (老脚本) DES_Python-master | — | — | 207 |
| `DES_Python-master/des_1.py` | (老脚本) DES_Python-master | — | — | 248 |
| `DES_Python-master/desstruct.py` | (老脚本) DES_Python-master | — | — | 89 |
| `factordb查询/factordb.py` | factordb 在线分解 n + 本地试除兜底(补充题型: Crypto/RSA) | requests | — | 155 |
| `md5爆破/md5-brust.py` | (老脚本) md5爆破 | — | — | 14 |
| `Nihilist密码/nihilist.py` | Nihilist 密码解密 — 基于 5x5 密钥矩阵的替换密码(py3 移植版) | — | — | 24 |
| `rot/rot.py` | (老脚本) rot | — | — | 13 |
| `RSA综合脚本利用/e=3 (小公钥指数攻击) (小明文攻击) (tereotyped messages攻击)/rsa1.py` | (老脚本) e=3 (小公钥指数攻击) (小明文攻击) (tereotyped messages攻击) | gmpy2, libnum | — | 17 |
| `RSA综合脚本利用/共模攻击+base64隐写/exp.py` | (老脚本) 共模攻击+base64隐写 | gmpy2, libnum, pycryptodome | — | 59 |
| `RSA综合脚本利用/已知 c1、c2、n1、n2、e的范围 (同公钥（e，n）加密的密文、具有同 q 的公钥加密的密文)/exp1-py2.py` | (老脚本) 已知 c1、c2、n1、n2、e的范围 (同公钥（e，n）加密的密文、具有同 q 的公钥加密的密文) | gmpy2, pycryptodome | — | 27 |
| `RSA综合脚本利用/已知 c1、c2、n1、n2、e的范围 (同公钥（e，n）加密的密文、具有同 q 的公钥加密的密文)/exp2-py3.py` | (老脚本) 已知 c1、c2、n1、n2、e的范围 (同公钥（e，n）加密的密文、具有同 q 的公钥加密的密文) | gmpy2, pycryptodome | — | 42 |
| `RSA综合脚本利用/已知 e1、e2、n (共模攻击) (模不互质)/exp2.py` | (老脚本) 已知 e1、e2、n (共模攻击) (模不互质) | gmpy2, libnum | — | 18 |
| `RSA综合脚本利用/已知 e1、e2、n (共模攻击) (模不互质)/exp3.py` | (老脚本) 已知 e1、e2、n (共模攻击) (模不互质) | gmpy2 | — | 34 |
| `RSA综合脚本利用/已知 e1、e2、n (共模攻击) (模不互质)/rsa.py` | (老脚本) 已知 e1、e2、n (共模攻击) (模不互质) | gmpy2 | — | 31 |
| `RSA综合脚本利用/已知 e、d、c ,求 m/exp.py` | (老脚本) 已知 e、d、c ,求 m | gmpy2, libnum, sympy | — | 29 |
| `RSA综合脚本利用/已知 e、d、p+q、(p+1)(q+1)、以及密文C，求明文m/hello.py` | (老脚本) 已知 e、d、p+q、(p+1)(q+1)、以及密文C，求明文m | libnum | — | 12 |
| `RSA综合脚本利用/已知 e、m1、m2、n、pq 接近 ,求原 m/exp.py` | (老脚本) 已知 e、m1、m2、n、pq 接近 ,求原 m | gmpy2, pycryptodome, sympy | — | 28 |
| `RSA综合脚本利用/已知 e、n、c,求导得 pq 解 m/exp.py` | (老脚本) 已知 e、n、c,求导得 pq 解 m | gmpy2 | — | 17 |
| `RSA综合脚本利用/已知 e、n、c,由威尔逊定理得 pq 解 m/exp.py` | (老脚本) 已知 e、n、c,由威尔逊定理得 pq 解 m | gmpy2, libnum, pycryptodome, sympy | — | 36 |
| `RSA综合脚本利用/已知 e、n、密文 c，求明文 m/hello.py` | (老脚本) 已知 e、n、密文 c，求明文 m | gmpy2, pycryptodome | — | 23 |
| `RSA综合脚本利用/已知 e、n、密文 c，求明文 m/hello1.py` | (老脚本) 已知 e、n、密文 c，求明文 m | gmpy2 | — | 20 |
| `RSA综合脚本利用/已知 e、n，求 d (e极大) (Wiener’s Attack)/hello.py` | (老脚本) 已知 e、n，求 d (e极大) (Wiener’s Attack) | owiener | — | 11 |
| `RSA综合脚本利用/已知 e、n，求 d (e极大) (Wiener’s Attack)/rsa-wiener-attack-master/Arithmetic.py` | Created on Dec 22, 2011 | — | — | 111 |
| `RSA综合脚本利用/已知 e、n，求 d (e极大) (Wiener’s Attack)/rsa-wiener-attack-master/ContinuedFractions.py` | Created on Dec 14, 2011 | — | — | 64 |
| `RSA综合脚本利用/已知 e、n，求 d (e极大) (Wiener’s Attack)/rsa-wiener-attack-master/hello.py` | (老脚本) rsa-wiener-attack-master | — | — | 14 |
| `RSA综合脚本利用/已知 e、n，求 d (e极大) (Wiener’s Attack)/rsa-wiener-attack-master/MillerRabin.py` | (老脚本) rsa-wiener-attack-master | — | — | 94 |
| `RSA综合脚本利用/已知 e、n，求 d (e极大) (Wiener’s Attack)/rsa-wiener-attack-master/RSAvulnerableKeyGenerator.py` | Created on Dec 14, 2011 | — | — | 95 |
| `RSA综合脚本利用/已知 e、n，求 d (e极大) (Wiener’s Attack)/rsa-wiener-attack-master/RSAwienerHacker.py` | Created on Dec 14, 2011 | — | — | 65 |
| `RSA综合脚本利用/已知 e、p、q，求 d/hello.py` | (老脚本) 已知 e、p、q，求 d | gmpy2 | — | 6 |
| `RSA综合脚本利用/已知 n、e、c、p、q 批量求 m (n 分解) (Roll 按行加密)/hello.py` | (老脚本) 已知 n、e、c、p、q 批量求 m (n 分解) (Roll 按行加密) | gmpy2 | — | 15 |
| `RSA综合脚本利用/已知 n、e、dp、c，求m (dp 泄露)/rsa.py` | (老脚本) 已知 n、e、dp、c，求m (dp 泄露) | gmpy2 | — | 27 |
| `RSA综合脚本利用/已知 public key、密文 c，求明文 m (公钥提取)/hello.py` | (老脚本) 已知 public key、密文 c，求明文 m (公钥提取) | gmpy2, rsa | — | 16 |
| `RSA综合脚本利用/已知 public key、密文 c，求明文 m (公钥提取)/rsa-base64.py` | (老脚本) 已知 public key、密文 c，求明文 m (公钥提取) | gmpy2, libnum, pycryptodome | — | 21 |
| `RSA综合脚本利用/已知 p、n、c、e的范围,求 m/brust.py` | (老脚本) 已知 p、n、c、e的范围,求 m | gmpy2, pycryptodome | — | 21 |
| `RSA综合脚本利用/已知 p、q、dp、dq、c 求明文 m (dp、dq 泄露)/hello.py` | (老脚本) 已知 p、q、dp、dq、c 求明文 m (dp、dq 泄露) | gmpy2 | — | 14 |
| `RSA综合脚本利用/已知e、p、q、密文c，求明文m/hello.py` | (老脚本) 已知e、p、q、密文c，求明文m | gmpy2, libnum, pycryptodome | — | 14 |
| `RSA综合脚本利用/已知多个 n、c (中国剩余定理)/hello.py` | (老脚本) 已知多个 n、c (中国剩余定理) | gmpy2, pycryptodome | — | 37 |
| `TEA加解密/tea_xtea.py` | tea_xtea TEA / XTEA 加解密(64位块, 128位密钥) | — | ✅ `--selftest` | 145 |
| `toy密码/toy.py` | (老脚本) toy密码 | — | — | 19 |
| `XOR自动爆破/xor_brute.py` | XOR 爆破工具(补充题型: Crypto/Reverse 通用) | — | — | 127 |
| `云影密码/yunying.py` | yunying.py — 云影密码(0/8 密码)编解码(攻防世界等平台高频 misc) | — | ✅ `--selftest` | 108 |
| `变异凯撒/encode_caesar.py` | (老脚本) 变异凯撒 | — | — | 9 |
| `变异凯撒/variant_caesar.py` | (老脚本) 变异凯撒 | — | — | 9 |
| `哈希长度扩展攻击/hash_ext.py` | hash_ext 哈希长度扩展攻击(md5/sha1) | — | ✅ `--selftest` | 196 |
| `四方密码/sifang.py` | (老脚本) 四方密码 | — | — | 65 |
| `培根密码/bacon.py` | 培根密码(Bacon Cipher) 加解密(补充题型: Crypto/古典密码) | — | — | 143 |
| `常用反解密脚本/cryp-1.py` | (老脚本) 常用反解密脚本 | — | — | 8 |
| `摩斯密码/morse.py` | 摩斯密码 加解密脚本(补充题型: Crypto/编码) | — | — | 128 |
| `栅栏密码/railfence.py` | 栅栏密码(Rail Fence Cipher) 加解密与爆破(补充题型: Crypto/古典密码) | — | — | 128 |
| `维吉尼亚加密/exp.py` | (老脚本) 维吉尼亚加密 | — | — | 11 |
| `维吉尼亚密钥爆破/vigenere_brute.py` | vigenere_brute.py — 维吉尼亚密码密钥爆破(重合指数 + 卡方频率分析) | — | ✅ `--selftest` | 183 |

## Encoding — 编码转换 (31)

> 编码转换:Base 系列 / hex / 二进制 / 字符统计

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `Base/b16-b32-b64-b85/1.py` | (老脚本) b16-b32-b64-b85 | — | — | 56 |
| `Base/B64-B32-B16解密/basedecode.py` | (老脚本) B64-B32-B16解密 | — | — | 18 |
| `Base/base64字符替换表/zifu_replac.py` | (老脚本) base64字符替换表 | — | — | 16 |
| `Base/base64异或/base64-xor.py` | (老脚本) base64异或 | — | — | 10 |
| `Base/Base64扩展/base64寻找缺失的字符/lost.py` | (老脚本) base64寻找缺失的字符 | — | — | 8 |
| `Base/Base64扩展/爆破/exp.py` | (老脚本) 爆破 | — | — | 19 |
| `Base/base64解码输出字节文本/base64_text.py` | (老脚本) base64解码输出字节文本 | — | — | 6 |
| `Base/base64连续解码/bbb64.py` | (老脚本) base64连续解码 | — | — | 20 |
| `Base/base64隐写加密与解密/base64_decode.py` | Base64 隐写解码(py3 移植版) | — | — | 35 |
| `Base/base64隐写加密与解密/base64_decode2.py` | Base64 隐写解码 · 变体(按首个差异字符计算偏移)(py3 移植版) | — | — | 46 |
| `Base/base64隐写加密与解密/base64_encode.py` | (老脚本) base64隐写加密与解密 | — | — | 27 |
| `Base/base64隐写加密与解密/test.py` | (老脚本) base64隐写加密与解密 | — | — | 8 |
| `Base/base混合匹配-4个python/base1.py` | (老脚本) base混合匹配-4个python | — | — | 28 |
| `hex倒叙/1.py` | (老脚本) hex倒叙 | — | — | 11 |
| `hex减位/1.py` | (老脚本) hex减位 | — | — | 16 |
| `二进制每8位倒序/1.py` | (老脚本) 二进制每8位倒序 | — | — | 5 |
| `二进制每8位倒序/二进制8位分组.py` | (老脚本) 二进制每8位倒序 | — | — | 5 |
| `十进制转字符/1.py` | (老脚本) 十进制转字符 | — | — | 15 |
| `去重/base64-zip.py` | (老脚本) 去重 | — | — | 5 |
| `去重/quchong.py` | (老脚本) 去重 | — | — | 15 |
| `去重/十六进制转字符.py` | (老脚本) 去重 | — | — | 6 |
| `字符替换表/zifu_replac.py` | (老脚本) 字符替换表 | — | — | 13 |
| `字符频率统计分析/test.py` | (老脚本) 字符频率统计分析 | — | — | 18 |
| `字符频率统计分析/test2.py` | (老脚本) 字符频率统计分析 | — | — | 4 |
| `文本转gbk编码/1.py` | (老脚本) 文本转gbk编码 | — | — | 8 |
| `曼彻斯特编码/decode_man.py` | (老脚本) 曼彻斯特编码 | — | — | 33 |
| `替换脚本/space.py` | (老脚本) 替换脚本 | — | — | 8 |
| `谍报-替换普通话/tihuan.py` | (老脚本) 谍报-替换普通话 | — | — | 13 |
| `进制互相转换/二进制高位补0/test.py` | (老脚本) 二进制高位补0 | — | — | 10 |
| `进制转化字符脚本/二进制转ascii/1.py` | (老脚本) 二进制转ascii | — | — | 9 |
| `进制转化字符脚本/循环遍历减去1-128数的ASCII码.py` | (老脚本) 进制转化字符脚本 | — | — | 15 |

## Steganography — 隐写 (19)

> 隐写:图片 / 音频 / 零宽字符 / 二维码

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `__init__.py` | — | — | — | 1 |
| `decode_image.py` | — | — | — | 20 |
| `EXIF信息提取/exif_dump.py` | 图片 EXIF/元信息提取(补充题型: Misc/Forensics) | pillow | — | 85 |
| `GIF帧时间隐写/gif_frames.py` | gif_frames GIF 帧分离 / 帧延时分析 | pillow | ✅ `--selftest` | 94 |
| `LSB隐写/lsb.py` | PNG LSB 隐写 嵌入/提取(补充题型: Misc/图片隐写) | pillow | — | 132 |
| `PNG结构分析/png_analyze.py` | png_analyze PNG 结构分析 / CRC 修复(py3 完善版) | pillow | ✅ `--selftest` | 173 |
| `RGB转图片/rgb.py` | (老脚本) RGB转图片 | pillow | — | 19 |
| `steghide爆破密码/steghide-brute.py` | (老脚本) steghide爆破密码 | — | — | 46 |
| `二维码解码/qr_decode.py` | qr_decode 二维码解码(opencv / pyzbar 双引擎) | numpy, opencv-python, pillow, pyzbar, qrcode | ✅ `--selftest` | 104 |
| `内存数据转图片/img_solve.py` | img_solve 内存 dump 数据转图片 | pillow | ✅ `--selftest` | 107 |
| `图片爆破宽高/1.py` | (老脚本) 图片爆破宽高 | — | — | 28 |
| `图片爆破宽高/2.py` | (老脚本) 图片爆破宽高 | — | — | 30 |
| `图片马生成/imgshell.py` | imgshell 图片马生成/校验 | pillow | ✅ `--selftest` | 104 |
| `字节转二维码/200-erweima.py` | (老脚本) 字节转二维码 | pillow | — | 15 |
| `文件尾数据检测/carve_tail.py` | carve_tail.py — 图片/文件尾部追加数据检测与剥离(隐写经典套路) | — | ✅ `--selftest` | 171 |
| `红绿灯-二进制/traffic.py` | (老脚本) 红绿灯-二进制 | pillow | — | 29 |
| `零宽字符隐写/zwstego.py` | zwstego 零宽字符隐写 编码/解码 | — | ✅ `--selftest` | 127 |
| `音频摩斯解析/audio_morse.py` | audio_morse 音频摩斯码解析(wav) | — | ✅ `--selftest` | 181 |
| `频域盲水印/pinyubwm.py` | (老脚本) 频域盲水印 | numpy, opencv-python | — | 57 |

## TrafficeAnalysis — 流量分析 (24)

> 流量分析:USB / WEB / 邮件 / Telnet / 修复(一键入口 solve.py)

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `__init__.py` | — | — | — | 1 |
| `decode_modbus.py` | — | pyshark | — | 28 |
| `extract_objects.py` | extract_objects.py — 从流量中提取传输的文件(通用技能) | — | — | 153 |
| `find_admin_url.py` | find_admin_url.py — 后台目录爆破分析(题型:黑客扫描到的后台登录地址是什么?) | — | — | 110 |
| `find_login.py` | find_login.py — 后台账号爆破分析(题型:黑客使用了什么账号密码登录了web后台?) | — | — | 120 |
| `find_scanner.py` | find_scanner.py — WEB扫描器识别(题型:黑客使用的是什么扫描器?) | — | — | 105 |
| `find_webshell.py` | find_webshell.py — WEBSHELL 上传/连接分析(题型:黑客上传的webshell文件名和内容是什么?) | — | — | 133 |
| `generate.py` | — | — | — | 12 |
| `ICMP数据提取/icmp_data.py` | icmp_data.py — 提取 ICMP echo 数据(纯标准库, 不依赖 scapy/tshark) | — | ✅ `--selftest` | 195 |
| `len2hex.py` | — | pyshark | — | 17 |
| `make_samples.py` | make_samples.py — 生成各题型的测试流量包(用于验证上面所有脚本能直接出解) | — | — | 499 |
| `pcapfix.py` | pcapfix.py — CTF 流量包修复(对应题型:流量包修复) | — | — | 138 |
| `pcaplib.py` | pcaplib.py — CTF 流量分析公共库(纯 Python 标准库实现,无需 scapy/pyshark) | — | — | 730 |
| `smtp_mail.py` | smtp_mail.py — SMTP/POP3 邮件流量分析(题型:邮件里藏flag/附件) | — | — | 143 |
| `solve.py` | solve.py — 一键流量分析:自动识别流量类型,调用对应脚本出解(总入口) | — | — | 176 |
| `telnet_session.py` | telnet_session.py — Telnet 流量还原(题型:telnet 明文口令/命令找flag) | — | — | 123 |
| `TTL隐写/TTL-encode.py` | (老脚本) TTL隐写 | — | — | 20 |
| `TTL隐写/TTL-stego.py` | (老脚本) TTL隐写 | — | — | 31 |
| `TTL隐写/TTL-stego2.py` | (老脚本) TTL隐写 | — | — | 23 |
| `usb_keyboard.py` | usb_keyboard.py — USB 键盘流量还原(题型:Flag藏于usb键盘流量中) | — | — | 126 |
| `usb_mouse.py` | usb_mouse.py — USB 鼠标流量还原(题型:Flag藏在鼠标移动轨迹中) | pillow | — | 167 |
| `usb流量/usbtxt.py` | USB HID 键盘流量解析(py3 移植版) | — | — | 87 |
| `USB鼠标流量解析/usb_mouse.py` | usb_mouse USB 鼠标流量还原轨迹 | pillow | ✅ `--selftest` | 165 |
| `流量数据提取脚本/1.py` | 从 pcap 提取 ICMP 回显响应(type 0) payload 末 8 字节(py3 移植版) | scapy | — | 23 |

## LogAnalysis — 日志分析 (3)

> 日志分析

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `__init__.py` | — | — | — | 1 |
| `access_log分析/access_log_analyze.py` | access_log_analyze.py — Nginx/Apache 访问日志统计分析(蓝队/取证必备) | — | ✅ `--selftest` | 229 |
| `日志匹配/1.py` | (老脚本) 日志匹配 | — | — | 11 |

## Web — Web 安全 (13)

> Web 安全:SQLi / SSTI / JWT / 反序列化 / 信息泄露

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `DS_Store解析/ds_store_exploit.py` | DS_Store 泄露利用(py3 完善版) | ds_store, requests | ✅ `--selftest` | 166 |
| `Git泄漏解析/git_dump_batch.py` | git_dump_batch 批量 Git 泄露利用(py3 完善版) | — | ✅ `--selftest` | 114 |
| `Git泄漏解析/git_index_parse.py` | git index(.git/index) 解析 — Git 泄露恢复辅助(py3 完善版) | — | ✅ `--selftest` | 125 |
| `gopher协议生成/gopher.py` | gopher SSRF payload 生成器(redis / http / 原始) | — | ✅ `--selftest` | 123 |
| `JWT伪造/jwt_forge.py` | JWT 破解与伪造(补充题型: Web/JWT) — 纯标准库, 无第三方依赖 | — | — | 157 |
| `PHP反序列化wakeup绕过/wakeup_bypass.py` | PHP 反序列化 __wakeup 绕过 & 序列化串工具(补充题型: Web/PHP反序列化) | — | — | 103 |
| `PHP反序列化类名爆破/php_class_brute.py` | PHP 反序列化 类名/属性名 爆破(py3 完善版) | requests | ✅ `--selftest` | 161 |
| `python-Picke序列化/1.py` | (老脚本) python-Picke序列化 | — | — | 9 |
| `python-Picke序列化/坐标转化脚本/2.py` | (老脚本) 坐标转化脚本 | — | — | 31 |
| `SQL盲注自动化/blind_sqli.py` | SQL 盲注自动化模板(补充题型: Web/SQL注入) | requests | — | 144 |
| `SSTI利用/ssti_probe.py` | SSTI 模板注入探测与利用(补充题型: Web/SSTI) | requests | — | 109 |
| `双参数爆破脚本/brust.py` | (老脚本) 双参数爆破脚本 | requests | — | 5 |
| `目录扫描/dirscan.py` | dirscan 轻量目录/文件扫描 | requests | ✅ `--selftest` | 133 |

## Pwn — 二进制漏洞利用 (6)

> 二进制漏洞利用:pwntools 模板 / shellcode

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `pwntools模板/fmtstr_exp.py` | 格式化字符串 Exploit 模板(pwntools)(补充题型: Pwn) | pwntools | — | 67 |
| `pwntools模板/libc_leak_template.py` | libc_leak_template 32 位 write 泄露 libc 模板(含 DynELF 备选) | pwntools | — | 67 |
| `pwntools模板/ret2libc_exp.py` | ret2libc 通用 Exploit 模板(pwntools)(补充题型: Pwn) | LibcSearcher, pwntools | — | 90 |
| `pwntools模板/simple_template.py` | simple_template 最小化 pwn exp 骨架 | pwntools | — | 42 |
| `shellcode生成与解析/shellcode_generator.py` | shellcode_generator 直接汇编生成 shellcode | pwntools | — | 80 |
| `shellcode生成与解析/shellcode_parser.py` | shellcode_parser 从 .s 源码汇编出 ELF 并提取 .text 中的 shellcode | pwntools | — | 60 |

## Reverse — 逆向 (7)

> 逆向:z3 / angr / pyc 修复 / ARM 模拟

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `angr求解模板/angr_template.py` | angr 符号执行 CTF 模板(补充题型: Reverse) | angr | — | 67 |
| `angr虚拟机混淆解题/burforce_vm.py` | burforce_vm angr 爆破虚拟机混淆题目 | angr | — | 70 |
| `ARM模拟调试器/arm_dbg.py` | arm_dbg 基于 unicorn 的 ARM 模拟调试器 | capstone, unicorn | — | 280 |
| `Frida hook模板/frida_hook.py` | frida_hook.py — Frida hook 脚本生成器(安卓逆向/CTF mobile 常用) | — | ✅ `--selftest` | 209 |
| `pyc文件头修复/pyc_fix.py` | pyc 文件头修复(补充题型: Reverse/pyc) | — | — | 166 |
| `z3求解模板/z3_template.py` | z3 约束求解 CTF 模板(补充题型: Reverse) | z3-solver | — | 90 |
| `相邻异或还原/xor.py` | xor.py 相邻字符异或链还原 flag(逆向题常见编码) | — | ✅ `--selftest` | 77 |

## Misc — 杂项 (26)

> 杂项:压缩包 / 文件修复 / CRC32 / 迷宫 / Brainfuck

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `CRC32校验爆破/crc-1byte.py` | (老脚本) CRC32校验爆破 | — | — | 21 |
| `CRC32校验爆破/crc-2byte.py` | (老脚本) CRC32校验爆破 | — | — | 23 |
| `CRC32校验爆破/crc-3byte.py` | (老脚本) CRC32校验爆破 | — | — | 24 |
| `CRC32校验爆破/crc-4byte.py` | (老脚本) CRC32校验爆破 | — | — | 25 |
| `CRC32校验爆破/crc-5byte.py` | (老脚本) CRC32校验爆破 | — | — | 26 |
| `CRC32校验爆破/crc32/crc32.py` | (老脚本) crc32 | — | — | 348 |
| `CRC32校验爆破/crc32/test.py` | (老脚本) crc32 | — | — | 73 |
| `CRC32校验爆破/crc32/test_data.py` | (老脚本) crc32 | — | — | 296 |
| `Python-Brainfuck-master/brainfuck.py` | (老脚本) Python-Brainfuck-master | — | — | 72 |
| `Python-Brainfuck-master/getch.py` | (老脚本) Python-Brainfuck-master | — | — | 44 |
| `robot迷宫求解/robot_maze.py` | robot_maze 迷宫求解(py3 移植完善版) | pillow | ✅ `--selftest` | 640 |
| `zip伪加密修复/zip_fix.py` | ZIP 伪加密检测与修复(补充题型: Misc/压缩包) | — | — | 115 |
| `zip密码爆破/zip_brute.py` | ZIP 密码爆破(补充题型: Misc/压缩包) | pyzipper | — | 119 |
| `一些比赛的脚本/祥云杯-xixixi/1.py` | (老脚本) 祥云杯-xixixi | — | — | 84 |
| `坐标画图/coord_plot.py` | coord_plot.py — 坐标点/连线画图(misc 高频: 给一堆坐标求 flag 图) | pillow | ✅ `--selftest` | 160 |
| `批量修改文件名后缀/modify-suffix.py` | (老脚本) 批量修改文件名后缀 | — | — | 16 |
| `批量解压压缩包+带密码/zip.py` | (老脚本) 批量解压压缩包+带密码 | — | — | 8 |
| `数学题/取模/1.py` | (老脚本) 取模 | — | — | 6 |
| `数学题/取模/2.py` | (老脚本) 取模 | — | — | 5 |
| `文件头修复/file_fix.py` | 常见文件头/尾修复 与 文件类型识别(补充题型: Misc/Forensics) | pillow | — | 146 |
| `文件异或/010editor异或/1.py` | (老脚本) 010editor异或 | — | — | 7 |
| `文件异或/yihuo.py` | (老脚本) 文件异或 | — | — | 10 |
| `文件异或/二进制异或/binary-yihuo.py` | (老脚本) 二进制异或 | — | — | 14 |
| `文件类型识别与提取/carve.py` | 文件雕刻/内嵌文件提取 — 纯 Python mini-binwalk(补充题型: Misc/Forensics) | pillow | — | 123 |
| `迷宫路径记录GUI/maze_run.py` | maze_run 迷宫路线方向键记录器(GUI) | — | — | 84 |
| `遍历读取压缩包文件判断1和0/批量图片二进制.py` | (老脚本) 遍历读取压缩包文件判断1和0 | — | — | 35 |

## Writeups — WP 实战做题脚本 (11)

> WP 实战做题脚本:SSTI / 代码审计 / 文件上传 / 文件包含 真题利用链

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `SSTI/自定义字符集异或编码/1.py` | 1.py SSTI 自定义字符集异或编码还原([pasecactf_2019]flask_ssti) | — | ✅ `--selftest` | 65 |
| `SSTI/遍历子类找os索引/SSTIFindSubprocess.py` | SSTIFindSubprocess.py SSTI 遍历 __subclasses__ 定位 os 模块索引 | requests | — | 61 |
| `代码审计/flask-session解密/session.py` | session.py Flask session cookie 解密(明文查看) | flask, itsdangerous | ✅ `--selftest` | 95 |
| `代码审计/htaccess上传LFI综合利用/EasyWeb.py` | EasyWeb.py .htaccess 上传 + php://filter LFI 综合利用([SUCTF 2019]EasyWeb) | requests | — | 66 |
| `代码审计/md5前缀爆破/EasySearch.py` | EasySearch.py MD5 前缀爆破([BJDCTF2020]EasySearch) | — | ✅ `--selftest` | 72 |
| `文件上传/thinkphp上传文件名爆破/tpupload.py` | tpupload.py ThinkPHP 上传文件名爆破([RoarCTF 2019]Simple Upload) | requests | — | 66 |
| `文件上传/thinkphp上传文件名爆破/tpupload2.py` | tpupload2.py uniqid 文件名前后缀定位辅助([RoarCTF 2019]Simple Upload) | — | ✅ `--selftest` | 58 |
| `文件包含/idna编码绕过探测/idna_unicode_bypass.py` | idna_unicode_bypass.py IDNA Unicode 字符绕过探测([SUCTF 2019]Pythonginx) | — | ✅ `--selftest` | 66 |
| `文件包含/phpfilter崩溃LFI/lfi_php_filter_exploit.py` | lfi_php_filter_exploit.py php://filter 崩溃留临时文件 + 包含 getshell | requests | — | 54 |
| `文件包含/仿射密码爆破/affine_cipher.py` | affine_cipher.py 仿射密码加密与爆破(带模 26 逆元表) | — | ✅ `--selftest` | 107 |
| `文件包含/希尔密码加解密/hill_cipher.py` | hill_cipher.py 希尔密码(Hill Cipher)模 26 加解密 | numpy | ✅ `--selftest` | 106 |

## 仓库工具(根目录) (2)

| 脚本 | 说明 | 依赖 | 自测 | 行数 |
|---|---|---|---|---|
| `check_env.py` | check_env 脚本库环境自检 | — | — | 202 |
| `gen_index.py` | gen_index 全库脚本索引生成器 | — | — | 249 |

---

*本文件由 gen_index.py 自动生成, 请勿手工编辑; 用法说明的人工版见 [README.md](README.md) 与 [TrafficeAnalysis/README.md](TrafficeAnalysis/README.md)。*
