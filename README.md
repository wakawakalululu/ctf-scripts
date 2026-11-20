# ctf-scripts

CTF 做题脚本集:211 个现成脚本,覆盖 **Web / Pwn / Reverse / Crypto / Misc / 隐写 / 流量 / 日志 / WP 实战** 九大类。
每个脚本可直接运行;较新的脚本**无参数运行即跑内置自测**(输出 `OK/FAIL`),实战时按用法传参或修改硬编码参数。

## 环境

- Python **>= 3.8**(推荐 3.10 / 3.12)
- 安装依赖:`pip install -r requirements.txt`
- 环境自检:`python check_env.py`(全库扫描,报告每个脚本的依赖与安装命令;`--missing` 只看缺依赖)

## 目录结构

```
ctf-scripts/
├── check_env.py            # 依赖自检: python check_env.py [--missing|--deps]
├── requirements.txt
├── Crypto/                 # 密码学:RSA 全家桶 / 古典密码 / 对称加密 / 哈希
├── Encoding/               # 编码转换:Base 系列 / hex / 二进制 / 字符统计
├── Steganography/          # 隐写:图片 / 音频 / 零宽字符 / 二维码
├── TrafficeAnalysis/       # 流量分析(含一键 solve.py,详见其 README.md)
├── LogAnalysis/            # 日志分析
├── Web/                    # Web:SQLi / SSTI / JWT / PHP反序列化 / Git泄露
├── Pwn/                    # pwntools 模板 / shellcode
├── Reverse/                # z3 / angr / pyc修复 / ARM模拟
├── Misc/                   # 压缩包 / 文件修复 / CRC32 / 迷宫 / Brainfuck
├── Writeups/               # WP 实战做题脚本(SSTI/代码审计/文件上传/文件包含, 自带原题解 README)
└── files/                  # 示例流量包(capture.pcap / Modbus.pcap 等)
```

## 快速开始

```bash
# 一键流量分析(自动识别 USB/WEB/邮件/Telnet)
python TrafficeAnalysis/solve.py TrafficeAnalysis/samples/usb_keyboard.pcap

# 任意脚本先跑自测(较新脚本支持)
python Crypto/摩斯密码/morse.py
python Web/JWT伪造/jwt_forge.py --selftest

# 2026-11-21 新增高频题型示例
python TrafficeAnalysis/DNS隧道解析/dns_tunnel.py tunnel.pcap      # DNS 隧道提取+自动解码
python Steganography/音频频谱图/audio_spectrogram.py sound.wav     # 频谱图里读 flag
python Pwn/溢出偏移定位/cyclic_offset.py --find 0x62616164          # 栈溢出偏移秒算

# 实战示例
python Misc/zip伪加密修复/zip_fix.py fake_enc.zip --fix
python Steganography/二维码解码/qr_decode.py flag.png

# WP 实战脚本(离线自测)
python Writeups/代码审计/flask-session解密/session.py --selftest
python Writeups/文件包含/仿射密码爆破/affine_cipher.py --selftest
```

> 找某个具体脚本?全量 211 个 .py 的自动索引见 [SCRIPTS-INDEX.md](SCRIPTS-INDEX.md)
> (由 `python gen_index.py` 生成,含每个脚本的说明 / 第三方依赖 / 自测标记;
> 新增脚本后重跑一次即可刷新,`python gen_index.py --check` 可校验是否过期)。

---

## TrafficeAnalysis/ — 流量分析

> 详细题型对照见 [TrafficeAnalysis/README.md](TrafficeAnalysis/README.md)。一键入口 `solve.py` 自动识别流量类型并调用对应脚本;依赖仅标准库 + Pillow,tshark 可选增强。

| 脚本 | 用途 | 用法 |
|---|---|---|
| `solve.py` | **一键分析**:识别流量类型→调用脚本→汇总 flag | `python solve.py x.pcap` |
| `pcapfix.py` | 修复损坏的 pcap(魔数/截断尾包) | `python pcapfix.py broken.cap [fixed.pcap]` |
| `find_scanner.py` | 识别 AWVS/Sqlmap/DirBuster 等 30+ 扫描器 | `python find_scanner.py x.pcap` |
| `find_admin_url.py` | 目录爆破分析,输出后台地址 | `python find_admin_url.py x.pcap` |
| `find_login.py` | 账号爆破分析,判定登录成功的账密 | `python find_login.py x.pcap` |
| `find_webshell.py` | webshell 上传分析(multipart+菜刀/蚁剑) | `python find_webshell.py x.pcap [导出目录]` |
| `usb_keyboard.py` | USB 键盘 HID 键码还原(含 Shift) | `python usb_keyboard.py x.pcap [--raw]` |
| `ICMP数据提取/icmp_data.py` | ICMP echo payload 提取(纯标准库,4 种链路层) | `python icmp_data.py x.pcap [--save out.bin --hex]` |
| `DNS隧道解析/dns_tunnel.py` | DNS 隧道提取:子域名/TXT 拼接自动 hex/base32/base64 解码(纯标准库) | `python dns_tunnel.py x.pcap [--suffix data.com --raw]` |
| `usb_mouse.py` | USB 鼠标轨迹画图(all/left/right) | `python usb_mouse.py x.pcap [out.png]` |
| `smtp_mail.py` | SMTP/POP3 邮件解析+附件导出 | `python smtp_mail.py x.pcap [导出目录]` |
| `telnet_session.py` | Telnet 会话还原+凭据配对 | `python telnet_session.py x.pcap` |
| `extract_objects.py` | HTTP 对象导出+按魔数切割文件 | `python extract_objects.py x.pcap [导出目录]` |
| `decode_modbus.py` | MODBUS 协议解析找 flag(依赖 pyshark) | 修改脚本内 pcap 路径后运行 |
| `len2hex.py` | 数据包长度转 hex(依赖 pyshark) | 修改脚本内参数后运行 |
| `generate.py` | 目录内文件按正则提取内容写入 passwd.txt | 修改脚本内目录后运行 |
| `usb流量/usbtxt.py` | USB HID 键盘码解析(数据放 usbdata.txt) | 修改数据文件后运行 |
| `USB鼠标流量解析/usb_mouse.py` | HID 鼠标数据还原轨迹/点击画图 | `python usb_mouse.py -f usb.pcap -p 3 --mode all` |
| `流量数据提取脚本/1.py` | scapy 提取 ICMP payload(依赖 scapy) | 修改脚本内 pcap 路径后运行 |
| `TTL隐写/` | IP TTL 字段隐写编解码 | `python TTL-stego.py`(数据放 out.txt) |
| `make_samples.py` | 生成自带答案的测试流量包 | `python make_samples.py` |

## Steganography/ — 隐写

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `decode_image.py` | Base64 字符串还原为 PNG 图片 | 修改脚本内 base64 后运行 |
| `LSB隐写/lsb.py` | PNG LSB 嵌入/提取(4 字节长度头) | `-x 图片.png` 提取 / `-e 图片.png --secret flag{}` 嵌入 |
| `文件尾数据检测/carve_tail.py` | PNG/JPG/GIF/ZIP/PDF 尾部附加数据检测+剥离 | `python carve_tail.py x.jpg [--save tail.bin --strip]` |
| `频域盲水印/pinyubwm.py` | 频域盲水印提取(opencv) | `python pinyubwm.py --original 原图 --image 水印图 --result out.png` |
| `图片爆破宽高/` | PNG IHDR 宽高 CRC32 爆破恢复 | 修改脚本内 CRC 值与图片路径后运行 |
| `PNG结构分析/png_analyze.py` | PNG 块列举/提取+CRC 批量修复+tEXt 预览 | `python png_analyze.py list x.png` / `fix-crc` |
| `GIF帧时间隐写/gif_frames.py` | GIF 帧分离+延时离群分析(MAD) | `python gif_frames.py -f x.gif --odd` |
| `GIF拆帧/gif_frames.py` | GIF 逐帧导出 PNG+帧延迟列表(拆帧看图/配合扫码) | `python gif_frames.py x.gif [--info -o outdir]` |
| `音频频谱图/audio_spectrogram.py` | WAV 转频谱图 PNG(numpy FFT,flag 画频谱题型)+主峰频率 | `python audio_spectrogram.py x.wav [--peak]` |
| `双图差分异或/img_diff.py` | 双图逐像素差分/XOR 还原空间域盲水印(自动缩放对齐) | `python img_diff.py a.png b.png [-m diff/xor --scale 4]` |
| `EXIF信息提取/exif_dump.py` | EXIF/PNG tEXt 元信息全 dump | `python exif_dump.py x.jpg` |
| `图片马生成/imgshell.py` | 图片马合成与 payload 偏移校验 | `python imgshell.py --make 图.jpg -p shell.php -o out.jpg` |
| `steghide爆破密码/steghide-brute.py` | steghide 字典爆破(需装 steghide) | 修改脚本内图片路径后运行 |
| `零宽字符隐写/zwstego.py` | 零宽字符隐写编解码 | `-e --secret flag{}` 嵌入 / `-d -f 文本` 提取 |
| `音频摩斯解析/audio_morse.py` | wav 音频摩斯码自动判定解码(纯标准库) | `python audio_morse.py x.wav` |
| `二维码解码/qr_decode.py` | QR 解码(cv2+pyzbar 双引擎,二值化/放大重试) | `python qr_decode.py x.png [--binarize]` |
| `字节转二维码/200-erweima.py` | 0/1 矩阵文本转二维码图片 | 数据放 `1.txt` 后运行 |
| `RGB转图片/rgb.py` | RGB 三元组文本逐像素生成图片 | 数据放 `qr.txt` 后运行 |
| `红绿灯-二进制/traffic.py` | 图片序列按像素颜色提取 0/1 转字符 | 修改图片目录后运行 |
| `内存数据转图片/img_solve.py` | 内存 dump 按宽高还原图片(行/列优先,灰度/RGB) | `python img_solve.py dump.bin -W 200 -H 150 --save out.png` |

## Crypto/ — 密码学

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `RSA综合脚本利用/` | **19 种 RSA 攻击场景**全集(小明文/共模/Wiener/dp泄露/CRT/pq接近等) | 按已知条件找对应子目录,改参数运行 |
| `factordb查询/factordb.py` | factordb 在线分解 n + 本地试除/Pollard rho 兜底 | `python factordb.py -n <N>`(离线加 `--local`) |
| `仿射密码爆破/affine_brute.py` | 仿射密码全 312 密钥爆破,卡方打分+flag/提示词置顶 | `python affine_brute.py "密文" [-w FLAG -n 10]` |
| `Playfair密码/playfair.py` | Playfair 加解密(5x5,I/J 合并,含维基经典向量自测) | `python playfair.py -e 明文 -k 密钥` / `-d` |
| `Hill密码/hill.py` | Hill 密码任意 n 阶加解密(mod 26 伴随矩阵求逆) | `python hill.py -e ACT -k "6,24,1;13,16,10;20,17,15"` |
| `敲击码/tapcode.py` | 敲击码(5x5,K→C)编解码,数字对/点划混排兼容 | `python tapcode.py -e HELLO` / `-d "23 15"` |
| `当铺密码/dangpu.py` | 当铺密码(汉字出头数→数字)编解码,--map 自定义变体 | `python dangpu.py -d "中人工大"` / `--show` |
| `哈希类型识别/hash_identify.py` | 按长度/前缀识别哈希类型,给 hashcat/john 命令,--dict 简单字典爆破 | `python hash_identify.py <hash>` / `--dict wordlist.txt` |
| `维吉尼亚密钥爆破/vigenere_brute.py` | 维吉尼亚无密钥爆破(重合指数定长+卡方定移位) | `python vigenere_brute.py cipher.txt [--keylen N --crib flag{]` |
| `云影密码/yunying.py` | 云影密码(0/8 密码)编解码 | `python yunying.py -d "8842101226885448"` / `-e HELLO` |
| `AES加解密模板/aes_template.py` | AES ECB/CBC 加解密,hex/base64 自动识别,PKCS7 | `python aes_template.py -m d -a ecb -k <hex密钥> -c <密文>` |
| `DES_Python-master/` | Python DES 实现 | `from des import DES`(详见其 README.md) |
| `TEA加解密/tea_xtea.py` | TEA/XTEA 加解密,delta/rounds 可调 | `python tea_xtea.py --algo xtea -a d -k KEY -c HEX` |
| `XOR自动爆破/xor_brute.py` | 单字节 256 全试 + crib 推导重复密钥 | `python xor_brute.py -c <密文> --crib flag{` |
| `md5爆破/md5-brust.py` | 带 `?` 通配符的明文 MD5 枚举还原 | 修改脚本内模板与目标 MD5 后运行 |
| `哈希长度扩展攻击/hash_ext.py` | md5/sha1 长度扩展伪造(纯标准库) | `python hash_ext.py -f md5 -d DATA -s SIG -a APPEND -l LEN` |
| `摩斯密码/morse.py` | 摩斯电码加解密(兼容 `·—_` 变体) | `python morse.py -d '..-. ..- -.'` |
| `培根密码/bacon.py` | 培根密码(24 字母表+大小写隐写) | `python bacon.py -d 'AABBB...'` / `--case` |
| `栅栏密码/railfence.py` | W 形栅栏加解密,栏数未知自动爆破 | `python railfence.py -d '密文'`(加 `--flag flag{` 筛选) |
| `维吉尼亚加密/exp.py` | 维吉尼亚加解密 | 修改脚本内密文/密钥后运行 |
| `变异凯撒/` | 凯撒变体(偏移量逐字符递增/减) | 修改脚本内密文后运行 |
| `rot/rot.py` | ROT13/ROT47 还原 | 修改脚本内数据后运行 |
| `四方密码/sifang.py` | 四方密码(Four-Square)加解密 | 修改脚本内密钥矩阵后运行 |
| `Nihilist密码/nihilist.py` | Nihilist 密码解密(5x5 密钥矩阵) | 修改脚本内密文/矩阵后运行 |
| `toy密码/toy.py` | Toy 密码双层替换解密 | 修改映射表后运行 |
| `26键盘密码-手机键盘密码/jianpan.py` | 手机 T9 / 26 键盘布局密码 | 修改脚本内数据后运行 |
| `常用反解密脚本/cryp-1.py` | XOR+偏移组合通用解密模板 | 修改脚本内密文后运行 |

## Encoding/ — 编码转换

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `Base/` | Base 全家桶:B16/32/64/85 互转、连续解码、换表、隐写、异或等 8 个子工具 | 按子目录名选择,改参数运行 |
| `hex倒叙/` | hex 字符串反转 | 改数据运行 |
| `hex减位/` | hex 值减固定偏移转字符 | 改数据运行 |
| `十进制转字符/` | 十进制 ASCII 转字符 | 改数据运行 |
| `二进制每8位倒序/` | 二进制每 8 位分组内部反转 | 改数据运行 |
| `进制互相转换/二进制高位补0/` | 二进制串高位补齐到 8 的倍数 | 改数据运行 |
| `进制转化字符脚本/` | 二进制转 ASCII / 穷举 ROT-N(1~128) | 改数据运行 |
| `字符替换表/zifu_replac.py` | 自定义 Base64 表映射解码 | 修改映射表后运行 |
| `字符频率统计分析/` | 字符频率统计(替换密码辅助分析) | 数据放 flag.txt 后运行 |
| `文本转gbk编码/1.py` | 文本转 GBK 编码写入文件 | 改数据运行 |
| `谍报-替换普通话/tihuan.py` | 同义词替换密码:对比原文与改写版恢复密文 | 修改 str1/str2/str3 后运行 |
| `去重/` | 文本去重 / hex 转字符 / base64-zip | 改数据运行 |
| `替换脚本/space.py` | 行长短编码为 0/1 二进制 | 数据放 attachment.txt 后运行 |
| `曼彻斯特编码/decode_man.py` | 曼彻斯特/差分曼彻斯特解码 | 修改二进制串后运行 |
| `行尾空白隐写/trailing_ws.py` | 行尾空格/Tab 承载二进制,3 种约定自动试解+写入 | `python trailing_ws.py x.txt` / `-e "flag{}"` |

## Web/ — Web 安全

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `SQL盲注自动化/blind_sqli.py` | 布尔/时间盲注,二分逐字符提取(自测内置虚拟目标) | 自测 `python blind_sqli.py`;实战改 HTTP 部分 |
| `SSTI利用/ssti_probe.py` | 模板引擎指纹探测+RCE payload 速查(6 引擎) | `python ssti_probe.py --url http://x --param name` / `--list` 看 payload 表 |
| `JWT伪造/jwt_forge.py` | JWT 解码/HS256 密钥爆破/伪造/alg:none(纯标准库) | `python jwt_forge.py -t TOKEN -w 字典` 爆破 / `-f --set role=admin` 伪造 |
| `PHP反序列化wakeup绕过/wakeup_bypass.py` | CVE-2016-7124 wakeup 绕过+私有属性串/URL编码 | `python wakeup_bypass.py -s 'O:8:"..."' -n 属性数 --url` |
| `PHP反序列化类名爆破/php_class_brute.py` | 类名/属性名两阶段爆破(配合 wakeup 绕过) | `python php_class_brute.py -u URL -p PARAM --marker 报错特征` |
| `python-Picke序列化/` | Python Pickle 反序列化利用 | 按题目修改脚本运行 |
| `Git泄漏解析/git_index_parse.py` | .git/index 路径与 SHA 恢复(纯标准库) | `python git_index_parse.py index --sha --check` |
| `Git泄漏解析/git_dump_batch.py` | 批量 git-dumper+flag 正则搜索 | `python git_dump_batch.py -t http://x/.git/` |
| `DS_Store解析/ds_store_exploit.py` | .DS_Store 泄露利用(远程递归/本地解析/--grep) | `python ds_store_exploit.py -u http://x/.DS_Store` / `-f 本地文件` |
| `目录扫描/dirscan.py` | 轻量后台/备份扫描(内置词表+多线程) | `python dirscan.py -u http://x/ [-w 字典 --ext php,bak]` |
| `gopher协议生成/gopher.py` | SSRF 打内网 Redis/HTTP,RESP+二次编码 | `python gopher.py --type redis --cmd "set x 1"` |
| `XXE_payload生成/xxe_payloads.py` | XXE 六大模板一键生成(文件读/PHP filter/OOB HTTP+FTP/报错回显) | `python xxe_payloads.py CLASSIC --file /flag` / `--list` |
| `双参数爆破脚本/brust.py` | 双参数组合爆破(如邀请码+用户ID) | 修改脚本内 url 与参数列表后运行 |

## Reverse/ — 逆向

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `z3求解模板/z3_template.py` | z3 约束求解:Int 方程组/BitVec XOR/Sum 三种模式 | 改脚本内约束后运行(依赖 z3-solver) |
| `angr求解模板/angr_template.py` | angr 符号执行标准模板(stdin 符号注入) | 改脚本内路径/地址后运行(建议 WSL) |
| `angr虚拟机混淆解题/burforce_vm.py` | angr 爆破 VM 混淆题(地址参数化) | `python burforce_vm.py 二进制 --find ADDR --avoid ADDR` |
| `pyc文件头修复/pyc_fix.py` | pyc 头修复(2.7~3.13 magic 表,自动探测头长/版本) | `python pyc_fix.py broken.pyc -o fixed.pyc` |
| `ARM模拟调试器/arm_dbg.py` | unicorn ARM 模拟调试(断点/单步/内存 dump) | `python arm_dbg.py --demo`;实战改 `run_demo()` 后 `--demo` 进入交互 |
| `相邻异或还原/xor.py` | 相邻字符异或链还原 flag(a^b=c ⇒ a^c=b) | `python xor.py` 解内置数据 / `--selftest` |
| `Frida hook模板/frida_hook.py` | Frida hook JS 生成器(java/native/crypto/replace 4 类模板) | `python frida_hook.py java --class com.x.Main --method check` |

## Pwn/ — 二进制漏洞利用

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `pwntools模板/ret2libc_exp.py` | 两段式 ret2libc(泄露 puts@got→libc base→system) | 改脚本内二进制/偏移后运行(依赖 pwntools) |
| `pwntools模板/fmtstr_exp.py` | 格式化字符串:栈泄露+任意写 GOT | 改脚本内参数后运行 |
| `pwntools模板/libc_leak_template.py` | 32 位 write 泄露 libc+DynELF 备选 | 改脚本内参数后运行 |
| `pwntools模板/simple_template.py` | 32 位简单栈溢出最小骨架 | 改脚本内参数后运行 |
| `pwntools模板/README.md` | checksec/cyclic/ROPgadget/one_gadget 武器链与 64 位栈对齐坑 | 阅读参考 |
| `shellcode生成与解析/shellcode_generator.py` | 直接汇编生成 shellcode(i386/amd64) | `python shellcode_generator.py --arch amd64` |
| `shellcode生成与解析/shellcode_parser.py` | 从 .s 汇编出 ELF 并提取 .text shellcode | `python shellcode_parser.py -s shellcode.s` |
| `溢出偏移定位/cyclic_offset.py` | De Bruijn 模式生成/崩溃值偏移定位(与 pwnlib cyclic 通用,免 pwntools) | `python cyclic_offset.py --gen 200` / `--find 0x62616164` |

> pwntools 本地进程调试需 WSL/Linux;Windows 直接 remote 打远程。

## Misc/ — 杂项

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `zip伪加密修复/zip_fix.py` | ZIP 伪加密检测/修复(`--fix` 清加密位,自动备份) | `python zip_fix.py x.zip --fix` |
| `zip密码爆破/zip_brute.py` | ZIP 爆破:纯数字/字典/全排列,pyzipper 支持 AES | `python zip_brute.py x.zip --digits 4` / `-w 字典` |
| `批量解压压缩包+带密码/zip.py` | 递归解压多层 ZIP(每层密码=文件名前 4 字符) | 修改起始文件名后运行 |
| `遍历读取压缩包文件判断1和0/` | 按压缩包内文件大小差异转 0/1 二进制 | 修改脚本内阈值后运行 |
| `CRC32校验爆破/` | CRC32 爆破 1~5 字节数据(zip 小文件/PNG chunk) | 按字节数选脚本,改目标 CRC 后运行 |
| `文件头修复/file_fix.py` | 11 类文件魔数识别+补头补尾(PNG/JPG/ZIP/RAR/PDF…) | `python file_fix.py x.bin --fix` |
| `文件类型识别与提取/carve.py` | 内嵌文件雕刻(mini-binwalk,魔数扫描+落盘) | `python carve.py x.bin -o carved/` |
| `文件异或/` | 文件级 XOR(hex 异或/010editor/二进制) | 改数据运行 |
| `批量修改文件名后缀/modify-suffix.py` | 批量追加后缀(如 .jpg) | 修改 path 后运行 |
| `Python-Brainfuck-master/` | Brainfuck 解释器 | 代码放 `1.txt` 后 `python brainfuck.py` |
| `坐标画图/coord_plot.py` | 坐标文本画图(每行 x,y 或空格多对,多笔画分隔,自动归一化) | `python coord_plot.py points.txt -o out.png [--mode point]` |
| `ASCII字符画转图片/ascii2img.py` | 字符画按亮度梯度还原灰度图(配合扫码,--charset/--invert) | `python ascii2img.py art.txt -o out.png` |
| `EML邮件解析/eml_parse.py` | .eml 头字段/正文解码/附件导出+flag 正则(纯标准库) | `python eml_parse.py mail.eml [--attach outdir]` |
| `robot迷宫求解/robot_maze.py` | 文本/图片迷宫求解最短路+随机迷宫生成 | `python robot_maze.py --solve maze.txt` / `--pic maze.png` |
| `迷宫路径记录GUI/maze_run.py` | 方向键走迷宫,记录 wasd 序列(GUI) | `python maze_run.py --chars 起点,终点,墙 --out out.txt` |
| `数学题/取模/` | 取模等数学计算辅助 | 改数据运行 |
| `一些比赛的脚本/祥云杯-xixixi/` | 比赛真题脚本 | 按题修改运行 |
| `emoji/` | emoji-aes 加解密(JS 实现) | 参见其 js 文件 |

## LogAnalysis/ — 日志分析

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `日志匹配/1.py` | 从 URL 编码的 LFI 日志中提取被包含文件的输出 | 日志放 `data.txt` 后运行 |
| `access_log分析/access_log_analyze.py` | Nginx/Apache 日志统计:Top IP/URI/状态码+SQLi/扫描器/webshell/爆破检测 | `python access_log_analyze.py access.log [--top 10 --burst 60 --grep flag]` |
| `PowerShell编码命令解码/ps_decode.py` | 日志/ps1 中 `-enc`/`FromBase64String` 提取解码(UTF-16LE) | `python ps_decode.py sec.log [--grep flag]` |

## Writeups/ — WP 实战做题脚本

> 收录比赛/靶场真题利用链脚本(源自 Des-CTF-Knowledge `WP汇总`),**各题型目录自带原始题解 README.md**;
> 分类内详细用法与题目对照见 [Writeups/README.md](Writeups/README.md)。原脚本硬编码的 buuoj 地址已改为 `--url` 参数,复用时替换目标即可。

| 脚本 | 题目/场景 | 用法 |
|---|---|---|
| `SSTI/自定义字符集异或编码/1.py` | [pasecactf_2019]flask_ssti 编码绕过 | `python 1.py` 还原内置密文(encode 自逆) |
| `SSTI/遍历子类找os索引/SSTIFindSubprocess.py` | FlaskLight 类:定位 `__subclasses__()` 中 os 下标 | `python SSTIFindSubprocess.py -u "http://x/?search="` |
| `代码审计/md5前缀爆破/EasySearch.py` | [BJDCTF2020]EasySearch | `python EasySearch.py`(默认爆 deadbeef)/ `--prefix --max --all` |
| `代码审计/htaccess上传LFI综合利用/EasyWeb.py` | [SUCTF 2019]EasyWeb(取反绕过+.htaccess+php://filter) | `python EasyWeb.py -u 上传接口`(利用链见 docstring) |
| `代码审计/flask-session解密/session.py` | Flask session cookie 明文解密(无需密钥) | `python session.py "ey...sig"` / `--selftest`(依赖 itsdangerous) |
| `文件上传/thinkphp上传文件名爆破/tpupload.py` | [RoarCTF 2019]Simple Upload(uniqid 文件名爆破) | `python tpupload.py -u 目录 --prefix 62189f4 --start 234 --mid bcdef --tail 1234567890abcdef` |
| `文件上传/thinkphp上传文件名爆破/tpupload2.py` | 同上:泄露片段算候选字符集 | `python tpupload2.py -a 4 -b e` |
| `文件包含/仿射密码爆破/affine_cipher.py` | 仿射密码加密/全组合爆破 | `python affine_cipher.py -e -m 明文 -a 5 -b 8` / `-c 密文 --marker fla` |
| `文件包含/希尔密码加解密/hill_cipher.py` | 希尔密码矩阵加解密(模 26 逆矩阵) | `python hill_cipher.py`(改 a/b/m 复用) |
| `文件包含/idna编码绕过探测/idna_unicode_bypass.py` | [SUCTF 2019]Pythonginx(IDNA 字符绕过) | `python idna_unicode_bypass.py`(128~65537 全扫) |
| `文件包含/phpfilter崩溃LFI/lfi_php_filter_exploit.py` | [WMCTF2020]Make PHP Great Again(strip_tags 崩溃临时文件) | `python lfi_php_filter_exploit.py -u "http://x/?file=php://filter/string.strip_tags/resource=..."` |

---

## 特征速查:遇到什么用什么

| 你遇到的 | 用什么 |
|---|---|
| pcap 有 USB 键盘/鼠标流量 | `TrafficeAnalysis/usb_keyboard.py`、`usb_mouse.py` |
| pcap 里 TTL 值奇怪(63/127/191/255) | `TrafficeAnalysis/TTL隐写/` |
| pcap 要提文件/扫描器/账密/webshell | `TrafficeAnalysis/extract_objects.py`、`find_*.py`(或直接 `solve.py` 一键) |
| pcap 有邮件/Telnet | `TrafficeAnalysis/smtp_mail.py`、`telnet_session.py` |
| pcap 里 ICMP echo payload 藏数据 | `TrafficeAnalysis/ICMP数据提取/icmp_data.py`(或 `solve.py` 自动识别) |
| pcap 大量查询同一域名的子域名(DNS 隧道) | `TrafficeAnalysis/DNS隧道解析/dns_tunnel.py` |
| 流量包损坏打不开 | `TrafficeAnalysis/pcapfix.py` |
| 图片打不开/尺寸不对 | `Steganography/图片爆破宽高/`、`PNG结构分析/png_analyze.py` |
| 图片能打开但怀疑尾巴藏了 zip/文本 | `Steganography/文件尾数据检测/carve_tail.py` |
| PNG LSB / 盲水印 / steghide / 零宽 | `Steganography/` 对应目录 |
| GIF 帧延时 / 拆帧看图 / 音频摩斯 / 音频频谱 flag | `Steganography/GIF帧时间隐写/`、`GIF拆帧/`、`音频摩斯解析/`、`音频频谱图/` |
| 两张图疑似盲水印(空间域对比) | `Steganography/双图差分异或/img_diff.py`(频域用 `频域盲水印/`) |
| 数据是 0/1 矩阵 / RGB 元组 / 图片序列 | `字节转二维码/`、`RGB转图片/`、`红绿灯-二进制/` |
| 内存 dump 还原图片 | `Steganography/内存数据转图片/img_solve.py` |
| ZIP 伪加密 / 爆破 / 多层嵌套 | `Misc/zip伪加密修复/`、`zip密码爆破/`、`批量解压压缩包+带密码/` |
| ZIP 内小文件 CRC 已知爆内容 | `Misc/CRC32校验爆破/` |
| 文件头损坏 / 找内嵌文件 | `Misc/文件头修复/`、`文件类型识别与提取/` |
| RSA 各种攻击 | `Crypto/RSA综合脚本利用/` 按已知条件选;先 `factordb.py -n` 试分解 |
| AES/DES/TEA 对称加密 | `Crypto/AES加解密模板/`、`DES_Python-master/`、`TEA加解密/` |
| 古典密码(摩斯/培根/栅栏/维吉尼亚/凯撒变体…) | `Crypto/` 对应目录 |
| Playfair / Hill / 敲击码 / 当铺 / 仿射 | `Crypto/Playfair密码/`、`Hill密码/`、`敲击码/`、`当铺密码/`、`仿射密码爆破/` |
| 拿到一串哈希不知道是什么类型 | `Crypto/哈希类型识别/hash_identify.py` |
| 文本行尾有可疑空格/Tab | `Encoding/行尾空白隐写/trailing_ws.py` |
| 维吉尼亚密文不知道密钥 | `Crypto/维吉尼亚密钥爆破/vigenere_brute.py`(IC+卡方自动破) |
| 密文全是 0 和 8(数字串按 0 分段) | `Crypto/云影密码/yunying.py` |
| Base64 解出来乱码 / 多次编码 / 换表 | `Encoding/Base/` 对应子工具 |
| hex 倒序 / 减偏移 / 二进制反转 | `Encoding/hex倒叙/`、`hex减位/`、`二进制每8位倒序/` |
| SQL 盲注 / SSTI / JWT / PHP 反序列化 | `Web/` 对应目录 |
| XXE(有回显/无回显外带/报错读文件) | `Web/XXE_payload生成/xxe_payloads.py` |
| .git / .DS_Store 泄露 | `Web/Git泄漏解析/`、`DS_Store解析/` |
| SSRF 打内网 Redis | `Web/gopher协议生成/` |
| SSTI 编码绕过 / 找 os 子类下标 | `Writeups/SSTI/` |
| Flask session cookie 看明文 | `Writeups/代码审计/flask-session解密/session.py` |
| md5 数字前缀校验 | `Writeups/代码审计/md5前缀爆破/EasySearch.py` |
| .htaccess 上传 LFI / strip_tags 崩溃 LFI | `Writeups/代码审计/htaccess上传LFI综合利用/`、`Writeups/文件包含/phpfilter崩溃LFI/` |
| 上传后文件名被 uniqid 重写 | `Writeups/文件上传/thinkphp上传文件名爆破/` |
| 仿射 / 希尔密码(含无密钥爆破) | `Crypto/仿射密码爆破/`、`Crypto/Hill密码/`(真题利用链见 `Writeups/文件包含/`) |
| URL 校验用 Unicode/IDNA 字符绕过 | `Writeups/文件包含/idna编码绕过探测/` |
| 约束求解 / 符号执行 / pyc 修复 | `Reverse/z3求解模板/`、`angr求解模板/`、`pyc文件头修复/` |
| 逆向 dump 出相邻异或数组 | `Reverse/相邻异或还原/xor.py` |
| ret2libc / 格式化字符串 / shellcode | `Pwn/pwntools模板/`、`Pwn/shellcode生成与解析/` |
| 栈溢出崩溃值求 padding 偏移 | `Pwn/溢出偏移定位/cyclic_offset.py`(--find 0x… 秒算) |
| LFI 日志包含提取 | `LogAnalysis/日志匹配/` |
| access log 统计/找攻击者/爆破 IP | `LogAnalysis/access_log分析/access_log_analyze.py` |
| 日志/脚本里 PowerShell -enc 编码命令 | `LogAnalysis/PowerShell编码命令解码/ps_decode.py` |
| .eml 邮件取证(头/正文/附件) | `Misc/EML邮件解析/eml_parse.py` |
| 字符画还原成图片(再扫码) | `Misc/ASCII字符画转图片/ascii2img.py` |
| Brainfuck / 迷宫 | `Misc/Python-Brainfuck-master/`、`robot迷宫求解/` |
| 一堆坐标画图出 flag | `Misc/坐标画图/coord_plot.py` |
| 安卓 Java/native 函数 hook、抓 Cipher 密钥 | `Reverse/Frida hook模板/frida_hook.py` |

## 依赖速查

核心:`requests` `pillow` `pycryptodome` `pyzipper` `numpy` `opencv-python` `z3-solver` `pyshark` `itsdangerous`
可选:`scapy` `pyzbar` `unicorn` `ds_store` `gmpy2` `libnum` `sympy` `owiener`
Pwn/符号执行(建议 WSL):`pwntools` `angr` `LibcSearcher`

不确定哪个脚本缺什么:`python check_env.py --missing`

## 关联项目与工具

| 项目 | 说明 | 位置 |
|---|---|---|
| CTF-misc-awd | AWD 攻防一体化工具(Rust) | 本机 `E:\Snow\Desktop\CTF\2026\local\CTF-misc-awd` |
| Fenjing | Jinja2 SSTI 自动化利用(本库 `Web/SSTI利用/` 的进阶替代) | 本机 `E:\Snow\Desktop\CTF\2026\local\CTF-Web-H\CTF-Web-H\Fenjing`,上游 [Marven11/Fenjing](https://github.com/Marven11/Fenjing) |
| changan-cup-forensics-kit | 长安杯取证工具箱(装机 / 分类启动 / 检材分析) | 本机 `workspace/2026/取证/changan-cup-forensics-kit` |
| ctf-tools | 常用工具本体(AntSword / CyberChef / DIE / dirsearch) | 本机 `workspace/2026/ctf-tools` |
| mohe-ctf(魔盒) | CTF 一站式工具箱(PyInstaller 打包,含工具镜像管理) | 本机 `workspace/2026/temp_repos/mohe-ctf` |
| blueteam-log-analyzer | 蓝队日志分析 CLI(本库 `LogAnalysis/` 的进阶替代) | 本机 `workspace/2026/temp_repos/blueteam-log-analyzer` |

## 更新日志

- **2026-11-21** 全库 195→211 个脚本。**新增 16 个高频题型脚本填补缺口**(全部带 docstring 用法与离线 `--selftest`,16 项自测实测全过;origin/upstream 无新提交):
  - `Crypto/Playfair密码/playfair.py` — Playfair 加解密(5x5 I/J 合并,自测含维基经典向量 BMODZ…);
  - `Crypto/Hill密码/hill.py` — Hill 任意 n 阶加解密(mod 26 伴随矩阵求逆,ACT→POH 经典向量);
  - `Crypto/仿射密码爆破/affine_brute.py` — 仿射 312 密钥全爆,卡方打分+flag/crib 置顶(自测真实还原 a=5,b=8);
  - `Crypto/敲击码/tapcode.py` — 敲击码编解码(5x5 K→C,数字对/点划混排);
  - `Crypto/当铺密码/dangpu.py` — 当铺密码(田0由1中2…春9)编解码,`--map` 兼容变体;
  - `Crypto/哈希类型识别/hash_identify.py` — 长度/前缀识别哈希类型+hashcat/john 命令速查+`--dict` 字典爆破;
  - `Encoding/行尾空白隐写/trailing_ws.py` — 行尾空格/Tab 隐写 3 种约定自动试解+编码写回;
  - `Steganography/GIF拆帧/gif_frames.py` — GIF 逐帧导出 PNG+帧延迟(自测内存合成 3 帧 GIF 验证);
  - `Steganography/音频频谱图/audio_spectrogram.py` — WAV→频谱图 PNG(numpy FFT),`--peak` 主峰频率(自测合成 440Hz 定位);
  - `Steganography/双图差分异或/img_diff.py` — 双图 diff/XOR 空间域盲水印还原(自动缩放对齐);
  - `Misc/ASCII字符画转图片/ascii2img.py` — 字符画按亮度梯度还原灰度图(字符画→图片→扫码题型);
  - `Misc/EML邮件解析/eml_parse.py` — .eml 头/正文/附件导出+flag 正则(纯标准库,自测内存构造邮件);
  - `LogAnalysis/PowerShell编码命令解码/ps_decode.py` — 日志中 `-enc`/`FromBase64String` 提取解码(蓝队取证);
  - `Web/XXE_payload生成/xxe_payloads.py` — XXE 六大模板参数化生成(文件读/PHP filter/OOB HTTP+FTP/报错回显);
  - `Pwn/溢出偏移定位/cyclic_offset.py` — De Bruijn 生成/崩溃值偏移定位,与 pwnlib cyclic 前缀通用(免 pwntools);
  - `TrafficeAnalysis/DNS隧道解析/dns_tunnel.py` — DNS 隧道子域名/TXT 提取+hex/base32/base64 自动解码(基于本地 pcaplib,自测含内存构造 pcap)。
  同步:分类表/特征速查/快速开始/SCRIPTS-INDEX 全量刷新;"仿射/希尔"速查条目改为指向 Crypto 主条目。
- **2026-11-20** 全库体检:32 个 `--selftest` 脚本实测全部通过,全库编译零错误,与 origin 同步。**新增 7 个脚本填补分类缺口**:
  - `LogAnalysis/access_log分析/access_log_analyze.py` — Nginx/Apache 日志统计(Top IP/URI/状态码)+ SQLi/扫描器/webshell/爆破检测(蓝队/取证题型,LogAnalysis 此前仅 1 个脚本);
  - `TrafficeAnalysis/ICMP数据提取/icmp_data.py` — 纯标准库 ICMP echo payload 提取(4 种链路层,自测含内存构造 pcap 回解),并挂入 `solve.py` 一键入口(无常见端口但有 ICMP 时自动调用);
  - `Steganography/文件尾数据检测/carve_tail.py` — PNG/JPG/GIF/ZIP/PDF 尾部附加数据检测/导出/剥离;
  - `Misc/坐标画图/coord_plot.py` — 坐标文本画图(一行多坐标对、多笔画分隔、自动归一化翻转 Y);
  - `Crypto/云影密码/yunying.py` — 云影密码(0/8)编解码;
  - `Crypto/维吉尼亚密钥爆破/vigenere_brute.py` — 重合指数定密钥长 + 卡方频率定移位,无密钥自动破(自测含真实英文语料爆破还原);
  - `Reverse/Frida hook模板/frida_hook.py` — Frida hook JS 生成器(java/native/crypto/replace 4 类模板,不依赖 frida 运行时即可生成)。
  全部带 docstring 用法与离线 `--selftest`(共 7 个新增自测);同步更新特征速查/依赖说明;上游 zelat/ctf-scripts 无新提交。
- **2026-11-19** 收录 Des-CTF-Knowledge `WP汇总` 全部 12 个真题做题脚本,新增 **Writeups/** 分类(SSTI/代码审计/文件上传/文件包含,各题型目录保留原题解 README,新分类使用说明见 [Writeups/README.md](Writeups/README.md));补收 `Reverse/相邻异或还原/xor.py`(全库比对确认此前仅漏这两处)。新脚本按仓库规范补齐 docstring / `--url` 参数化 / 离线 `--selftest`(1.py、EasySearch、session、tpupload2、affine、hill、idna、xor 共 8 个新增自测)。`gen_index.py`、`check_env.py` 增补 itsdangerous/flask 依赖映射,requirements.txt 加入 itsdangerous;上游 zelat/ctf-scripts 无新提交。

- **2026-11-13** 全库体检:175 个脚本 Python3 语法全部通过,17 个带 `--selftest` 的脚本实测全部 OK;新增 `gen_index.py` 一键生成全量索引 [SCRIPTS-INDEX.md](SCRIPTS-INDEX.md)(176 个脚本逐个列出说明/依赖/自测,`--check` 可进 CI);新增 GitHub Actions CI(全库语法编译 + 索引一致性检查)与 `.gitattributes` 统一换行;README 增加关联项目章节;补装 libnum / sympy / owiener / rsa 轻依赖。
- **2026-11-12** 收录 Des-CTF-Knowledge 全量做题脚本:新增 Crypto/Encoding/Web/Pwn/Reverse/Misc 六大类与 Steganography/TrafficeAnalysis/LogAnalysis 补充工具共 86 个目录;新增 `check_env.py` 依赖自检;重写 README 分类索引。
