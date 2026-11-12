# ctf-scripts

CTF 做题脚本集:100+ 现成脚本,覆盖 **Web / Pwn / Reverse / Crypto / Misc / 隐写 / 流量 / 日志** 八大类。
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
└── files/                  # 示例流量包(capture.pcap / Modbus.pcap 等)
```

## 快速开始

```bash
# 一键流量分析(自动识别 USB/WEB/邮件/Telnet)
python TrafficeAnalysis/solve.py TrafficeAnalysis/samples/usb_keyboard.pcap

# 任意脚本先跑自测(较新脚本支持)
python Crypto/摩斯密码/morse.py
python Web/JWT伪造/jwt_forge.py --selftest

# 实战示例
python Misc/zip伪加密修复/zip_fix.py fake_enc.zip --fix
python Steganography/二维码解码/qr_decode.py flag.png
```

> 找某个具体脚本?全量 176 个 .py 的自动索引见 [SCRIPTS-INDEX.md](SCRIPTS-INDEX.md)
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
| `频域盲水印/pinyubwm.py` | 频域盲水印提取(opencv) | `python pinyubwm.py --original 原图 --image 水印图 --result out.png` |
| `图片爆破宽高/` | PNG IHDR 宽高 CRC32 爆破恢复 | 修改脚本内 CRC 值与图片路径后运行 |
| `PNG结构分析/png_analyze.py` | PNG 块列举/提取+CRC 批量修复+tEXt 预览 | `python png_analyze.py list x.png` / `fix-crc` |
| `GIF帧时间隐写/gif_frames.py` | GIF 帧分离+延时离群分析(MAD) | `python gif_frames.py -f x.gif --odd` |
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
| `双参数爆破脚本/brust.py` | 双参数组合爆破(如邀请码+用户ID) | 修改脚本内 url 与参数列表后运行 |

## Reverse/ — 逆向

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `z3求解模板/z3_template.py` | z3 约束求解:Int 方程组/BitVec XOR/Sum 三种模式 | 改脚本内约束后运行(依赖 z3-solver) |
| `angr求解模板/angr_template.py` | angr 符号执行标准模板(stdin 符号注入) | 改脚本内路径/地址后运行(建议 WSL) |
| `angr虚拟机混淆解题/burforce_vm.py` | angr 爆破 VM 混淆题(地址参数化) | `python burforce_vm.py 二进制 --find ADDR --avoid ADDR` |
| `pyc文件头修复/pyc_fix.py` | pyc 头修复(2.7~3.13 magic 表,自动探测头长/版本) | `python pyc_fix.py broken.pyc -o fixed.pyc` |
| `ARM模拟调试器/arm_dbg.py` | unicorn ARM 模拟调试(断点/单步/内存 dump) | `python arm_dbg.py --demo`;实战改 `run_demo()` 后 `--demo` 进入交互 |

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
| `robot迷宫求解/robot_maze.py` | 文本/图片迷宫求解最短路+随机迷宫生成 | `python robot_maze.py --solve maze.txt` / `--pic maze.png` |
| `迷宫路径记录GUI/maze_run.py` | 方向键走迷宫,记录 wasd 序列(GUI) | `python maze_run.py --chars 起点,终点,墙 --out out.txt` |
| `数学题/取模/` | 取模等数学计算辅助 | 改数据运行 |
| `一些比赛的脚本/祥云杯-xixixi/` | 比赛真题脚本 | 按题修改运行 |
| `emoji/` | emoji-aes 加解密(JS 实现) | 参见其 js 文件 |

## LogAnalysis/ — 日志分析

| 脚本/目录 | 用途 | 用法 |
|---|---|---|
| `日志匹配/1.py` | 从 URL 编码的 LFI 日志中提取被包含文件的输出 | 日志放 `data.txt` 后运行 |

---

## 特征速查:遇到什么用什么

| 你遇到的 | 用什么 |
|---|---|
| pcap 有 USB 键盘/鼠标流量 | `TrafficeAnalysis/usb_keyboard.py`、`usb_mouse.py` |
| pcap 里 TTL 值奇怪(63/127/191/255) | `TrafficeAnalysis/TTL隐写/` |
| pcap 要提文件/扫描器/账密/webshell | `TrafficeAnalysis/extract_objects.py`、`find_*.py`(或直接 `solve.py` 一键) |
| pcap 有邮件/Telnet | `TrafficeAnalysis/smtp_mail.py`、`telnet_session.py` |
| 流量包损坏打不开 | `TrafficeAnalysis/pcapfix.py` |
| 图片打不开/尺寸不对 | `Steganography/图片爆破宽高/`、`PNG结构分析/png_analyze.py` |
| PNG LSB / 盲水印 / steghide / 零宽 | `Steganography/` 对应目录 |
| GIF 帧延时 / 音频摩斯 / 二维码 | `Steganography/GIF帧时间隐写/`、`音频摩斯解析/`、`二维码解码/` |
| 数据是 0/1 矩阵 / RGB 元组 / 图片序列 | `字节转二维码/`、`RGB转图片/`、`红绿灯-二进制/` |
| 内存 dump 还原图片 | `Steganography/内存数据转图片/img_solve.py` |
| ZIP 伪加密 / 爆破 / 多层嵌套 | `Misc/zip伪加密修复/`、`zip密码爆破/`、`批量解压压缩包+带密码/` |
| ZIP 内小文件 CRC 已知爆内容 | `Misc/CRC32校验爆破/` |
| 文件头损坏 / 找内嵌文件 | `Misc/文件头修复/`、`文件类型识别与提取/` |
| RSA 各种攻击 | `Crypto/RSA综合脚本利用/` 按已知条件选;先 `factordb.py -n` 试分解 |
| AES/DES/TEA 对称加密 | `Crypto/AES加解密模板/`、`DES_Python-master/`、`TEA加解密/` |
| 古典密码(摩斯/培根/栅栏/维吉尼亚/凯撒变体…) | `Crypto/` 对应目录 |
| Base64 解出来乱码 / 多次编码 / 换表 | `Encoding/Base/` 对应子工具 |
| hex 倒序 / 减偏移 / 二进制反转 | `Encoding/hex倒叙/`、`hex减位/`、`二进制每8位倒序/` |
| SQL 盲注 / SSTI / JWT / PHP 反序列化 | `Web/` 对应目录 |
| .git / .DS_Store 泄露 | `Web/Git泄漏解析/`、`DS_Store解析/` |
| SSRF 打内网 Redis | `Web/gopher协议生成/` |
| 约束求解 / 符号执行 / pyc 修复 | `Reverse/z3求解模板/`、`angr求解模板/`、`pyc文件头修复/` |
| ret2libc / 格式化字符串 / shellcode | `Pwn/pwntools模板/`、`Pwn/shellcode生成与解析/` |
| LFI 日志包含提取 | `LogAnalysis/日志匹配/` |
| Brainfuck / 迷宫 | `Misc/Python-Brainfuck-master/`、`robot迷宫求解/` |

## 依赖速查

核心:`requests` `pillow` `pycryptodome` `pyzipper` `numpy` `opencv-python` `z3-solver` `pyshark`
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

## 更新日志

- **2026-11-13** 全库体检:175 个脚本 Python3 语法全部通过,17 个带 `--selftest` 的脚本实测全部 OK;新增 `gen_index.py` 一键生成全量索引 [SCRIPTS-INDEX.md](SCRIPTS-INDEX.md)(176 个脚本逐个列出说明/依赖/自测,`--check` 可进 CI);README 增加关联项目章节;补装 libnum / sympy / owiener / rsa 轻依赖。
- **2026-11-12** 收录 Des-CTF-Knowledge 全量做题脚本:新增 Crypto/Encoding/Web/Pwn/Reverse/Misc 六大类与 Steganography/TrafficeAnalysis/LogAnalysis 补充工具共 86 个目录;新增 `check_env.py` 依赖自检;重写 README 分类索引。
