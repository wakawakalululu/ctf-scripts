# TrafficeAnalysis — CTF 流量分析脚本集

对应《CTF流量分析 wireshark之题型深度解析》的全部题型,每个脚本**可直接运行出解答**。
依赖:仅 Python 3 标准库 + Pillow(画鼠标轨迹用);装有 Wireshark(tshark)时自动用
tshark 提取,没有也能用内置纯 Python 解析器,双引擎结果一致。

## 题型 → 脚本对照表

| 题型(文章章节) | 脚本 | 用法 | 关键原理 |
|---|---|---|---|
| 流量包修复 | `pcapfix.py` | `python pcapfix.py broken.cap [fixed.pcap]` | 重建全局头魔数/丢弃截断尾包 |
| WEB扫描分析 | `find_scanner.py` | `python find_scanner.py x.pcap` | UA/路径/报文匹配 awvs、sqlmap、dirbuster 等特征(等价 `http contains`) |
| 后台目录爆破 | `find_admin_url.py` | `python find_admin_url.py x.pcap` | URL 频次统计 + admin/login 关键字 + 200/302 打分 |
| 后台账号爆破 | `find_login.py` | `python find_login.py x.pcap` | 提取所有 POST 账号密码参数,按 302/Set-Cookie 判定登录成功 |
| WEBSHELL上传 | `find_webshell.py` | `python find_webshell.py x.pcap [导出目录]` | multipart 解析文件名/内容 + eval/system 关键字 + base64 payload 解码 |
| USB键盘流量 | `usb_keyboard.py` | `python usb_keyboard.py x.pcap [--raw]` | usb.capdata 8字节 HID 报告 → 键码映射(含Shift),自动高亮 flag/数字密码 |
| USB鼠标流量 | `usb_mouse.py` | `python usb_mouse.py x.pcap [out.png]` | 4字节 HID 报告累积坐标 → PIL 画轨迹图(all/left/right 三种模式) |
| SMTP/POP3邮件 | `smtp_mail.py` | `python smtp_mail.py x.pcap [导出目录]` | DATA 段 MIME 解析、RFC2047 头解码、base64/QP 正文、附件导出 |
| Telnet明文 | `telnet_session.py` | `python telnet_session.py x.pcap` | 剥 IAC 协商字节,按包序交错还原会话,自动配对 login:/Password: |
| ICMP隐写传数据 | `ICMP数据提取/icmp_data.py` | `python icmp_data.py x.pcap [--save out.bin --hex]` | 纯标准库解析 echo request/reply payload,拼接+flag 搜索(支持 4 种链路层) |
| 文件提取(通用) | `extract_objects.py` | `python extract_objects.py x.pcap [导出目录]` | HTTP 对象导出 + 全流量按魔数切割(png/jpg/zip/pdf...) |
| **一键自动分析** | `solve.py` | `python solve.py x.pcap` | 识别流量类型 → 调用对应脚本 → 汇总所有 flag |

`solve.py` 识别规则:USB 链路层(usbmon 220 / USBPcap 249)→ USB 套件;
23 端口 → telnet;25/110/587 → mail;80/8080 → web;仅有 ICMP echo 无常见端口时 → icmp_data;
无法解析先自动 pcapfix;最后做全文 flag 正则 + base64 候选搜索兜底。

## 2026-11 新增子工具

| 脚本 | 用途 | 用法 |
|---|---|---|
| `USB鼠标流量解析/usb_mouse.py` | HID 鼠标数据还原轨迹/点击画图(参考 UsbmiceCracker) | `python usb_mouse.py -f usb.pcap -p 3 --mode all`;无参数 `--selftest` 自测 |
| `usb流量/usbtxt.py` | USB HID 键盘码→字符(数据放 usbdata.txt) | 修改数据文件后运行 |
| `流量数据提取脚本/1.py` | scapy 提取 ICMP 回显 payload(依赖 scapy) | 修改脚本内 pcap 路径后运行 |
| `TTL隐写/` | IP TTL 字段隐写编解码(常见值 63/127/191/255) | `python TTL-stego.py`(数据放 out.txt);`TTL-encode.py` 编码 |

## 快速开始

```bash
# 1. 生成全部题型的测试流量包(自带答案,用于验证/学习)
python make_samples.py

# 2. 一键分析任意流量包
python solve.py samples/usb_keyboard.pcap
python solve.py samples/web_attack.pcap

# 3. 或按题型单独运行(见上表)
python usb_keyboard.py samples/usb_keyboard.pcap
python find_webshell.py samples/web_attack.pcap
```

## samples/ 自带样例(生成时即含答案)

| 文件 | 内容 | 预期答案 |
|---|---|---|
| `web_attack.pcap` | AWVS扫描 + DirBuster目录爆破 + 登录爆破 + webshell上传 | `flag{welc0me_t0_admin}` 等3个;扫描器 AWVS/DirBuster;后台 `/admin/login.php`;账密 `admin/admin123`;webshell `muma.php` |
| `usb_keyboard.pcap` | HID 键码输入(混入摄像头/鼠标无关流量) | `flag{u5b_k3yb0ard_ftw}` |
| `usb_mouse.pcap` | HID 位移轨迹画字 | 轨迹图为 `FLAG` 字样 |
| `mail.pcap` | SMTP 邮件,base64 正文+附件 | `flag{ma1l_h1d3s_secr3t}` |
| `telnet.pcap` | 明文登录(root/toor)含 IAC 协商 | `flag{telnet_1s_plaint3xt}` |
| `broken.pcap` | 魔数破坏+尾包截断的损坏包 | `pcapfix.py` 修复后可正常分析 |

## 公共库 `pcaplib.py`

所有脚本的底座,也可独立使用:

- `read_pcap()` / `build_streams()` / `parse_http_stream()` / `iter_http()`
- `iter_usb()` 支持 Linux usbmon(220) 与 USBPcap(249) 两种 USB 链路层
- `decode_hid_keyboard()` HID 键码→字符(含 Shift 变换)
- `tshark_fields()` 可选 tshark 增强;`find_flags()` flag 正则搜索

## 实战备忘(等价 tshark 命令)

```
http contains "acunetix"                      # 找扫描器
http.request.method=="POST" && http contains "admin"   # 找登录
tshark -r usb.pcap -T fields -e usb.capdata   # USB 第一步提数据
```
