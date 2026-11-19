# Writeups/ — WP 实战做题脚本

收录自 Des-CTF-Knowledge 的**比赛/靶场真题做题脚本**(`WP汇总` 与 `CTF常用脚本及工具/reverse` 中此前漏收的部分)。
每个子目录 = 一个题型场景,脚本保留原 WP 写法并按仓库规范补了 docstring / 参数化 / 离线自测;
**各题型目录下的 `README.md` 是原始题解笔记**,写题目背景与完整利用链,先读它再套脚本。

> 原脚本多数硬编码了 buuoj 靶场地址(实例早已销毁),复用时替换 `--url` 参数即可。

## SSTI

| 脚本 | 对应题目/场景 | 用法 |
|---|---|---|
| `自定义字符集异或编码/1.py` | [pasecactf_2019]flask_ssti(编码绕过) | `python 1.py`(内置密文直接还原)/ `-c 密文 -k key1 -k2 key2`;encode 自逆,再套一次即解码 |
| `遍历子类找os索引/SSTIFindSubprocess.py` | [CSCCTF 2019]FlaskLight 等需要定位 `__subclasses__()` 下标 | `python SSTIFindSubprocess.py -u "http://x/?search=" -k os --limit 1000`(需网络) |

## 代码审计

| 脚本 | 对应题目/场景 | 用法 |
|---|---|---|
| `md5前缀爆破/EasySearch.py` | [BJDCTF2020]EasySearch(md5 前缀校验) | `python EasySearch.py`(默认爆 deadbeef 前缀)/ `--prefix xxx --max 10^7` / `--all` 列全部 |
| `htaccess上传LFI综合利用/EasyWeb.py` | [SUCTF 2019]EasyWeb(取反绕过+.htaccess+php://filter) | `python EasyWeb.py -u "http://x/?_=<payload>&...=get_the_flag"`(需网络);链路见脚本 docstring |
| `flask-session解密/session.py` | Flask 题:拿到 session cookie 直接看明文 | `python session.py "ey...sig"` / `--selftest`;伪造见 `Web/JWT伪造/jwt_forge.py`(依赖 itsdangerous) |

## 文件上传

| 脚本 | 对应题目/场景 | 用法 |
|---|---|---|
| `thinkphp上传文件名爆破/tpupload.py` | [RoarCTF 2019]Simple Upload(uniqid 文件名不回显) | `python tpupload.py -u "http://x/Public/Uploads/" --prefix 62189f4 --start 234 --mid bcdef --tail 1234567890abcdef`(需网络) |
| `thinkphp上传文件名爆破/tpupload2.py` | 同上:由泄露出的一头一尾字符算中间候选集 | `python tpupload2.py -a 4 -b e`;`--selftest` |

## 文件包含

| 脚本 | 对应题目/场景 | 用法 |
|---|---|---|
| `仿射密码爆破/affine_cipher.py` | 仿射密码(Affine)题:加密 / 全组合爆破 | `python affine_cipher.py -e -m "flag{}" -a 5 -b 8` / `python affine_cipher.py -c "密文" --marker fla` |
| `希尔密码加解密/hill_cipher.py` | 希尔密码(Hill)题:矩阵加密与模 26 逆矩阵解密 | `python hill_cipher.py`(跑示例)/ `--selftest`(依赖 numpy) |
| `idna编码绕过探测/idna_unicode_bypass.py` | [SUCTF 2019]Pythonginx(IDNA 字符绕过 URL 校验) | `python idna_unicode_bypass.py`(全量 128~65537)/ `--start --end` 限范围 |
| `phpfilter崩溃LFI/lfi_php_filter_exploit.py` | [WMCTF2020]Make PHP Great Again(strip_tags 崩溃留临时文件) | `python lfi_php_filter_exploit.py -u "http://x/fl.php?file=php://filter/string.strip_tags/resource=/etc/passwd" -p "<?php ..."`(需网络) |

## 特征速查

| 你遇到的 | 用什么 |
|---|---|
| SSTI payload 有自定义字符集/编码 | `SSTI/自定义字符集异或编码/1.py` |
| SSTI 要找 `__subclasses__()` 里 os 的下标 | `SSTI/遍历子类找os索引/SSTIFindSubprocess.py` |
| md5(数字) 前缀/截断校验 | `代码审计/md5前缀爆破/EasySearch.py` |
| 拿到 Flask session cookie 想看明文 | `代码审计/flask-session解密/session.py` |
| .htaccess 可上传 + auto_append_file LFI | `代码审计/htaccess上传LFI综合利用/EasyWeb.py` |
| 上传后文件名被 uniqid 重写不回显 | `文件上传/thinkphp上传文件名爆破/`(tpupload + tpupload2 配合) |
| 仿射 / 希尔密码 | `文件包含/仿射密码爆破/`、`文件包含/希尔密码加解密/` |
| URL 校验可被 Unicode/IDNA 字符绕过 | `文件包含/idna编码绕过探测/idna_unicode_bypass.py` |
| php://filter strip_tags 崩溃临时文件 LFI | `文件包含/phpfilter崩溃LFI/lfi_php_filter_exploit.py` |
