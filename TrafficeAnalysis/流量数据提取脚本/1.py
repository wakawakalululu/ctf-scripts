# -*- coding: utf-8 -*-
"""从 pcap 提取 ICMP 回显响应(type 0) payload 末 8 字节(py3 移植版)

依赖: pip install scapy
用法: python 1.py out.pcapng
     修改脚本中的过滤条件以适配题目。
"""
import sys

from scapy.all import ICMP, rdpcap

if len(sys.argv) >= 2:
    pcap_file = sys.argv[1]
else:
    pcap_file = 'out.pcapng'

packets = rdpcap(pcap_file)

for packet in packets:
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 0:
            print(packet[ICMP].load[-8:])
