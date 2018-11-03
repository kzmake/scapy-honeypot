#!/usr/bin/env python
# coding: utf-8

import hashlib

from scapy.all import *
from scapy.layers.inet import IP, TCP, Raw

from filter import is_tcp_packet, has_ip_address
from settings import *
from sniffer import Sniffer


def find_tcp_packet(packet: Packet):
    """スニッフィングしたパケットを処理する.

    Args:
        packet: scapy で取得したパケット.
    """
    # packet.show()

    ip = packet[IP]
    tcp = packet[TCP]
    flags = tcp.flags

    if ip.src == TARGET_IP_ADDRESS:
        uid = hashlib.sha256(f"{ip.src}:{tcp.sport} > {ip.dst}:{tcp.dport}".encode()).hexdigest()
        print(f"[Packet] {uid} Send {packet.summary()}")
    else:
        uid = hashlib.sha256(f"{ip.dst}:{tcp.dport} > {ip.src}:{tcp.sport}".encode()).hexdigest()
        # データもってたら表示してみる
        if packet.haslayer(Raw):
            print(f"[Packet] {uid} Recv {packet.summary()} {packet[Raw].load}")
        else:
            print(f"[Packet] {uid} Recv {packet.summary()}")

    if flags == "S":
        i = IP(src=ip.dst, dst=ip.src)
        t = TCP(sport=tcp.dport, dport=tcp.sport, flags='SA', seq=random.randint(1, 45536), ack=(tcp.seq + 1))
        frame = i / t
        send(frame, verbose=False)

    elif 'P' in list(str(flags)):
        i = IP(src=ip.dst, dst=ip.src)
        t = TCP(sport=tcp.dport, dport=tcp.sport, flags='A', seq=tcp.ack, ack=(tcp.seq + len(packet)))
        frame = i / t
        send(frame, verbose=False)


if __name__ == "__main__":
    # sniff filter
    print(f"Filter: TCP and IpAddress: {TARGET_IP_ADDRESS}")

    # フィルタ作成
    packet_filter = lambda p: is_tcp_packet(p) and has_ip_address(p, TARGET_IP_ADDRESS)

    # sniffing用Thread作成・実施
    sniffer = Sniffer(prn=find_tcp_packet, packet_filter=packet_filter)
    sniffer.run()
