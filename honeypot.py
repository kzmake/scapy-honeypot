#!/usr/bin/env python
# coding: utf-8

from scapy.all import *
from scapy.layers.inet import IP, TCP, Raw

from settings import *


def is_tcp_packet(packet: Packet) -> bool:
    """TCPパケットかを判定する.

    Args:
        packet: scapy で取得したパケット.

    Returns:
        TCPパケットであれば True, そうでなければ False を返却する.
    """
    return packet.haslayer(IP) and packet.haslayer(TCP)


def has_ip_address(packet: Packet, ip_address: str) -> bool:
    """パケットの src/dst の IpAddress が ip_address かを判定する.

    Args:
        packet: scapy で取得したパケット.
        ip_address: IpAddress.

    Returns:
        パケットの src/dst が指定された IpAddress であれば True, そうでなければ False を返却する.
    """
    i = packet[IP]
    return ip_address in (i.src, i.dst)


def has_port(packet: Packet, port: int) -> bool:
    """パケットの sport/dport が Port かを判定する.

    Args:
        packet: scapy で取得したパケット.
        port: Port.

    Returns:
        パケットの sport/dport が指定された Port であれば True, そうでなければ False を返却する.
    """
    t = packet[TCP]
    return port in (t.sport, t.dport)


def make_filter(packet: Packet) -> bool:
    """パケットをスニッフィングするためのフィルターを作成する.

    Args:
        packet: scapy で取得したパケット.

    Returns:
        フィルタ対象のパケットであれば True, そうでなければ False を返却する.
    """
    return is_tcp_packet(packet) and has_ip_address(packet, IP_ADDRESS) and not has_port(packet, SSH_PORT)


def find_packet(packet: Packet):
    """スニッフィングしたパケットを処理する.

    Args:
        packet: scapy で取得したパケット.
    """
    # packet.show()

    ip = packet[IP]
    tcp = packet[TCP]
    flags = tcp.flags

    print(f"[Recv sniffed packet: {flags}] {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}")

    if flags == "S":
        i = IP(src=ip.dst, dst=ip.src)
        t = TCP(sport=tcp.dport, dport=tcp.sport, flags='SA', seq=random.randint(1, 45536), ack=(tcp.seq + 1))
        frame = i / t
        send(frame, verbose=False)

        print(f"[Send dummy packet: SYN/ACK] {i.src}:{t.sport} -> {i.dst}:{t.dport}")

    elif 'P' in list(str(flags)):
        i = IP(src=ip.dst, dst=ip.src)
        t = TCP(sport=tcp.dport, dport=tcp.sport, flags='A', seq=tcp.ack, ack=(tcp.seq + len(packet)))
        frame = i / t
        send(frame, verbose=False)

        print("[Send dummy packet: ACK]", i.src, t.sport, " -> ", i.dst, t.dport)

    # データもってたら表示してみる
    if packet.haslayer(Raw):
        packet[Raw].show()


# sniffing 開始
sniff(prn=find_packet, lfilter=make_filter, store=0)
