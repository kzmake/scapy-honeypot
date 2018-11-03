from scapy.all import *
from scapy.layers.inet import IP, TCP


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
