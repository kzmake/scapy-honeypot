#!/usr/bin/env python

import hashlib

from scapy.all import *
from scapy.layers.inet import IP, TCP, Raw

from filter import is_tcp_packet, has_ip_address
from settings import *
from sniffer import Sniffer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('honeypot')

if LOGGER == 'fluent':
    from fluent import handler
    import msgpack
    from io import BytesIO

    def overflow_handler(pendings):
        unpacker = msgpack.Unpacker(BytesIO(pendings))
        for unpacked in unpacker:
            print(unpacked)


    fluent_format = {
        'host': '%(hostname)s',
        'where': '%(module)s.%(funcName)s',
        'type': '%(levelname)s',
        'stack_trace': '%(exc_text)s'
    }

    h = handler.FluentHandler('pot.packet', host=FLUENT_HOST, port=FLUENT_PORT, buffer_overflow_handler=overflow_handler)
    formatter = handler.FluentRecordFormatter(fluent_format)
    h.setFormatter(formatter)
    logger.addHandler(h)


def logging_packet(packet: Packet):
    ip = packet[IP]
    tcp = packet[TCP]
    flags = tcp.flags

    if ip.src == TARGET_IP_ADDRESS:
        gid = hashlib.sha256(f"{ip.src}:{tcp.sport} > {ip.dst}:{tcp.dport}".encode()).hexdigest()
    else:
        gid = hashlib.sha256(f"{ip.dst}:{tcp.dport} > {ip.src}:{tcp.sport}".encode()).hexdigest()

    if packet.haslayer(Raw):
        payload = str(packet[Raw].load)
    else:
        payload = ''

    logger.info(
        {
            'gid': str(gid),
            'recv_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'country_code': 'JP',
            'flag': str(flags),
            'src': str(ip.src),
            'dst': str(ip.dst),
            'sport': str(tcp.sport),
            'dport': str(tcp.dport),
            'summary': str(packet.summary()),
            'payload': payload
        })


def find_tcp_packet(packet: Packet):
    """スニッフィングしたパケットを処理する.

    Args:
        packet: scapy で取得したパケット.
    """
    # packet.show()

    ip = packet[IP]
    tcp = packet[TCP]
    flags = tcp.flags

    logging_packet(packet)

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
