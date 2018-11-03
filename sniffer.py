from scapy.all import *


class Sniffer:
    def __init__(self, prn=None, packet_filter=None):
        # フィルタの設定
        if filter:
            self.packet_filter = packet_filter
        else:
            self.packet_filter = lambda: True

        # print設定
        if prn:
            self.prn = prn
        else:
            self.prn = lambda p: f"{p.summary()}"

    def run(self):
        # 別スレッドで実施
        thread = threading.Thread(target=self._sniff)
        thread.start()

    def _sniff(self):
        # sniffing
        sniff(prn=self.prn, lfilter=self.packet_filter, store=False)
