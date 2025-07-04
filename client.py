#!/usr/bin/env python3
import ipaddress
import logging
from typing import cast

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet as NFQPacket
from scapy.all import Raw, conf, get_if_addr, send
from scapy.layers.inet import ICMP, IP

# your server’s public IP (the decap box)
SERVER_IP = "192.168.1.61"
CLIENT_PRIVATE = get_if_addr(conf.iface)

# ID for our echo messages
ICMP_ID = 0x1234  # os.getpid() & 0xFFFF
seq_out = 0

logging.getLogger().setLevel(logging.DEBUG)

# build a small BLACKLIST of dest‐nets we do NOT want to tunnel:
BLACKLIST = [
    ipaddress.ip_network("127.0.0.0/8"),  # lo
    # ipaddress.ip_network("10.0.0.0/8"),  # private
    # ipaddress.ip_network("192.168.0.0/16"),  # private
    # ipaddress.ip_network(SERVER_IP + "/32"),  # the tunnel server itself
]


def normalize_for_local(inner_bytes: bytes):
    p = IP(inner_bytes)
    # rewrite the dst to your private client IP
    p.dst = CLIENT_PRIVATE
    # delete old length/checksums so Scapy recalcs them
    del p.len, p.chksum
    if p.haslayer(Raw):  # strip Raw so checksums get recomputed
        pass
    if p.haslayer(IP):
        # ensure TCP checksum is also cleared
        if p.haslayer("TCP"):
            del p["TCP"].chksum
    # you can also reset ttl if you like
    p.ttl = max(p.ttl, 64)
    return bytes(p)


def should_wrap_tcp(ip_pkt: IP) -> bool:
    # Only IPv4 TCP, dest not in BLACKLIST
    if ip_pkt.proto != 6:
        return False
    dst = ipaddress.IPv4Address(ip_pkt.dst)
    return not any(dst in net for net in BLACKLIST)


def client_cb(nf_pkt: NFQPacket):
    global seq_out
    raw = nf_pkt.get_payload()
    ip = cast(IP, IP(raw))

    # 1) Outgoing TCP → wrap in ICMP echo‐request
    if should_wrap_tcp(ip):
        logging.debug(f"outgoing tcp packet {ip.summary()}")
        inner = raw
        icmp = (
            IP(dst=SERVER_IP)
            / ICMP(type=8, code=0, id=ICMP_ID, seq=seq_out)
            / Raw(inner)
        )
        send(icmp, verbose=True)
        seq_out = (seq_out + 1) & 0xFFFF
        nf_pkt.drop()
        return

    # 2) Incoming ICMP echo‐reply → unwrap & inject
    if ip.proto == 1 and ip[ICMP].type == 0 and ip[ICMP].id == ICMP_ID:
        logging.debug("incoming icmp reply with tunnel code")
        inner = bytes(ip[ICMP].payload)
        fixed = normalize_for_local(inner)
        nf_pkt.set_payload(fixed)
        nf_pkt.accept()
        return

    # otherwise leave untouched
    nf_pkt.accept()


if __name__ == "__main__":
    nf = NetfilterQueue()
    nf.bind(1, client_cb)
    print("Client tunnel up. Ctrl-C to quit.")
    try:
        nf.run()
    except KeyboardInterrupt:
        pass
    finally:
        nf.unbind()
