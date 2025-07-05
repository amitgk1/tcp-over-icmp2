#!/usr/bin/env python3
import ipaddress
import logging
import socket
import threading
from typing import cast

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet as NFQPacket
from scapy.all import Raw, conf, get_if_addr
from scapy.layers.inet import ICMP, IP, TCP

# your server’s public IP (the decap box)
SERVER_IP = "192.168.1.61"
CLIENT_PRIVATE = get_if_addr(conf.iface)

# ID for our echo messages
ICMP_ID = 0x1234  # os.getpid() & 0xFFFF
seq_out = 0

# ICMP socket for echo-requests
sock_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock_icmp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

logging.getLogger().setLevel(logging.INFO)

# build a small BLACKLIST of dest‐nets we do NOT want to tunnel:
BLACKLIST = [
    ipaddress.ip_network("127.0.0.0/8"),  # lo
    # ipaddress.ip_network("10.0.0.0/8"),  # private
    # ipaddress.ip_network("192.168.0.0/16"),  # private
    # ipaddress.ip_network(SERVER_IP + "/32"),  # the tunnel server itself
]

NUM_QUEUES = 4


def start_worker(qnum: int, callback):
    nf = NetfilterQueue()
    nf.bind(qnum, callback, max_len=4096)
    try:
        nf.run()
    except KeyboardInterrupt:
        pass
    finally:
        nf.unbind()


def normalize_and_nat_local(inner: bytes) -> bytes:
    """Re‐write dst→CLIENT_PRIVATE, recalc checksums."""
    p = cast(IP, IP(inner))
    p.dst = CLIENT_PRIVATE
    # force recompute
    del p.len, p.chksum
    del p[TCP].chksum
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
        icmp = (
            IP(dst=SERVER_IP) / ICMP(type=8, code=0, id=ICMP_ID, seq=seq_out) / Raw(raw)
        )

        sock_icmp.sendto(bytes(icmp), (SERVER_IP, 0))
        seq_out = (seq_out + 1) & 0xFFFF
        nf_pkt.drop()
        return

    # 2) Incoming ICMP echo‐reply → unwrap & inject
    if ip.proto == 1 and ip[ICMP].type == 0 and ip[ICMP].id == ICMP_ID:
        logging.debug("incoming icmp reply with tunnel code")
        inner = bytes(ip[ICMP].payload)
        fixed = normalize_and_nat_local(inner)
        nf_pkt.set_payload(fixed)
        nf_pkt.accept()
        return

    # otherwise leave untouched
    nf_pkt.accept()


if __name__ == "__main__":
    threads = [
        threading.Thread(target=start_worker, args=(q, client_cb), daemon=True)
        for q in range(NUM_QUEUES)
    ]
    try:
        logging.info("Client tunnel up. Ctrl-C to quit.")
        for t in threads:
            t.start()
    finally:
        for t in threads:
            t.join()
