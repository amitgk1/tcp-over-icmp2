#!/usr/bin/env python3
import logging
import socket
import threading
from typing import cast

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet as NFQPacket
from scapy.all import Raw, conf, get_if_addr
from scapy.layers.inet import ICMP, IP, TCP

SERVER_IP = get_if_addr(conf.iface)
CLIENT_IP = "192.168.1.152"

ICMP_ID = 0x1234  # os.getpid() & 0xFFFF
seq_reply = 0

logging.getLogger().setLevel(logging.INFO)

# ICMP socket for echo-reply
sock_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock_icmp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# RAW IP socket for forwarding the unwrapped inner packet
sock_ip = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
# tell kernel we include our own IP header
sock_ip.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

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


def clamp_mss(pkt: IP, mss: int = 1000):
    """If pkt is TCP-SYN, replace any MSS with our small one."""
    if TCP in pkt and (pkt[TCP].flags & 0x2):  # SYN
        opts = pkt[TCP].options or []
        opts = [o for o in opts if o[0] != "MSS"]
        opts.insert(0, ("MSS", mss))
        pkt[TCP].options = opts


def normalize_and_forward(inner: bytes):
    """
    Rewrite src→SERVER_PUBLIC, clamp MSS on SYN,
    recalc checksums, and raw‐send to the real target.
    """
    p = cast(IP, IP(inner))
    clamp_mss(p)
    p.src = SERVER_IP
    # clear old fields so Scapy fixes them
    del p.len, p.chksum
    del p[TCP].chksum
    p.ttl = max(p.ttl, 64)
    sock_ip.sendto(bytes(p), (p.dst, 0))


def server_cb(nf_pkt: NFQPacket):
    global seq_reply
    raw = nf_pkt.get_payload()
    ip = IP(raw)

    # 1) incoming echo-requests → unwrap & forward inner → accept
    if (
        ip.proto == 1
        and ip.haslayer(ICMP)
        and ip[ICMP].type == 8
        and ip[ICMP].id == ICMP_ID
    ):
        inner = bytes(ip[ICMP].payload)
        normalize_and_forward(inner)
        nf_pkt.drop()
        return

    # 2) forwarded TCP replies to client‐inner → wrap & send back, drop
    if ip.proto == 6 and ip.dst == SERVER_IP:
        logging.debug(f"got response from target, sending to {CLIENT_IP}")
        icmp = (
            IP(dst=CLIENT_IP)
            / ICMP(type=0, code=0, id=ICMP_ID, seq=seq_reply)
            / Raw(raw)
        )
        sock_icmp.sendto(bytes(icmp), (CLIENT_IP, 0))
        seq_reply = (seq_reply + 1) & 0xFFFF
        nf_pkt.drop()
        return

    # otherwise pass through
    nf_pkt.accept()


if __name__ == "__main__":
    threads = [
        threading.Thread(target=start_worker, args=(q, server_cb), daemon=True)
        for q in range(NUM_QUEUES)
    ]
    try:
        logging.info("Server tunnel up. Ctrl-C to quit.")
        for t in threads:
            t.start()
    finally:
        for t in threads:
            t.join()
