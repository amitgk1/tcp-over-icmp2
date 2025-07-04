#!/usr/bin/env python3
import logging

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet as NFQPacket
from scapy.all import Raw, conf, get_if_addr, send
from scapy.layers.inet import ICMP, IP, TCP

SERVER_IP = get_if_addr(conf.iface)
CLIENT_IP = "192.168.1.152"

ICMP_ID = 0x1234  # os.getpid() & 0xFFFF
seq_reply = 0

logging.getLogger().setLevel(logging.DEBUG)


def normalize_and_nat(inner_bytes):
    """
    Parse the inner IP packet, rewrite src → SERVER_PUBLIC,
    drop old checksums, let Scapy rebuild them, return bytes().
    """
    p = IP(inner_bytes)
    # 1) NAT: set the src to your public IP
    p.src = SERVER_IP
    # 2) clear length & checksum so Scapy will recalc
    if hasattr(p, "len"):
        del p.len
    if hasattr(p, "chksum"):
        del p.chksum

    # 3) if it's TCP, clear its checksum too and maybe fix options
    if TCP in p:
        del p[TCP].chksum
        # if it's a SYN, ensure it has an MSS option
        if p[TCP].flags & 0x02:  # SYN flag
            opts = p[TCP].options or []
            if not any(o[0] == "MSS" for o in opts):
                p[TCP].options = [("MSS", 1460)] + opts

    # 4) reset TTL
    p.ttl = max(p.ttl, 64)

    return p


def server_cb(nf_pkt: NFQPacket):
    global seq_reply
    raw = nf_pkt.get_payload()
    ip = IP(raw)

    # 1) incoming echo-requests → unwrap & forward inner → accept
    if ip.proto == 1 and ip[ICMP].type == 8 and ip[ICMP].id == ICMP_ID:
        logging.debug("got icmp packet from tunnel")
        inner = bytes(ip[ICMP].payload)
        fixed = normalize_and_nat(inner)
        # send it straight out via raw socket
        send(fixed, verbose=False)
        nf_pkt.drop()
        return

    logging.debug(f"incoming ip packet {ip.summary()}")
    # 2) forwarded TCP replies to client‐inner → wrap & send back, drop
    if ip.proto == 6 and ip.dst == SERVER_IP:
        logging.debug(f"got response from target, sending to {CLIENT_IP}")
        icmp = (
            IP(dst=CLIENT_IP)
            / ICMP(type=0, code=0, id=ICMP_ID, seq=seq_reply)
            / Raw(raw)
        )
        send(icmp, verbose=False)
        seq_reply = (seq_reply + 1) & 0xFFFF
        nf_pkt.drop()
        return

    # otherwise pass through
    nf_pkt.accept()


if __name__ == "__main__":
    nf = NetfilterQueue()
    nf.bind(1, server_cb)
    print("Server tunnel up. Ctrl-C to quit.")
    try:
        nf.run()
    except KeyboardInterrupt:
        pass
    finally:
        nf.unbind()
