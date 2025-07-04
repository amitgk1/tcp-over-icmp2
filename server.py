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


def normalize_inner(inner_bytes: bytes):
    p = IP(inner_bytes)
    # fix TTL if it has decayed
    p.ttl = 64
    # strip any old checksums
    del p.chksum
    # there may be multiple TCP layers if you stack Raw, so pick the first
    if TCP in p:
        del p[TCP].chksum

    # (optionally) ensure there is an MSS option like curl would add
    opts = p[TCP].options or []
    has_mss = any(o[0] == "MSS" for o in opts)
    if not has_mss:
        opts = [("MSS", 1460)] + opts
        p[TCP].options = opts

    return bytes(p)


def server_cb(nf_pkt: NFQPacket):
    global seq_reply
    raw = nf_pkt.get_payload()
    ip = IP(raw)

    # 1) incoming echo-requests → unwrap & forward inner → accept
    if ip.proto == 1 and ip[ICMP].type == 8 and ip[ICMP].id == ICMP_ID:
        logging.debug("got icmp packet from tunnel")
        inner = normalize_inner(ip[Raw].load)

        # re‐inject into kernel so NAT + FORWARD apply:
        nf_pkt.set_payload(inner)
        nf_pkt.accept()
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
