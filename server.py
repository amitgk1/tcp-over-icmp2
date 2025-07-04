#!/usr/bin/env python3
import ipaddress
import logging

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet as NFQPacket
from scapy.all import Raw, send
from scapy.layers.inet import ICMP, IP

# the client‐side public IP (where we send our replies)
CLIENT_PUBLIC = "198.168.1.152"
# the private subnet your client uses as inner‐src
CLIENT_INNER_NET = ipaddress.ip_network("198.168.244.0/24")

ICMP_ID = 0x1234  # os.getpid() & 0xFFFF
seq_reply = 0

logging.getLogger().setLevel(logging.DEBUG)


def server_cb(nf_pkt: NFQPacket):
    global seq_reply
    raw = nf_pkt.get_payload()
    ip = IP(raw)

    # 1) incoming echo-requests → unwrap & forward inner → accept
    if ip.proto == 1 and ip[ICMP].type == 8 and ip[ICMP].id == ICMP_ID:
        logging.debug("got icmp packet from tunnel")
        inner = bytes(ip[ICMP].payload)
        # re‐inject into kernel so NAT + FORWARD apply:
        nf_pkt.set_payload(inner)
        nf_pkt.accept()
        return

    logging.debug(f"incoming ip packet {ip.summary()}")
    # 2) forwarded TCP replies to client‐inner → wrap & send back, drop
    if ip.proto == 6 and ip.dst in CLIENT_INNER_NET:
        logging.debug("got response from target")
        inner = raw
        icmp = (
            IP(dst=CLIENT_PUBLIC)
            / ICMP(type=0, code=0, id=ICMP_ID, seq=seq_reply)
            / Raw(inner)
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
