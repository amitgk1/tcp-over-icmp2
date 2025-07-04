#!/usr/bin/env python3
import logging

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet as NFQPacket
from scapy.all import Raw, conf, get_if_addr, send
from scapy.layers.inet import ICMP, IP

SERVER_IP = get_if_addr(conf.iface)

ICMP_ID = 0x1234  # os.getpid() & 0xFFFF
seq_reply = 0

logging.getLogger().setLevel(logging.DEBUG)


def server_cb(nf_pkt: NFQPacket):
    global seq_reply
    client_ip = ""
    raw = nf_pkt.get_payload()
    ip = IP(raw)

    # 1) incoming echo-requests → unwrap & forward inner → accept
    if ip.proto == 1 and ip[ICMP].type == 8 and ip[ICMP].id == ICMP_ID:
        client_ip = ip.src
        logging.debug("got icmp packet from tunnel")
        inner = ip[Raw].load
        # re‐inject into kernel so NAT + FORWARD apply:
        nf_pkt.set_payload(inner)
        nf_pkt.accept()
        return

    logging.debug(f"incoming ip packet {ip.summary()}")
    # 2) forwarded TCP replies to client‐inner → wrap & send back, drop
    if ip.proto == 6 and ip.dst == SERVER_IP:
        logging.debug(f"got response from target, sending to {client_ip}")
        icmp = (
            IP(dst=client_ip)
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
