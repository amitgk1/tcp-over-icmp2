#!/usr/bin/env python3
import ipaddress
import logging
import socket
from typing import cast, override

import iptc
from netfilterqueue import Packet as NFQPacket
from scapy.all import Raw, conf, get_if_addr
from scapy.layers.inet import ICMP, IP, TCP

from iptable_manager import IPTableRule, TunnelIPTablesRules
from tunnel import PacketHandler, Tunnel

CLIENT_PRIVATE = get_if_addr(conf.iface)

# ID for our echo messages
ICMP_ID = 0x1234  # os.getpid() & 0xFFFF

logging.getLogger().setLevel(logging.INFO)

# build a small BLACKLIST of dest‐nets we do NOT want to tunnel:
BLACKLIST = [
    ipaddress.ip_network("127.0.0.0/8"),  # lo
    # ipaddress.ip_network("10.0.0.0/8"),  # private
    # ipaddress.ip_network("192.168.0.0/16"),  # private
    # ipaddress.ip_network(SERVER_IP + "/32"),  # the tunnel server itself
]

NUM_QUEUES = 4


class ClientPacketHandler(PacketHandler):
    def __init__(self, server_ip: ipaddress.IPv4Address) -> None:
        super().__init__()
        self.server_ip = server_ip

        # ICMP socket for echo-requests
        self.sock_icmp = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        )
        self.sock_icmp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def cleanup(self):
        self.sock_icmp.close()

    @override
    def get_rules(self):
        # PREROUTING: ICMP echo-reply → NFQUEUE
        icmp_rule = iptc.Rule()
        icmp_rule.protocol = "icmp"
        m = iptc.Match(icmp_rule, "icmp")
        m.icmp_type = "echo-reply"
        icmp_rule.add_match(m)

        # OUTPUT: TCP !127.0.0.0/8 → NFQUEUE
        tcp_rule = iptc.Rule()
        tcp_rule.protocol = "tcp"
        tcp_rule.dst = "!127.0.0.1/8"
        return TunnelIPTablesRules(
            icmp=(IPTableRule(chain="PREROUTING", rule=icmp_rule)),
            tcp=(IPTableRule(chain="OUTPUT", rule=tcp_rule)),
        )

    @override
    def handle_icmp(self, nf_pkt: NFQPacket) -> None:
        # 2) Incoming ICMP echo‐reply → unwrap & inject
        raw = nf_pkt.get_payload()
        ip = cast(IP, IP(raw))

        if ip.proto == 1 and ip[ICMP].type == 0 and ip[ICMP].id == ICMP_ID:
            logging.debug("incoming icmp reply with tunnel code")
            inner = bytes(ip[ICMP].payload)
            fixed = normalize_and_nat_local(inner)
            nf_pkt.set_payload(fixed)
            nf_pkt.accept()
            return

        # otherwise leave untouched
        nf_pkt.accept()

    @override
    def handle_tcp(self, nf_pkt: NFQPacket) -> None:
        raw = nf_pkt.get_payload()
        ip = cast(IP, IP(raw))

        # 1) Outgoing TCP → wrap in ICMP echo‐request
        if should_wrap_tcp(ip):
            icmp = (
                IP(dst=self.server_ip)
                / ICMP(type=8, code=0, id=ICMP_ID, seq=next(self.seq_count))
                / Raw(raw)
            )

            self.sock_icmp.sendto(bytes(icmp), (self.server_ip, 0))
            nf_pkt.drop()
            return

        nf_pkt.accept()


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


if __name__ == "__main__":
    parser = Tunnel.generate_common_arg_parser()
    parser.add_argument(
        "server_ip", type=ipaddress.IPv4Address, help="ip address of the client"
    )
    args = parser.parse_args()
    client = ClientPacketHandler(args.server_ip)
    tunnel = Tunnel(
        client.get_rules(), Tunnel.parser_args_to_tunnel_options(args), client
    )
    try:
        tunnel.start()
    except KeyboardInterrupt:
        pass
    finally:
        logging.info("Shutting down...")
        client.cleanup()
        tunnel.cleanup()
