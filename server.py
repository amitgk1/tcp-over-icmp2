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

SERVER_IP = get_if_addr(conf.iface)
ICMP_ID = 0x1234

logging.getLogger().setLevel(logging.INFO)


class ServerPacketHandler(PacketHandler):
    def __init__(self, client_ip: str) -> None:
        super().__init__()
        self.client_ip = client_ip
        # ICMP socket for echo-reply
        self.sock_icmp = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        )
        self.sock_icmp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # RAW IP socket for forwarding the unwrapped inner packet
        self.sock_ip = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )

        # tell kernel we include our own IP header
        self.sock_ip.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def cleanup(self):
        self.sock_icmp.close()
        self.sock_ip.close()

    @override
    def get_rules(self):
        # PREROUTING: ICMP echo‐request → NFQUEUE
        icmp_rule = iptc.Rule()
        icmp_rule.protocol = "icmp"
        m = iptc.Match(icmp_rule, "icmp")
        m.icmp_type = "echo-request"
        icmp_rule.add_match(m)

        # PREROUTING: any TCP→SERVER_PUBLIC → NFQUEUE
        tcp_rule = iptc.Rule()
        tcp_rule.protocol = "tcp"
        tcp_rule.dst = SERVER_IP
        return TunnelIPTablesRules(
            icmp=(IPTableRule(chain="PREROUTING", rule=icmp_rule)),
            tcp=(IPTableRule(chain="PREROUTING", rule=tcp_rule)),
        )

    @override
    def handle_icmp(self, nf_pkt: NFQPacket) -> None:
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
            self._normalize_and_forward(inner)
            nf_pkt.drop()
            return

        # otherwise pass through
        nf_pkt.accept()

    def handle_tcp(self, nf_pkt: NFQPacket) -> None:
        raw = nf_pkt.get_payload()
        ip = IP(raw)
        # 2) forwarded TCP replies to client‐inner → wrap & send back, drop
        if ip.proto == 6 and ip.dst == SERVER_IP:
            logging.debug(f"got response from target, sending to {self.client_ip}")
            icmp = (
                IP(dst=self.client_ip)
                / ICMP(type=0, code=0, id=ICMP_ID, seq=next(self.seq_count))
                / Raw(raw)
            )
            self.sock_icmp.sendto(bytes(icmp), (self.client_ip, 0))
            nf_pkt.drop()
            return

        # otherwise pass through
        nf_pkt.accept()

    def clamp_mss(self, pkt: IP, mss: int = 1000):
        """If pkt is TCP-SYN, replace any MSS with our small one."""
        if TCP in pkt and (pkt[TCP].flags & 0x2):  # SYN
            opts = pkt[TCP].options or []
            opts = [o for o in opts if o[0] != "MSS"]
            opts.insert(0, ("MSS", mss))
            pkt[TCP].options = opts

    def _normalize_and_forward(self, inner: bytes):
        """
        Rewrite src→SERVER_PUBLIC, clamp MSS on SYN,
        recalc checksums, and raw‐send to the real target.
        """
        p = cast(IP, IP(inner))
        self.clamp_mss(p)
        p.src = SERVER_IP
        # clear old fields so Scapy fixes them
        del p.len, p.chksum
        del p[TCP].chksum
        p.ttl = max(p.ttl, 64)
        self.sock_ip.sendto(bytes(p), (p.dst, 0))


if __name__ == "__main__":
    parser = Tunnel.generate_common_arg_parser()
    parser.add_argument(
        "client_ip", type=ipaddress.IPv4Address, help="ip address of the client"
    )
    args = parser.parse_args()
    server = ServerPacketHandler(str(args.client_ip))
    tunnel = Tunnel(
        server.get_rules(), Tunnel.parser_args_to_tunnel_options(args), server
    )
    try:
        tunnel.start()
    except KeyboardInterrupt:
        pass
    finally:
        logging.info("Shutting down...")
        server.cleanup()
        tunnel.cleanup()
