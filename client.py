#!/usr/bin/env python3
import logging
import socket
from typing import cast, override

import iptc
from netfilterqueue import Packet as NFQPacket
from scapy.all import conf, get_if_addr
from scapy.layers.inet import ICMP, IP, TCP

from iptable_manager import IPTableRule, TunnelIPTablesRules
from tunnel import PacketHandler
from tunnel_packet import CLIENT_FLAG, ICMP_ECHO_REQUEST, SERVER_FLAG, TunnelPacket

CLIENT_PRIVATE = get_if_addr(conf.iface)


class ClientPacketHandler(PacketHandler):
    def __init__(self, server_ip: str) -> None:
        super().__init__()
        self.server_ip = server_ip
        self.logger = logging.getLogger(__name__)

        # ICMP socket for echo-requests
        self.sock_icmp = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        )
        self.sock_icmp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def cleanup(self):
        self.logger.debug("cleaning up client icmp socket")
        self.sock_icmp.close()

    @override
    def get_rules(self):
        # PREROUTING: ICMP echo-reply
        icmp_rule = iptc.Rule()
        icmp_rule.protocol = "icmp"
        m = iptc.Match(icmp_rule, "icmp")
        m.icmp_type = "echo-reply"
        icmp_rule.add_match(m)
        icmp = IPTableRule(chain="PREROUTING", rule=icmp_rule)

        # OUTPUT: TCP !127.0.0.0/8
        tcp_rule = iptc.Rule()
        tcp_rule.protocol = "tcp"
        tcp_rule.dst = "!127.0.0.1/8"
        tcp = IPTableRule(chain="OUTPUT", rule=tcp_rule)
        return TunnelIPTablesRules(icmp=icmp, tcp=tcp)

    @override
    def handle_icmp(self, nf_pkt: NFQPacket) -> None:
        """
        Incoming ICMP echo-reply → unwrap & inject
        """

        raw = nf_pkt.get_payload()
        inner = TunnelPacket.parse_icmp_packet(raw, expected_flag=SERVER_FLAG)

        if inner:
            self.logger.debug("incoming icmp reply with tunnel code")
            fixed = normalize_and_nat_local(inner)
            nf_pkt.set_payload(fixed)
            nf_pkt.accept()
            return

        # otherwise leave untouched
        nf_pkt.accept()

    @override
    def handle_tcp(self, nf_pkt: NFQPacket) -> None:
        self.logger.debug("outgoing tcp packet")
        raw = nf_pkt.get_payload()

        icmp = (
            IP(dst=self.server_ip)
            / ICMP(
                type=ICMP_ECHO_REQUEST,
                code=0,
                id=TunnelPacket.ICMP_ID,
                seq=next(self.seq_count),
            )
            / TunnelPacket.from_tcp_bytes_to_tunnel_bytes(raw, flag=CLIENT_FLAG)
        )

        self.sock_icmp.sendto(bytes(icmp), (self.server_ip, 0))
        nf_pkt.drop()
        return


def normalize_and_nat_local(inner: bytes) -> bytes:
    """Re-write dst→CLIENT_PRIVATE, recalc checksums."""
    p = cast(IP, IP(inner))
    p.dst = CLIENT_PRIVATE
    # force recompute
    del p.len, p.chksum
    del p[TCP].chksum
    p.ttl = max(p.ttl, 64)
    return bytes(p)
