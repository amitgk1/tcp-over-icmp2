import logging
import struct
from typing import Literal, TypeAlias

from scapy.layers.inet import ICMP, IP

ICMP_ECHO_REQUEST = 8

SERVER_FLAG = b"0"
CLIENT_FLAG = b"1"

FLAG: TypeAlias = Literal[b"0", b"1"]

logger = logging.getLogger(__name__)


class TunnelPacket:
    ICMP_ID = 0x1234
    ICMP_ID_BYTES = struct.pack("!H", ICMP_ID)
    MAGIC_PREFIX_SIZE = len(ICMP_ID_BYTES)

    @staticmethod
    def from_tcp_bytes_to_tunnel_bytes(pkt: bytes, flag: FLAG) -> bytes:
        return TunnelPacket.ICMP_ID_BYTES + flag + pkt

    @staticmethod
    def parse_icmp_packet(pkt: bytes, expected_flag: FLAG) -> bytes | None:
        ip = IP(pkt)
        if not (ip[ICMP] and ip[ICMP].id == TunnelPacket.ICMP_ID):
            logger.warning("ICMP packet id didn't match tunnel")
            return None

        inner = ip[ICMP].payload
        if len(inner) < TunnelPacket.MAGIC_PREFIX_SIZE + 1:
            logger.warning("ICMP packet data was too short - not from tunnel")
            return None

        magic_prefix = inner[: TunnelPacket.MAGIC_PREFIX_SIZE]
        if magic_prefix != TunnelPacket.ICMP_ID_BYTES:
            logger.warning(
                "ICMP packet data didn't contain magic prefix - not from tunnel"
            )
            return None

        flag = inner[
            TunnelPacket.MAGIC_PREFIX_SIZE : TunnelPacket.MAGIC_PREFIX_SIZE + 1
        ]
        if expected_flag != flag:
            logger.warning(
                "ICMP packet flag didn't match expectation. expected: %b but got %b\nprobably auto kernel reply",
                expected_flag,
                flag,
            )
            return None
        return inner[TunnelPacket.MAGIC_PREFIX_SIZE + 1 :]
