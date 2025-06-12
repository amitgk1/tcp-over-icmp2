#!/usr/bin/env python3
"""
Shared components for TCP-over-ICMP tunnel
"""

import hashlib
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from scapy.all import Raw
from scapy.layers.inet import ICMP, IP, TCP

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Protocol constants
ICMP_TUNNEL_TYPE = 8  # Echo Request
ICMP_TUNNEL_CODE = 0
MAGIC_BYTES = b"\xde\xad\xbe\xef"


# Connection states
class ConnState:
    INIT = 0
    SYN_SENT = 1
    ESTABLISHED = 2
    FIN_WAIT = 3
    CLOSED = 4


@dataclass
class TunnelHeader:
    """Custom header for encapsulating TCP in ICMP"""

    conn_id: int
    seq_num: int
    ack_num: int
    flags: int
    data_len: int
    dst_ip: str = ""
    dst_port: int = 0

    def pack(self) -> bytes:
        """Pack header into bytes"""
        # Convert IP to 4 bytes
        ip_bytes = socket.inet_aton(self.dst_ip) if self.dst_ip else b"\x00\x00\x00\x00"

        # Pack: magic(4) + conn_id(4) + seq(4) + ack(4) + flags(4) + data_len(4) + ip(4) + port(2) = 30 bytes total
        return MAGIC_BYTES + struct.pack(
            "!IIIII4sH",
            self.conn_id,
            self.seq_num,
            self.ack_num,
            self.flags,
            self.data_len,
            ip_bytes,
            self.dst_port,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "TunnelHeader":
        """Unpack header from bytes"""
        if not data.startswith(MAGIC_BYTES):
            raise ValueError("Invalid magic bytes")

        if len(data) < 30:  # magic(4) + 5*int(4) + ip(4) + port(2) = 30 bytes
            raise ValueError("Header too short")

        values = struct.unpack("!IIIII4sH", data[4:30])
        conn_id, seq_num, ack_num, flags, data_len, ip_bytes, dst_port = values

        # Convert IP bytes back to string
        dst_ip = socket.inet_ntoa(ip_bytes) if ip_bytes != b"\x00\x00\x00\x00" else ""

        return cls(conn_id, seq_num, ack_num, flags, data_len, dst_ip, dst_port)


class ConnectionTracker:
    """Track TCP connection state"""

    def __init__(self):
        self.connections: Dict[int, dict] = {}
        self.next_conn_id = 1

    def generate_conn_id(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> int:
        """Generate unique connection ID"""
        key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        hash_obj = hashlib.md5(key.encode())
        return int.from_bytes(hash_obj.digest()[:4], "big")

    def add_connection(
        self,
        conn_id: int,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        initial_seq: int = 0,
    ) -> None:
        """Add new connection to tracker"""
        self.connections[conn_id] = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "state": ConnState.INIT,
            "client_seq": initial_seq,
            "server_seq": 0,
            "client_ack": 0,
            "server_ack": 0,
            "socket": None,
        }
        logger.info(
            f"Added connection {conn_id}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        )

    def get_connection(self, conn_id: int) -> Optional[dict]:
        """Get connection info"""
        return self.connections.get(conn_id)

    def remove_connection(self, conn_id: int) -> None:
        """Remove connection"""
        if conn_id in self.connections:
            conn = self.connections[conn_id]
            if conn.get("socket"):
                conn["socket"].close()
            del self.connections[conn_id]
            logger.info(f"Removed connection {conn_id}")


def create_icmp_packet(
    dst_ip: str, tunnel_header: TunnelHeader, payload: bytes = b""
) -> bytes:
    """Create ICMP packet with tunnel payload"""
    # Create ICMP packet
    icmp_payload = tunnel_header.pack() + payload

    icmp_pkt = ICMP(type=ICMP_TUNNEL_TYPE, code=ICMP_TUNNEL_CODE) / Raw(
        load=icmp_payload
    )
    ip_pkt = IP(dst=dst_ip) / icmp_pkt

    return bytes(ip_pkt)


def parse_icmp_packet(packet_data: bytes) -> Tuple[Optional[TunnelHeader], bytes]:
    """Parse ICMP packet and extract tunnel data"""
    try:
        pkt = IP(packet_data)

        if not (
            pkt.proto == 1
            and hasattr(pkt, "payload")
            and isinstance(pkt.payload, ICMP)
            and pkt.payload.type == ICMP_TUNNEL_TYPE
        ):
            return None, b""

        icmp_payload = bytes(pkt.payload.payload)
        if (
            len(icmp_payload) < 30
        ):  # Updated header size: magic(4) + 5*int(4) + ip(4) + port(2)
            return None, b""

        header = TunnelHeader.unpack(icmp_payload)
        payload = icmp_payload[30:]  # Updated offset

        return header, payload

    except Exception as e:
        logger.error(f"Error parsing ICMP packet: {e}")
        return None, b""


def create_raw_socket() -> socket.socket:
    """Create raw socket for ICMP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return sock
    except PermissionError:
        logger.error("Raw socket creation failed - need root privileges")
        raise


def extract_tcp_info(packet_data: bytes) -> Tuple[str, int, str, int, int, int, int]:
    """Extract TCP connection info from packet"""
    try:
        pkt = IP(packet_data)
        tcp_layer = pkt[TCP]

        return (
            pkt.src,  # src_ip
            tcp_layer.sport,  # src_port
            pkt.dst,  # dst_ip
            tcp_layer.dport,  # dst_port
            tcp_layer.seq,  # seq_num
            tcp_layer.ack,  # ack_num
            tcp_layer.flags,  # flags
        )
    except Exception as e:
        logger.error(f"Error extracting TCP info: {e}")
        return "", 0, "", 0, 0, 0, 0


def create_tcp_response(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    """Create TCP response packet"""
    tcp_pkt = TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags)
    if payload:
        tcp_pkt = tcp_pkt / Raw(load=payload)

    ip_pkt = IP(src=src_ip, dst=dst_ip) / tcp_pkt
    return bytes(ip_pkt)
