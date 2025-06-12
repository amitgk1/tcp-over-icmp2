#!/usr/bin/env python3
"""
Shared components for TCP-over-ICMP tunnel
"""

import hashlib
import logging
import socket
import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Dict, Optional, Tuple

from scapy.all import IPSession, Packet, Raw, sniff
from scapy.layers.inet import ICMP, IP

# Configure logging
logger = logging.getLogger(__name__)


ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_CODE = 0


class TunnelFlags(IntEnum):
    """Flags for tunnel protocol"""

    DATA = 0x01
    SYN = 0x02
    ACK = 0x04
    FIN = 0x08
    RST = 0x10
    CLOSE = 0x20


@dataclass
class TunnelHeader:
    """Custom header for ICMP tunnel protocol"""

    HEADER_SIZE = 16

    conn_id: int
    seq_num: int
    ack_num: int
    flags: int
    data_len: int

    def pack(self) -> bytes:
        """Pack header into bytes"""
        return struct.pack(
            "!IIIHH",
            self.conn_id,
            self.seq_num,
            self.ack_num,
            self.flags,
            self.data_len,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "TunnelHeader":
        """Unpack header from bytes"""
        conn_id, seq_num, ack_num, flags, data_len = struct.unpack(
            "!IIIHH", data[: TunnelHeader.HEADER_SIZE]
        )
        return cls(conn_id, seq_num, ack_num, flags, data_len)


@dataclass
class ConnectionState:
    """Track TCP connection state"""

    local_addr: Tuple[str, int]
    remote_addr: Tuple[str, int]
    local_seq: int = 0
    remote_seq: int = 0
    local_ack: int = 0
    remote_ack: int = 0
    state: str = "INIT"  # INIT, SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSED
    last_activity: float = 0
    sock: Optional[socket.socket] = None

    def __post_init__(self):
        self.last_activity = time.time()

    def update_activity(self):
        self.last_activity = time.time()


class TunnelProtocol:
    """Shared protocol implementation"""

    MAX_DATA_SIZE = 1400  # Leave room for IP + ICMP headers
    ICMP_ID = 0x1234  # Fixed ICMP ID for our tunnel

    @staticmethod
    def generate_connection_id(
        local_addr: Tuple[str, int], remote_addr: Tuple[str, int]
    ) -> int:
        """Generate unique connection ID from addresses"""
        data = f"{local_addr[0]}:{local_addr[1]}->{remote_addr[0]}:{remote_addr[1]}"
        hash_obj = hashlib.md5(data.encode())
        return struct.unpack("!I", hash_obj.digest()[:4])[0]

    @staticmethod
    def create_icmp_packet(
        dst_ip: str, header: TunnelHeader, payload: bytes = b""
    ) -> Packet:
        """Create ICMP packet with tunnel data"""
        tunnel_data = header.pack() + payload

        # Create ICMP echo request
        icmp_packet = ICMP(
            type=8,  # Echo Request
            id=TunnelProtocol.ICMP_ID,
            seq=header.seq_num & 0xFFFF,  # Use lower 16 bits of seq for ICMP seq
        ) / Raw(load=tunnel_data)

        # Create IP packet
        ip_packet = IP(dst=dst_ip) / icmp_packet

        return ip_packet

    @staticmethod
    def parse_icmp_packet(packet: IP) -> Optional[Tuple[TunnelHeader, bytes]]:
        """Parse ICMP packet and extract tunnel data"""
        try:
            if not packet.haslayer(ICMP):
                return None

            icmp = packet[ICMP]

            # Check if it's our tunnel traffic
            if icmp.type not in [0, 8] or icmp.id != TunnelProtocol.ICMP_ID:
                return None

            if not packet.haslayer(Raw):
                return None

            raw_data = packet[Raw].load

            if len(raw_data) < TunnelHeader.HEADER_SIZE:
                return None

            # Extract tunnel header
            header = TunnelHeader.unpack(raw_data[: TunnelHeader.HEADER_SIZE])
            payload = raw_data[
                TunnelHeader.HEADER_SIZE : TunnelHeader.HEADER_SIZE + header.data_len
            ]

            return header, payload

        except Exception as e:
            logger.error(f"Error parsing ICMP packet: {e}")
            return None

    @staticmethod
    def create_raw_socket() -> socket.socket:
        """Create raw socket for ICMP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            return sock
        except PermissionError:
            logger.error("Raw socket creation failed. Run as root!")
            raise

    @staticmethod
    def calculate_tcp_checksum(
        ip_src: str, ip_dst: str, tcp_header: bytes, tcp_data: bytes = b""
    ) -> int:
        """Calculate TCP checksum"""
        # Create pseudo header
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(ip_src),
            socket.inet_aton(ip_dst),
            0,  # reserved
            socket.IPPROTO_TCP,
            len(tcp_header) + len(tcp_data),
        )

        # Combine pseudo header, TCP header, and data
        checksum_data = pseudo_header + tcp_header + tcp_data

        # Calculate checksum
        if len(checksum_data) % 2:
            checksum_data += b"\x00"

        checksum = 0
        for i in range(0, len(checksum_data), 2):
            checksum += struct.unpack("!H", checksum_data[i : i + 2])[0]

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        checksum = ~checksum & 0xFFFF

        return checksum


class ConnectionManager:
    """Manage multiple TCP connections"""

    def __init__(self):
        self.connections: Dict[int, ConnectionState] = {}
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()

    def add_connection(self, conn_id: int, conn_state: ConnectionState):
        """Add new connection"""
        self.connections[conn_id] = conn_state
        logger.info(
            f"Added connection {conn_id}: {conn_state.local_addr} -> {conn_state.remote_addr}"
        )

    def get_connection(self, conn_id: int) -> Optional[ConnectionState]:
        """Get connection by ID"""
        return self.connections.get(conn_id)

    def remove_connection(self, conn_id: int):
        """Remove connection"""
        if conn_id in self.connections:
            conn = self.connections[conn_id]
            if conn.sock:
                try:
                    conn.sock.close()
                except:
                    pass
            del self.connections[conn_id]
            logger.info(f"Removed connection {conn_id}")

    def cleanup_stale_connections(self):
        """Remove stale connections"""
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval:
            return

        self.last_cleanup = now
        stale_connections = []

        for conn_id, conn in self.connections.items():
            if now - conn.last_activity > 600:  # 10 minutes timeout
                stale_connections.append(conn_id)

        for conn_id in stale_connections:
            logger.info(f"Cleaning up stale connection {conn_id}")
            self.remove_connection(conn_id)

    def list_connections(self) -> Dict[int, ConnectionState]:
        """Get all active connections"""
        return self.connections.copy()


def setup_logging(debug: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("tunnel.log")],
    )


def packet_filter(packet: Packet):
    """Filter for ICMP packets"""
    return (
        packet.haslayer(IP)
        and packet.haslayer(ICMP)
        and packet[ICMP].id == TunnelProtocol.ICMP_ID
    )


def start_icmp_listener(
    handle_icmp_packet: Callable[[ICMP], Optional[Any]],
    stop_filter: Callable[[Packet], bool],
):
    """Start ICMP packet listener"""
    logger.info("Starting ICMP listener...")

    try:
        # Use scapy to sniff ICMP packets
        sniff(
            session=IPSession,
            filter="icmp",
            prn=handle_icmp_packet,
            lfilter=packet_filter,
            stop_filter=stop_filter,
            store=False,
        )
    except Exception as e:
        logger.error(f"Error in ICMP listener: {e}")

    logger.info("ICMP listener stopped")


# Utility functions
def is_root() -> bool:
    """Check if running as root"""
    import os

    return os.geteuid() == 0


def get_local_ip() -> str:
    """Get local IP address"""
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"
