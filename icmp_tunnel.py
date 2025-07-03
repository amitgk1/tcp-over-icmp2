import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class TunnelPacket:
    seq: int
    ack: int
    flags: int  # SYN=1, ACK=2, FIN=4, RST=8, DATA=16
    window: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    data: bytes

    # Flags
    FLAG_SYN = 1
    FLAG_ACK = 2
    FLAG_FIN = 4
    FLAG_RST = 8
    FLAG_DATA = 16

    def pack(self) -> bytes:
        """Pack the tunnel packet into bytes"""
        header = struct.pack(
            "!IIHH4sH4sH",
            self.seq,
            self.ack,
            self.flags,
            self.window,
            socket.inet_aton(self.src_ip),
            self.src_port,
            socket.inet_aton(self.dst_ip),
            self.dst_port,
        )
        return header + self.data

    @classmethod
    def unpack(cls, data: bytes) -> "TunnelPacket":
        """Unpack bytes into a tunnel packet"""
        if len(data) < 24:  # Minimum header size
            raise ValueError("Packet too small")

        header = struct.unpack("!IIHH4sH4sH", data[:24])
        seq, ack, flags, window, src_ip_int, src_port, dst_ip_int, dst_port = header

        src_ip = socket.inet_ntoa(src_ip_int)
        dst_ip = socket.inet_ntoa(dst_ip_int)
        payload = data[24:]

        return cls(seq, ack, flags, window, src_ip, src_port, dst_ip, dst_port, payload)


class ICMPTunnel:
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        )
        self.running = False
        self.packet_id = random.randint(1, 65535)
        self.received_packets = {}  # To track and ignore kernel auto-replies

    def create_icmp_packet(self, data: bytes, packet_type: int = 8) -> bytes:
        """Create ICMP packet with our tunnel data"""
        # ICMP header: type(1) + code(1) + checksum(2) + id(2) + sequence(2)
        icmp_header = struct.pack("!BBHHH", packet_type, 0, 0, self.packet_id, 0)

        # Calculate checksum
        checksum = self._calculate_checksum(icmp_header + data)
        icmp_header = struct.pack("!BBHHH", packet_type, 0, checksum, self.packet_id, 0)

        return icmp_header + data

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        return ~checksum & 0xFFFF

    def send_packet(self, tunnel_packet: TunnelPacket, dest_ip: str):
        """Send tunnel packet via ICMP"""
        data = tunnel_packet.pack()
        icmp_packet = self.create_icmp_packet(data)

        # Store packet info to identify kernel auto-replies
        packet_key = (
            dest_ip,
            self.packet_id,
            data[:8],
        )  # Use first 8 bytes as identifier
        self.received_packets[packet_key] = time.time()

        self.socket.sendto(icmp_packet, (dest_ip, 0))

    def receive_packet(
        self, timeout: float = 1.0
    ) -> Optional[Tuple[TunnelPacket, str]]:
        """Receive and parse tunnel packet from ICMP"""
        self.socket.settimeout(timeout)

        try:
            data, addr = self.socket.recvfrom(65535)
            src_ip = addr[0]

            # Skip IP header (typically 20 bytes)
            ip_header_len = (data[0] & 0x0F) * 4
            icmp_data = data[ip_header_len:]

            if len(icmp_data) < 8:  # Minimum ICMP header
                return None

            # Parse ICMP header
            icmp_type, icmp_code, checksum, packet_id, sequence = struct.unpack(
                "!BBHHH", icmp_data[:8]
            )

            # Check if this is a kernel auto-reply we should ignore
            payload = icmp_data[8:]
            packet_key = (src_ip, packet_id, payload[:8])

            if packet_key in self.received_packets:
                # This is likely a kernel auto-reply, ignore it
                del self.received_packets[packet_key]
                return None

            # Clean up old packet tracking entries
            current_time = time.time()
            self.received_packets = {
                k: v for k, v in self.received_packets.items() if current_time - v < 30
            }  # Keep for 30 seconds

            if len(payload) < 24:  # Our minimum tunnel packet size
                return None

            try:
                tunnel_packet = TunnelPacket.unpack(payload)
                return tunnel_packet, src_ip
            except ValueError:
                return None

        except socket.timeout:
            return None
        except Exception as e:
            print(f"Error receiving packet: {e}")
            return None

    def start(self):
        """Start the tunnel"""
        self.running = True

    def stop(self):
        """Stop the tunnel"""
        self.running = False
        self.socket.close()
