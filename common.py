import socket
import struct

# --- Custom Tunnel Header Constants and Structure ---
# Format string for struct:
# !B: unsigned char (1 byte) for Flags
# !H: unsigned short (2 bytes) for Tunnel ID
# !I: unsigned int (4 bytes) for Original Destination IP (as int)
# !H: unsigned short (2 bytes) for Original Destination Port
# !I: unsigned int (4 bytes) for Seq Offset (client's virtual TCP seq)
# !I: unsigned int (4 bytes) for Ack Offset (client's virtual TCP ack)
# !H: unsigned short (2 bytes) for Original TCP Packet Length (length of raw TCP bytes following header)
# Total: 1 + 2 + 4 + 2 + 4 + 4 + 2 = 19 bytes
TUNNEL_HEADER_FORMAT = "!BHIHIIH"  # Flags | Tunnel ID | Orig Dest IP | Orig Dest Port | Seq Offset | Ack Offset | Original TCP Pkt Length
TUNNEL_HEADER_LEN = struct.calcsize(TUNNEL_HEADER_FORMAT)

# Flags (1 byte)
FLAG_SYN = 0x01
FLAG_ACK = 0x02
FLAG_PSH = 0x04
FLAG_FIN = 0x08
FLAG_RST = 0x10

# ICMP Type and Code for our tunnel packets
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REQUEST_CODE = 0
ICMP_ECHO_REPLY_TYPE = 0
ICMP_ECHO_REPLY_CODE = 0

# --- SO_ORIGINAL_DST specific for Linux (used by client) ---
SOL_IP = 0
SO_ORIGINAL_DST = 80


# --- Utility functions ---
def ip_to_int(ip_addr):
    """Converts a string IP address to an integer."""
    return struct.unpack("!I", socket.inet_aton(ip_addr))[0]


def int_to_ip(ip_int):
    """Converts an integer IP address to a string."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def parse_original_dst(sock):
    """Parses SO_ORIGINAL_DST socket option for redirected connections."""
    original_dst_raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)

    # Use network byte order for all multi-byte fields:
    original_port, ip_bytes = struct.unpack("!2xH4s8x", original_dst_raw)

    original_ip = socket.inet_ntoa(ip_bytes)

    return original_ip, original_port


class TunnelHeader:
    # Updated __init__ to include original_dst_ip_int and original_dst_port
    def __init__(
        self,
        flags,
        tunnel_id,
        original_dst_ip: str,
        original_dst_port,
        seq_offset,
        ack_offset,
        tcp_len,
    ):
        self.flags = flags
        self.tunnel_id = tunnel_id
        self.original_dst_ip = original_dst_ip
        self.original_dst_port = original_dst_port
        self.seq_offset = seq_offset
        self.ack_offset = ack_offset
        self.tcp_len = tcp_len

    def pack(self):
        return struct.pack(
            TUNNEL_HEADER_FORMAT,
            self.flags,
            self.tunnel_id,
            ip_to_int(self.original_dst_ip),
            self.original_dst_port,
            self.seq_offset,
            self.ack_offset,
            self.tcp_len,
        )

    @classmethod
    def unpack(cls, data):
        if len(data) < TUNNEL_HEADER_LEN:
            raise ValueError("Data too short for TunnelHeader")
        (
            flags,
            tunnel_id,
            original_dst_ip_int,
            original_dst_port,
            seq_offset,
            ack_offset,
            tcp_len,
        ) = struct.unpack(TUNNEL_HEADER_FORMAT, data[:TUNNEL_HEADER_LEN])
        return cls(
            flags,
            tunnel_id,
            int_to_ip(original_dst_ip_int),
            original_dst_port,
            seq_offset,
            ack_offset,
            tcp_len,
        )
