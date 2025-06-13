import socket
import struct

# --- Custom Tunnel Header Constants and Structure ---
# Format string for struct:
# !H: unsigned short (2 bytes) for Tunnel ID
# !B: unsigned char (1 byte) for Flags
# !I: unsigned int (4 bytes) for Seq Offset
# !I: unsigned int (4 bytes) for Ack Offset
# !H: unsigned short (2 bytes) for Original TCP Packet Length
# Total: 2 + 1 + 4 + 4 + 2 = 13 bytes
TUNNEL_HEADER_FORMAT = (
    "!BHHII"  # Flags | Tunnel ID | Seq Offset | Ack Offset | Original TCP Pkt Length
)
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
# Check /usr/include/linux/netfilter_ipv4.h for these constants
# IP_ORIGDST = 80 in setsockopt, sockaddr_in size is 16
SOL_IP = 0  # Corresponds to IPPROTO_IP
SO_ORIGINAL_DST = 80  # Corresponds to SO_ORIGINAL_DST


# --- Utility functions ---
def ip_to_int(ip_addr):
    """Converts a string IP address to an integer."""
    return struct.unpack("!I", socket.inet_aton(ip_addr))[0]


def int_to_ip(ip_int):
    """Converts an integer IP address to a string."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def parse_original_dst(sock):
    """Parses SO_ORIGINAL_DST socket option for redirected connections."""
    # struct sockaddr_in {
    #   sa_family_t sin_family;  (2 bytes)
    #   in_port_t   sin_port;    (2 bytes)
    #   struct in_addr sin_addr; (4 bytes)
    #   char        sin_zero[8]; (8 bytes padding)
    # } Total = 16 bytes
    original_dst_raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)

    # Use network byte order for all multi-byte fields:
    # !H: unsigned short for family (2 bytes)
    # !H: unsigned short for port (2 bytes)
    # 4s: 4-byte string for IP address (already network byte order)
    # 8s: 8-byte string for padding
    family_net_byte_order, port_net_byte_order, ip_bytes, _ = struct.unpack(
        "!HH4s8s", original_dst_raw
    )

    # Convert family and port from network byte order to host byte order
    family = socket.ntohs(family_net_byte_order)
    original_port = socket.ntohs(port_net_byte_order)

    # Check if family is indeed AF_INET
    if family != socket.AF_INET:
        raise ValueError(
            f"Unsupported socket family for SO_ORIGINAL_DST: {family}. Expected AF_INET ({socket.AF_INET})"
        )

    original_ip = socket.inet_ntoa(ip_bytes)  # IP is always network byte order

    return original_ip, original_port


class TunnelHeader:
    def __init__(self, flags, tunnel_id, seq_offset, ack_offset, tcp_len):
        self.flags = flags
        self.tunnel_id = tunnel_id
        self.seq_offset = seq_offset
        self.ack_offset = ack_offset
        self.tcp_len = tcp_len

    def pack(self):
        return struct.pack(
            TUNNEL_HEADER_FORMAT,
            self.flags,
            self.tunnel_id,
            self.seq_offset,
            self.ack_offset,
            self.tcp_len,
        )

    @classmethod
    def unpack(cls, data):
        if len(data) < TUNNEL_HEADER_LEN:
            raise ValueError("Data too short for TunnelHeader")
        flags, tunnel_id, seq_offset, ack_offset, tcp_len = struct.unpack(
            TUNNEL_HEADER_FORMAT, data[:TUNNEL_HEADER_LEN]
        )
        return cls(flags, tunnel_id, seq_offset, ack_offset, tcp_len)
