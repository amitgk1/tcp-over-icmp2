from .connection_manager import ConnectionManager, ConnectionState
from .logging_config import setup_logging
from .packet_handler import PacketHandler, PacketType, TunnelPacket
from .utils import (
    calculate_checksum,
    format_ip_port,
    get_local_ip,
    parse_ip_port,
    validate_ip,
    validate_port,
)

__all__ = [
    "PacketHandler",
    "TunnelPacket",
    "PacketType",
    "ConnectionManager",
    "ConnectionState",
    "validate_ip",
    "validate_port",
    "parse_ip_port",
    "format_ip_port",
    "get_local_ip",
    "calculate_checksum",
    "setup_logging",
]


def hello() -> str:
    return "Hello from shared!"
