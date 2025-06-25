import logging
import socket
import struct
from typing import Optional, Tuple


def validate_ip(ip: str, logger: Optional[logging.Logger] = None) -> bool:
    """Validate if a string is a valid IP address."""
    try:
        socket.inet_aton(ip)
        if logger:
            logger.debug(f"IP validation successful: {ip}")
        return True
    except OSError as e:
        if logger:
            logger.debug(f"IP validation failed: {ip} - {e}")
        return False


def validate_port(port: int, logger: Optional[logging.Logger] = None) -> bool:
    """Validate if a port number is valid."""
    is_valid = 1 <= port <= 65535
    if logger:
        logger.debug(f"Port validation: {port} -> {is_valid}")
    return is_valid


def calculate_checksum(data: bytes, logger: Optional[logging.Logger] = None) -> int:
    """Calculate Internet checksum for data."""
    if logger:
        logger.debug(f"Calculating checksum for {len(data)} bytes")

    if len(data) % 2 == 1:
        data += b"\x00"
        if logger:
            logger.debug("Added padding byte for odd-length data")

    sum_val = 0
    for i in range(0, len(data), 2):
        sum_val += struct.unpack("!H", data[i : i + 2])[0]

    while sum_val >> 16:
        sum_val = (sum_val & 0xFFFF) + (sum_val >> 16)

    checksum = ~sum_val & 0xFFFF
    if logger:
        logger.debug(f"Calculated checksum: 0x{checksum:04x}")

    return checksum


def parse_ip_port(
    addr: str, logger: Optional[logging.Logger] = None
) -> Tuple[str, int]:
    """Parse IP:port string into tuple."""
    if logger:
        logger.debug(f"Parsing address: {addr}")

    if ":" not in addr:
        error_msg = f"Invalid address format: {addr}"
        if logger:
            logger.error(error_msg)
        raise ValueError(error_msg)

    ip, port_str = addr.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError as e:
        error_msg = f"Invalid port: {port_str}"
        if logger:
            logger.error(f"{error_msg} - {e}")
        raise ValueError(error_msg)

    if not validate_ip(ip, logger):
        error_msg = f"Invalid IP: {ip}"
        if logger:
            logger.error(error_msg)
        raise ValueError(error_msg)

    if not validate_port(port, logger):
        error_msg = f"Invalid port: {port}"
        if logger:
            logger.error(error_msg)
        raise ValueError(error_msg)

    result = (ip, port)
    if logger:
        logger.debug(f"Successfully parsed address: {addr} -> {result}")

    return result


def format_ip_port(ip: str, port: int, logger: Optional[logging.Logger] = None) -> str:
    """Format IP and port into string."""
    result = f"{ip}:{port}"
    if logger:
        logger.debug(f"Formatted address: {ip}, {port} -> {result}")
    return result


def get_local_ip(logger: Optional[logging.Logger] = None) -> str:
    """Get local IP address."""
    try:
        if logger:
            logger.debug("Determining local IP address")

        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

            if logger:
                logger.debug(f"Local IP determined: {local_ip}")

            return local_ip
    except Exception as e:
        if logger:
            logger.warning(f"Failed to determine local IP, using localhost: {e}")
        return "127.0.0.1"
