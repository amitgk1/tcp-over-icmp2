#!/usr/bin/env python3
"""
Debug script for TCP-over-ICMP tunnel development.

This script provides various debugging utilities and tests for the tunnel components.
"""

import argparse
import logging
import sys
from typing import Optional

from shared import (
    ConnectionManager,
    PacketHandler,
    PacketType,
    TunnelPacket,
    format_ip_port,
    get_local_ip,
    parse_ip_port,
    setup_logging,
    validate_ip,
    validate_port,
)


def test_packet_handler(logger: logging.Logger):
    """Test packet handler functionality."""
    logger.info("Testing PacketHandler...")

    handler = PacketHandler(logger=logger)

    # Test single packet creation
    test_data = b"Hello, World! This is a test packet."
    logger.info(f"Creating packet with data: {test_data}")

    packets = handler.create_packet(PacketType.DATA, "test-conn-123", test_data)
    logger.info(f"Created {len(packets)} packet(s)")

    # Test packet parsing
    for i, packet_data in enumerate(packets):
        logger.info(f"Parsing packet {i+1}...")
        parsed_packet = handler.parse_packet(packet_data)

        if parsed_packet:
            logger.info(f"✓ Successfully parsed packet {i+1}")
            logger.info(f"  Type: {parsed_packet.packet_type.name}")
            logger.info(f"  Connection: {parsed_packet.connection_id}")
            logger.info(f"  Data size: {len(parsed_packet.data)}")
            logger.info(f"  Sequence: {parsed_packet.sequence}")
        else:
            logger.error(f"✗ Failed to parse packet {i+1}")

    # Test large packet fragmentation
    large_data = b"X" * 10000  # 10KB of data
    logger.info(f"Testing fragmentation with {len(large_data)} bytes of data...")

    fragmented_packets = handler.create_packet(
        PacketType.DATA, "test-conn-456", large_data
    )
    logger.info(f"Created {len(fragmented_packets)} fragmented packets")

    # Test fragment reassembly
    for i, packet_data in enumerate(fragmented_packets):
        parsed_packet = handler.parse_packet(packet_data)
        if parsed_packet:
            reassembled_data = handler.handle_fragmented_packet(parsed_packet)
            if reassembled_data:
                logger.info(f"✓ Successfully reassembled data from fragment {i+1}")
                logger.info(f"  Reassembled size: {len(reassembled_data)}")
            else:
                logger.debug(f"Fragment {i+1} stored, waiting for more fragments")


def test_connection_manager(logger: logging.Logger):
    """Test connection manager functionality."""
    logger.info("Testing ConnectionManager...")

    manager = ConnectionManager(logger=logger)
    manager.start()

    # Test connection creation
    client_addr = ("192.168.1.100", 12345)
    server_addr = ("8.8.8.8", 80)

    logger.info(f"Adding connection: {client_addr} -> {server_addr}")
    conn_id = manager.add_connection(client_addr, server_addr)
    logger.info(f"Connection ID: {conn_id}")

    # Test connection retrieval
    conn = manager.get_connection(conn_id)
    if conn:
        logger.info(f"✓ Successfully retrieved connection: {conn.connection_id}")
        logger.info(f"  Client: {conn.client_addr}")
        logger.info(f"  Server: {conn.server_addr}")
        logger.info(f"  State: {conn.state.value}")
    else:
        logger.error("✗ Failed to retrieve connection")

    # Test connection stats
    stats = manager.get_connection_stats()
    logger.info(f"Connection stats: {stats}")

    # Test connection cleanup
    logger.info("Testing connection cleanup...")
    manager.close_connection(conn_id)

    conn_after_close = manager.get_connection(conn_id)
    if not conn_after_close:
        logger.info("✓ Connection successfully closed and removed")
    else:
        logger.error("✗ Connection still exists after close")

    manager.stop()


def test_utils(logger: logging.Logger):
    """Test utility functions."""
    logger.info("Testing utility functions...")

    # Test IP validation
    test_ips = ["192.168.1.1", "10.0.0.1", "256.256.256.256", "invalid-ip"]
    for ip in test_ips:
        is_valid = validate_ip(ip, logger)
        logger.info(f"IP {ip}: {'✓' if is_valid else '✗'}")

    # Test port validation
    test_ports = [80, 443, 8080, 0, 65536, 70000]
    for port in test_ports:
        is_valid = validate_port(port, logger)
        logger.info(f"Port {port}: {'✓' if is_valid else '✗'}")

    # Test address parsing
    test_addresses = [
        "192.168.1.1:80",
        "10.0.0.1:443",
        "invalid:address",
        "192.168.1.1",
    ]
    for addr in test_addresses:
        try:
            parsed = parse_ip_port(addr, logger)
            logger.info(f"Address {addr}: ✓ -> {parsed}")
        except ValueError as e:
            logger.info(f"Address {addr}: ✗ -> {e}")

    # Test address formatting
    test_pairs = [("192.168.1.1", 80), ("10.0.0.1", 443)]
    for ip, port in test_pairs:
        formatted = format_ip_port(ip, port, logger)
        logger.info(f"Format {ip}:{port}: ✓ -> {formatted}")

    # Test local IP detection
    local_ip = get_local_ip(logger)
    logger.info(f"Local IP: {local_ip}")


def test_network_connectivity(logger: logging.Logger):
    """Test basic network connectivity."""
    logger.info("Testing network connectivity...")

    import socket

    # Test DNS resolution
    test_hosts = ["google.com", "8.8.8.8", "192.168.1.1"]
    for host in test_hosts:
        try:
            ip = socket.gethostbyname(host)
            logger.info(f"DNS {host}: ✓ -> {ip}")
        except socket.gaierror as e:
            logger.info(f"DNS {host}: ✗ -> {e}")

    # Test port connectivity
    test_connections = [
        ("8.8.8.8", 53),  # Google DNS
        ("1.1.1.1", 53),  # Cloudflare DNS
        ("192.168.1.1", 80),  # Common router
    ]

    for host, port in test_connections:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                logger.info(f"Connect {host}:{port}: ✓")
            else:
                logger.info(f"Connect {host}:{port}: ✗ (error code: {result})")
        except Exception as e:
            logger.info(f"Connect {host}:{port}: ✗ -> {e}")


def main():
    """Main debug function."""
    parser = argparse.ArgumentParser(description="TCP-over-ICMP Tunnel Debug Tool")
    parser.add_argument(
        "--log-level",
        "-l",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="DEBUG",
        help="Log level (default: DEBUG)",
    )
    parser.add_argument(
        "--test",
        "-t",
        choices=["packet", "connection", "utils", "network", "all"],
        default="all",
        help="Test to run (default: all)",
    )
    parser.add_argument("--log-file", help="Log file path (optional)")

    args = parser.parse_args()

    # Set up logging
    logger = setup_logging(
        name="tcp-over-icmp-debug", level=args.log_level, log_file=args.log_file
    )

    logger.info("=" * 60)
    logger.info("TCP-over-ICMP Tunnel Debug Tool")
    logger.info("=" * 60)

    try:
        if args.test in ["packet", "all"]:
            test_packet_handler(logger)
            logger.info("")

        if args.test in ["connection", "all"]:
            test_connection_manager(logger)
            logger.info("")

        if args.test in ["utils", "all"]:
            test_utils(logger)
            logger.info("")

        if args.test in ["network", "all"]:
            test_network_connectivity(logger)
            logger.info("")

        logger.info("=" * 60)
        logger.info("Debug tests completed successfully!")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"Debug test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
