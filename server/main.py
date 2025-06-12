#!/usr/bin/env python3
"""
TCP-over-ICMP Tunnel Server
Receives ICMP packets, extracts TCP data, and forwards to real destinations
"""

import argparse
import subprocess
import sys
import threading
from typing import Dict, List

from netfilterqueue import NetfilterQueue, Packet
from scapy.layers.inet import ICMP, IP

from shared import (
    ICMP_ECHO_REQUEST,
    ConnectionManager,
    TunnelProtocol,
    get_local_ip,
    is_root,
    logger,
    setup_logging,
)


class TunnelServer:
    """TCP-over-ICMP Tunnel Server"""

    def __init__(
        self, bind_ip: str = "0.0.0.0", debug: bool = False, queue_num: int = 1
    ):
        self.bind_ip = bind_ip
        self.debug = debug
        self.queue_num = queue_num
        self.running = False

        # Connection management
        self.conn_manager = ConnectionManager()
        self.local_ip = get_local_ip()

        # Client tracking
        self.clients: Dict[str, float] = {}  # client_ip -> last_seen

        # Threading
        self.icmp_thread = None
        self.connection_threads: List[threading.Thread] = []

        # Setup logging
        setup_logging(debug)

    def setup_iptables_rules(self):
        """Setup iptables rules to intercept ICMP packets"""
        rules = [
            f"iptables -t raw -A PREROUTING -p icmp -j NFQUEUE --queue-num {self.queue_num}",
        ]

        logger.info("Setting up iptables rules...")
        for rule in rules:
            try:
                result = subprocess.run(rule.split(), capture_output=True, text=True)
                if result.returncode != 0:
                    logger.warning(f"Failed to add rule: {rule}")
                    logger.warning(f"Error: {result.stderr}")
                else:
                    logger.debug(f"Added rule: {rule}")
            except Exception as e:
                logger.error(f"Error adding iptables rule: {e}")

    def cleanup_iptables_rules(self):
        """Remove iptables rules"""
        rules = [
            f"iptables -t raw -D PREROUTING -p icmp -j NFQUEUE --queue-num {self.queue_num}",
        ]

        logger.info("Cleaning up iptables rules...")
        for rule in rules:
            try:
                subprocess.run(rule.split(), capture_output=True)
            except:
                pass

    def handle_icmp_packet(self, packet: Packet):
        """Handle incoming ICMP packet"""
        try:
            scapy_packet = IP(packet.get_payload())
            if (
                scapy_packet.haslayer(ICMP)
                and scapy_packet[ICMP].id == TunnelProtocol.ICMP_ID
                and scapy_packet[ICMP].type == ICMP_ECHO_REQUEST
            ):
                packet.drop()
                logger.info(f"got icmp packet: {scapy_packet.summary()}")
            else:
                packet.accept()
        except Exception as e:
            logger.error(f"Error handling ICMP packet: {e}")

    def start(self):
        """Start the tunnel server"""
        if not is_root():
            logger.error("Server must be run as root for raw sockets")
            return False

        try:
            self.running = True

            logger.info(f"Starting tunnel server on {self.bind_ip}")
            logger.info("Waiting for ICMP tunnel connections...")

            self.setup_iptables_rules()

            # Setup netfilter queue
            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(self.queue_num, self.handle_icmp_packet)
            self.nfqueue.run()

        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        except Exception as e:
            logger.error(f"Error starting server: {e}")
        finally:
            self.stop()

        return True

    def stop(self):
        """Stop the tunnel server"""
        logger.info("Stopping tunnel server...")

        self.running = False

        # Cleanup iptables rules
        self.cleanup_iptables_rules()

        # Close all connections
        for conn_id in list(self.conn_manager.connections.keys()):
            conn_state = self.conn_manager.get_connection(conn_id)
            if conn_state and conn_state.sock:
                try:
                    conn_state.sock.close()
                except:
                    pass
            self.conn_manager.remove_connection(conn_id)

        # Wait for connection threads to finish
        for thread in self.connection_threads:
            if thread.is_alive():
                thread.join(timeout=2)

        logger.info("Tunnel server stopped")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}")
    global server
    if server:
        server.stop()
    sys.exit(0)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="TCP-over-ICMP Tunnel Server")
    parser.add_argument(
        "--bind-ip", default="0.0.0.0", help="IP address to bind to (default: 0.0.0.0)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # # Setup signal handlers
    # signal.signal(signal.SIGINT, signal_handler)
    # signal.signal(signal.SIGTERM, signal_handler)

    # Create server
    global server
    server = TunnelServer(args.bind_ip, args.debug)

    if not server.start():
        sys.exit(1)


if __name__ == "__main__":
    main()
