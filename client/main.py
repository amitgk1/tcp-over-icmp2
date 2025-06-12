#!/usr/bin/env python3
"""
TCP-over-ICMP Tunnel Client
Intercepts TCP packets using netfilterqueue and tunnels them over ICMP
"""

import argparse
import signal
import subprocess
import sys
import threading

from netfilterqueue import NetfilterQueue, Packet
from scapy.all import Raw
from scapy.layers.inet import ICMP, IP, TCP

from shared import (
    ICMP_ECHO_REQUEST,
    ConnectionManager,
    TunnelProtocol,
    get_local_ip,
    is_root,
    logger,
    setup_logging,
)


class TunnelClient:
    """TCP-over-ICMP Tunnel Client"""

    def __init__(self, server_ip: str, queue_num: int = 0, debug: bool = False):
        self.server_ip = server_ip
        self.queue_num = queue_num
        self.debug = debug
        self.running = False

        # Connection management
        self.conn_manager = ConnectionManager()
        self.local_ip = get_local_ip()

        # Sockets
        self.icmp_sock = TunnelProtocol.create_raw_socket()
        self.nfqueue = None

        # Threading
        self.icmp_thread = None

        # Setup logging
        setup_logging(debug)

    def setup_iptables_rules(self):
        """Setup iptables rules to intercept TCP packets"""
        rules = [
            # Intercept outgoing TCP packets (common ports)
            f"iptables -t mangle -A OUTPUT -p tcp --dport 80,443,22,21,25,53,110,143,993,995 -j NFQUEUE --queue-num {self.queue_num}",
            # Intercept HTTP/HTTPS specifically
            f"iptables -t mangle -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num {self.queue_num}",
            f"iptables -t mangle -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num {self.queue_num}",
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
            f"iptables -t mangle -D OUTPUT -p tcp --dport 80,443,22,21,25,53,110,143,993,995 -j NFQUEUE --queue-num {self.queue_num}",
            f"iptables -t mangle -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num {self.queue_num}",
            f"iptables -t mangle -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num {self.queue_num}",
        ]

        logger.info("Cleaning up iptables rules...")
        for rule in rules:
            try:
                subprocess.run(rule.split(), capture_output=True)
            except:
                pass

    def process_packet(self, packet: Packet):
        """Process intercepted TCP packet"""
        try:
            data = packet.get_payload()
            pkt = IP(data)

            if not pkt.haslayer(TCP):
                packet.accept()
                return

            to_send = (
                IP(dst=self.server_ip)
                / ICMP(type=ICMP_ECHO_REQUEST, id=TunnelProtocol.ICMP_ID)
                / Raw(data)
            )
            logger.info(
                f"got tpc packet, sending it as icmp and letting if get forwarded anyway for now\npkt: {to_send.summary()}"
            )
            if (
                self.icmp_sock.sendto(
                    to_send.build(),
                    (self.server_ip, 0),
                )
                <= 0
            ):
                logger.warning("did not send bytes...")
            packet.accept()

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            packet.accept()

    def handle_icmp_response(self):
        """Handle ICMP responses from server"""
        try:
            while True:
                data = self.icmp_sock.recv(1024 * 4)
                packet = IP(data)
                if ICMP in packet:
                    logger.info(f"got icmp response: {packet.summary()}")
        except Exception as e:
            if self.running:
                logger.error(f"Error handling ICMP response: {e}")

    def start(self):
        """Start the tunnel client"""
        if not is_root():
            logger.error("Client must be run as root for raw sockets and iptables")
            return False

        try:
            # Setup iptables rules
            self.setup_iptables_rules()

            # Setup netfilter queue
            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(self.queue_num, self.process_packet)

            self.running = True

            # Start ICMP response handler thread
            self.icmp_thread = threading.Thread(
                target=self.handle_icmp_response, daemon=True
            )
            self.icmp_thread.start()

            logger.info(f"Tunnel client started. Server: {self.server_ip}")
            logger.info("All TCP traffic will be tunneled through ICMP")

            # Run netfilter queue (blocking)
            self.nfqueue.run()

        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        except Exception as e:
            logger.error(f"Error starting client: {e}")
        finally:
            self.stop()

        return True

    def stop(self):
        """Stop the tunnel client"""
        logger.info("Stopping tunnel client...")

        self.running = False

        # Close netfilter queue
        if self.nfqueue:
            try:
                self.nfqueue.unbind()
            except:
                pass

        # Wait for threads
        if self.icmp_thread and self.icmp_thread.is_alive():
            self.icmp_thread.join(timeout=2)

        # Cleanup iptables rules
        self.cleanup_iptables_rules()

        # Close all connections
        for conn_id in list(self.conn_manager.connections.keys()):
            self.conn_manager.remove_connection(conn_id)

        logger.info("Tunnel client stopped")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}")
    global client
    if client:
        client.stop()
    sys.exit(0)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="TCP-over-ICMP Tunnel Client")
    parser.add_argument("server_ip", help="IP address of tunnel server")
    parser.add_argument(
        "--queue-num", type=int, default=0, help="Netfilter queue number (default: 0)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create and start client
    global client
    client = TunnelClient(args.server_ip, args.queue_num, args.debug)

    if not client.start():
        sys.exit(1)


if __name__ == "__main__":
    main()
