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

import netfilterqueue as nfq
from scapy.all import Packet as ScapyPacket
from scapy.all import Raw, send, sr
from scapy.layers.inet import ICMP, IP, TCP

from shared import (
    ICMP_ECHO_REPLY,
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

    def parse_nfq_packet(self, pkt: nfq.Packet):
        scapy_packet = IP(pkt.get_payload())
        if (
            scapy_packet.haslayer(ICMP)
            and scapy_packet[ICMP].id == TunnelProtocol.ICMP_ID
            and scapy_packet[ICMP].type == ICMP_ECHO_REQUEST
        ):
            tcp = IP(scapy_packet[ICMP].payload)
            if tcp.haslayer(TCP):
                return (scapy_packet, tcp)
        return None

    def handle_icmp_packet(self, packet: nfq.Packet):
        """Handle incoming ICMP packet"""
        try:
            result = self.parse_nfq_packet(packet)
            if result:
                packet.drop()
                scapy_packet, tcp = result
                logger.info(
                    f"got icmp packet: {scapy_packet.summary()} and the encapsulated packet: {tcp.summary()}"
                )
                threading.Thread(target=self.forward_tcp_packet, args=result).start()
            else:
                packet.accept()
        except Exception:
            logger.exception("Error handling ICMP packet")
            packet.drop()

    def forward_tcp_packet(
        self, full_icmp_packet: ScapyPacket, encapsulated_tcp_packet: ScapyPacket
    ):
        client = (encapsulated_tcp_packet[IP].src, encapsulated_tcp_packet[TCP].sport)
        target = (encapsulated_tcp_packet[IP].dst, encapsulated_tcp_packet[TCP].dport)
        # deleting source to auto generate server ip and port so the response will get here and not the client
        del encapsulated_tcp_packet[IP].src
        del encapsulated_tcp_packet[TCP].sport
        response, unanswered = sr(encapsulated_tcp_packet)
        if len(unanswered) > 0:
            logger.warning(f"target {target[0]}:{target[1]} did not answer tcp request")
            return
        logger.debug(
            f"forwarding response from target {target[0]}:{target[1]} to client {client[0]} as icmp"
        )
        for query_answer in response:
            # NAT - change target to be client
            pkt = query_answer.answer
            logger.debug(f"response was {pkt.summary()}")
            pkt[IP].dst = client[0]
            pkt[TCP].dport = client[1]
            logger.debug(f"overridden pkt is now {pkt.summary()}")

            to_send = (
                IP(dst=client[0])
                / ICMP(type=ICMP_ECHO_REPLY, id=TunnelProtocol.ICMP_ID)
                / Raw(pkt.build())
            )
            logger.debug(f"sending response encapsulated as icmp {to_send.summary()}")
            send(to_send)

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
            self.nfqueue = nfq.NetfilterQueue()
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
