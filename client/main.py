#!/usr/bin/env python3
"""
TCP-over-ICMP Tunnel Client
Intercepts outgoing TCP connections and tunnels them over ICMP
"""

import socket
import subprocess
import sys
import threading

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP, TCP

from shared import (
    ConnectionTracker,
    ConnState,
    TunnelHeader,
    create_icmp_packet,
    create_raw_socket,
    create_tcp_response,
    extract_tcp_info,
    logger,
    parse_icmp_packet,
)


class TunnelClient:
    def __init__(self, server_ip: str, queue_num: int = 0):
        self.server_ip = server_ip
        self.queue_num = queue_num
        self.tracker = ConnectionTracker()
        self.running = False

        # Create raw socket for ICMP communication
        self.icmp_socket = create_raw_socket()

    def setup_iptables(self):
        """Setup iptables rules to intercept TCP traffic"""
        rules = [
            f"iptables -t mangle -I OUTPUT -p tcp --dport 1:65535 -j NFQUEUE --queue-num {self.queue_num}",
        ]

        for rule in rules:
            try:
                subprocess.run(rule.split(), check=True)
                logger.info(f"Added iptables rule: {rule}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to add iptables rule: {e}")

    def cleanup_iptables(self):
        """Remove iptables rules"""
        rules = [
            f"iptables -t mangle -D OUTPUT -p tcp --dport 1:65535 -j NFQUEUE --queue-num {self.queue_num}",
        ]

        for rule in rules:
            try:
                subprocess.run(rule.split(), check=True, stderr=subprocess.DEVNULL)
                logger.info(f"Removed iptables rule: {rule}")
            except subprocess.CalledProcessError:
                pass  # Rule might not exist

    def handle_tcp_packet(self, packet):
        """Process intercepted TCP packet"""
        try:
            packet_data = packet.get_payload()
            src_ip, src_port, dst_ip, dst_port, seq, ack, flags = extract_tcp_info(
                packet_data
            )

            # Generate connection ID
            conn_id = self.tracker.generate_conn_id(src_ip, src_port, dst_ip, dst_port)

            # Get or create connection
            conn = self.tracker.get_connection(conn_id)
            if not conn:
                self.tracker.add_connection(
                    conn_id, src_ip, src_port, dst_ip, dst_port, seq
                )
                conn = self.tracker.get_connection(conn_id)

            # Extract TCP payload
            tcp_pkt = IP(packet_data)
            payload = b""
            if tcp_pkt[TCP].payload:
                payload = bytes(tcp_pkt[TCP].payload)

            # Create tunnel header with destination info
            tunnel_header = TunnelHeader(
                conn_id=conn_id,
                seq_num=seq,
                ack_num=ack,
                flags=flags,
                data_len=len(payload),
                dst_ip=dst_ip,
                dst_port=dst_port,
            )

            # Send via ICMP tunnel
            icmp_packet = create_icmp_packet(self.server_ip, tunnel_header, payload)
            self.icmp_socket.sendto(icmp_packet, (self.server_ip, 0))

            logger.debug(
                f"Tunneled packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, "
                f"seq={seq}, flags={flags}, payload_len={len(payload)}"
            )

            # Update connection state
            if flags & 0x02:  # SYN flag
                conn["state"] = ConnState.SYN_SENT
            elif flags & 0x01:  # FIN flag
                conn["state"] = ConnState.FIN_WAIT

            # Drop the original packet (don't let it go out normally)
            packet.drop()

        except Exception as e:
            logger.exception(f"Error handling TCP packet: {e}")
            packet.drop()

    def icmp_listener(self):
        """Listen for ICMP responses from server"""
        while self.running:
            try:
                data, addr = self.icmp_socket.recvfrom(65535)

                # Parse ICMP packet
                header, payload = parse_icmp_packet(data)
                if not header:
                    continue

                # Get connection info
                conn = self.tracker.get_connection(header.conn_id)
                if not conn:
                    logger.warning(
                        f"Received packet for unknown connection {header.conn_id}"
                    )
                    continue

                # Create TCP response packet
                tcp_response = create_tcp_response(
                    conn["dst_ip"],
                    conn["dst_port"],
                    conn["src_ip"],
                    conn["src_port"],
                    header.seq_num,
                    header.ack_num,
                    header.flags,
                    payload,
                )

                # Inject response back into network stack
                response_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
                )
                response_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                response_socket.sendto(tcp_response, (conn["src_ip"], 0))
                response_socket.close()

                logger.debug(
                    f"Injected response: {conn['dst_ip']}:{conn['dst_port']} -> "
                    f"{conn['src_ip']}:{conn['src_port']}, seq={header.seq_num}"
                )

                # Update connection state
                if header.flags & 0x01:  # FIN flag
                    self.tracker.remove_connection(header.conn_id)

            except Exception as e:
                logger.error(f"Error in ICMP listener: {e}")

    def start(self):
        """Start the tunnel client"""
        logger.info(f"Starting TCP-over-ICMP tunnel client (server: {self.server_ip})")

        # Setup iptables rules
        self.setup_iptables()

        # Start ICMP listener thread
        self.running = True
        icmp_thread = threading.Thread(target=self.icmp_listener, daemon=True)
        icmp_thread.start()

        # Setup netfilter queue
        nfqueue = NetfilterQueue()
        nfqueue.bind(self.queue_num, self.handle_tcp_packet)

        try:
            logger.info("Tunnel client started. Press Ctrl+C to stop.")
            nfqueue.run()
        except KeyboardInterrupt:
            logger.info("Stopping tunnel client...")
        finally:
            self.stop()

    def stop(self):
        """Stop the tunnel client"""
        self.running = False
        self.cleanup_iptables()
        self.icmp_socket.close()
        logger.info("Tunnel client stopped")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 client.py <server_ip>")
        sys.exit(1)

    server_ip = sys.argv[1]

    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root")
        sys.exit(1)

    client = TunnelClient(server_ip)
    client.start()


if __name__ == "__main__":
    import os

    main()
