#!/usr/bin/env python3
"""
TCP-over-ICMP Tunnel Client
Intercepts TCP packets using netfilterqueue and tunnels them over ICMP
"""

import argparse
import signal
import socket
import subprocess
import sys
import threading
from typing import cast

from netfilterqueue import NetfilterQueue, Packet
from scapy.all import Raw, send
from scapy.layers.inet import IP, TCP

from shared import (
    ConnectionManager,
    ConnectionState,
    TunnelFlags,
    TunnelHeader,
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
        self.icmp_socket = None
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
            pkt = IP(packet.get_payload())

            if not pkt.haslayer(TCP):
                packet.accept()
                return

            tcp = pkt[TCP]

            # Generate connection ID
            local_addr = (pkt.src, tcp.sport)
            remote_addr = (pkt.dst, tcp.dport)
            conn_id = TunnelProtocol.generate_connection_id(local_addr, remote_addr)

            # Get or create connection state
            conn_state = self.conn_manager.get_connection(conn_id)
            if not conn_state:
                conn_state = ConnectionState(local_addr, remote_addr)
                self.conn_manager.add_connection(conn_id, conn_state)

            conn_state.update_activity()

            # Determine tunnel flags
            flags = TunnelFlags.DATA
            if tcp.flags & 0x02:  # SYN
                flags |= TunnelFlags.SYN
                conn_state.state = "SYN_SENT"
            if tcp.flags & 0x10:  # ACK
                flags |= TunnelFlags.ACK
            if tcp.flags & 0x01:  # FIN
                flags |= TunnelFlags.FIN
                conn_state.state = "FIN_WAIT"
            if tcp.flags & 0x04:  # RST
                flags |= TunnelFlags.RST
                conn_state.state = "CLOSED"

            # Extract payload
            payload = bytes(tcp.payload) if tcp.payload else b""

            # Update sequence numbers
            conn_state.local_seq = tcp.seq
            conn_state.local_ack = tcp.ack

            # Create tunnel header
            header = TunnelHeader(
                conn_id=conn_id,
                seq_num=tcp.seq,
                ack_num=tcp.ack,
                flags=flags,
                data_len=len(payload),
            )

            # Create ICMP packet
            icmp_pkt = TunnelProtocol.create_icmp_packet(
                self.server_ip, header, payload
            )

            # Send over ICMP tunnel
            try:
                send(icmp_pkt, verbose=False)
                logger.debug(
                    f"Sent packet: conn_id={conn_id}, seq={tcp.seq}, flags={flags}, payload_len={len(payload)}"
                )
            except Exception as e:
                logger.error(f"Failed to send ICMP packet: {e}")
                packet.accept()
                return

            # Drop the original packet (don't let it go out normally)
            packet.drop()

            # Clean up closed connections
            if flags & (TunnelFlags.RST | TunnelFlags.FIN):
                if conn_state.state in ["CLOSED", "FIN_WAIT"]:
                    threading.Timer(
                        5.0, lambda: self.conn_manager.remove_connection(conn_id)
                    ).start()

        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            packet.accept()

    def handle_icmp_response(self):
        """Handle ICMP responses from server"""
        logger.info("Starting ICMP response handler...")

        while self.running and self.icmp_socket:
            try:
                # Receive ICMP packet
                data, addr = self.icmp_socket.recvfrom(4096)

                # Parse IP packet, cast for types
                ip_pkt = cast(IP, IP(data))

                # Parse tunnel data
                result = TunnelProtocol.parse_icmp_packet(ip_pkt)
                if not result:
                    continue

                header, payload = result

                # Get connection state
                conn_state = self.conn_manager.get_connection(header.conn_id)
                if not conn_state:
                    logger.warning(
                        f"Received data for unknown connection {header.conn_id}"
                    )
                    continue

                conn_state.update_activity()

                # Update remote sequence numbers
                conn_state.remote_seq = header.seq_num
                conn_state.remote_ack = header.ack_num

                # Create TCP response packet
                tcp_flags = 0
                if header.flags & TunnelFlags.SYN:
                    tcp_flags |= 0x02
                if header.flags & TunnelFlags.ACK:
                    tcp_flags |= 0x10
                if header.flags & TunnelFlags.FIN:
                    tcp_flags |= 0x01
                if header.flags & TunnelFlags.RST:
                    tcp_flags |= 0x04

                # Build TCP packet to inject back into network stack
                tcp_pkt = (
                    IP(src=conn_state.remote_addr[0], dst=conn_state.local_addr[0])
                    / TCP(
                        sport=conn_state.remote_addr[1],
                        dport=conn_state.local_addr[1],
                        flags=tcp_flags,
                        seq=header.seq_num,
                        ack=header.ack_num,
                        window=8192,
                    )
                    / Raw(load=payload)
                )

                # Send the crafted packet
                send(tcp_pkt, verbose=False)
                logger.debug(
                    f"Injected TCP response: conn_id={header.conn_id}, seq={header.seq_num}, payload_len={len(payload)}"
                )

                # Handle connection state changes
                if header.flags & TunnelFlags.SYN and header.flags & TunnelFlags.ACK:
                    conn_state.state = "ESTABLISHED"
                elif header.flags & TunnelFlags.FIN:
                    conn_state.state = "CLOSED"
                elif header.flags & TunnelFlags.RST:
                    conn_state.state = "CLOSED"
                    self.conn_manager.remove_connection(header.conn_id)

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error handling ICMP response: {e}")
                break

        logger.info("ICMP response handler stopped")

    def start(self):
        """Start the tunnel client"""
        if not is_root():
            logger.error("Client must be run as root for raw sockets and iptables")
            return False

        try:
            # Create raw ICMP socket
            self.icmp_socket = TunnelProtocol.create_raw_socket()
            self.icmp_socket.settimeout(1.0)

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

        # Close sockets
        if self.icmp_socket:
            try:
                self.icmp_socket.close()
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
