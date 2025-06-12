#!/usr/bin/env python3
"""
TCP-over-ICMP Tunnel Server
Receives ICMP packets, extracts TCP data, and forwards to real destinations
"""

import select
import socket
import sys
import threading
from typing import Dict

from shared import (
    ConnectionTracker,
    ConnState,
    TunnelHeader,
    create_icmp_packet,
    create_raw_socket,
    logger,
    parse_icmp_packet,
)


class TunnelServer:
    def __init__(self, bind_ip: str = "0.0.0.0"):
        self.bind_ip = bind_ip
        self.tracker = ConnectionTracker()
        self.running = False

        # Create raw socket for ICMP
        self.icmp_socket = create_raw_socket()

        # Active TCP connections to real servers
        self.tcp_sockets: Dict[int, socket.socket] = {}

    def handle_new_connection(
        self,
        conn_id: int,
        dst_ip: str,
        dst_port: int,
        client_ip: str,
        header: TunnelHeader,
        payload: bytes,
    ):
        """Handle new TCP connection establishment"""
        try:
            # Create TCP socket to real destination
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.settimeout(10)

            logger.info(f"Connecting to {dst_ip}:{dst_port} for connection {conn_id}")
            tcp_sock.connect((dst_ip, dst_port))
            tcp_sock.settimeout(None)

            # Store socket
            self.tcp_sockets[conn_id] = tcp_sock

            # Update connection state
            conn = self.tracker.get_connection(conn_id)
            if conn:
                conn["state"] = ConnState.ESTABLISHED
                conn["socket"] = tcp_sock

            # Send initial data if any
            if payload:
                tcp_sock.send(payload)
                logger.debug(f"Sent {len(payload)} bytes to {dst_ip}:{dst_port}")

            # Send SYN-ACK equivalent back to client
            response_header = TunnelHeader(
                conn_id=conn_id,
                seq_num=header.ack_num,
                ack_num=header.seq_num + len(payload) + 1,
                flags=0x12,  # SYN+ACK
                data_len=0,
            )

            response_packet = create_icmp_packet(client_ip, response_header)
            self.icmp_socket.sendto(response_packet, (client_ip, 0))

            # Start thread to handle this connection
            conn_thread = threading.Thread(
                target=self.handle_tcp_connection,
                args=(conn_id, tcp_sock, client_ip),
                daemon=True,
            )
            conn_thread.start()

        except Exception as e:
            logger.error(f"Failed to establish connection to {dst_ip}:{dst_port}: {e}")
            self.send_rst_to_client(conn_id, client_ip, header)

    def handle_tcp_connection(
        self, conn_id: int, tcp_sock: socket.socket, client_ip: str
    ):
        """Handle ongoing TCP connection"""
        try:
            while self.running:
                # Wait for data from real server
                ready, _, _ = select.select([tcp_sock], [], [], 1.0)
                if not ready:
                    continue

                data = tcp_sock.recv(4096)
                if not data:
                    # Connection closed by server
                    logger.info(f"Connection {conn_id} closed by server")
                    self.send_fin_to_client(conn_id, client_ip)
                    break

                # Send data back to client via ICMP
                conn = self.tracker.get_connection(conn_id)
                if not conn:
                    break

                response_header = TunnelHeader(
                    conn_id=conn_id,
                    seq_num=conn["server_seq"],
                    ack_num=conn["client_seq"],
                    flags=0x18,  # PSH+ACK
                    data_len=len(data),
                )

                response_packet = create_icmp_packet(client_ip, response_header, data)
                self.icmp_socket.sendto(response_packet, (client_ip, 0))

                logger.debug(
                    f"Sent {len(data)} bytes back to client for connection {conn_id}"
                )

                # Update sequence numbers
                conn["server_seq"] += len(data)

        except Exception as e:
            logger.error(f"Error handling TCP connection {conn_id}: {e}")
        finally:
            self.cleanup_connection(conn_id)

    def send_rst_to_client(
        self, conn_id: int, client_ip: str, original_header: TunnelHeader
    ):
        """Send RST packet to client"""
        rst_header = TunnelHeader(
            conn_id=conn_id,
            seq_num=original_header.ack_num,
            ack_num=original_header.seq_num + 1,
            flags=0x04,  # RST
            data_len=0,
        )

        rst_packet = create_icmp_packet(client_ip, rst_header)
        self.icmp_socket.sendto(rst_packet, (client_ip, 0))

    def send_fin_to_client(self, conn_id: int, client_ip: str):
        """Send FIN packet to client"""
        conn = self.tracker.get_connection(conn_id)
        if not conn:
            return

        fin_header = TunnelHeader(
            conn_id=conn_id,
            seq_num=conn["server_seq"],
            ack_num=conn["client_seq"],
            flags=0x01,  # FIN
            data_len=0,
        )

        fin_packet = create_icmp_packet(client_ip, fin_header)
        self.icmp_socket.sendto(fin_packet, (client_ip, 0))

    def cleanup_connection(self, conn_id: int):
        """Clean up connection resources"""
        if conn_id in self.tcp_sockets:
            self.tcp_sockets[conn_id].close()
            del self.tcp_sockets[conn_id]

        self.tracker.remove_connection(conn_id)

    def handle_icmp_packet(self, data: bytes, client_ip: str):
        """Process incoming ICMP packet from client"""
        try:
            header, payload = parse_icmp_packet(data)
            if not header:
                return

            logger.debug(
                f"Received tunnel packet: conn_id={header.conn_id}, "
                f"flags={header.flags}, data_len={header.data_len}"
            )

            # Get or create connection
            conn = self.tracker.get_connection(header.conn_id)

            # Handle SYN (new connection)
            if header.flags & 0x02:  # SYN flag
                if not conn:
                    # Use destination from tunnel header
                    dst_ip = header.dst_ip
                    dst_port = header.dst_port

                    if not dst_ip or not dst_port:
                        logger.error(
                            f"No destination info in SYN packet for connection {header.conn_id}"
                        )
                        self.send_rst_to_client(header.conn_id, client_ip, header)
                        return

                    # Create connection tracking
                    self.tracker.add_connection(
                        header.conn_id, client_ip, 0, dst_ip, dst_port, header.seq_num
                    )

                    # Handle new connection
                    self.handle_new_connection(
                        header.conn_id, dst_ip, dst_port, client_ip, header, payload
                    )
                return

            if not conn:
                logger.warning(
                    f"Received packet for unknown connection {header.conn_id}"
                )
                return

            # Handle data packets
            if header.data_len > 0 and header.conn_id in self.tcp_sockets:
                tcp_sock = self.tcp_sockets[header.conn_id]
                tcp_sock.send(payload)
                logger.debug(f"Forwarded {len(payload)} bytes to real server")

                # Update sequence tracking
                conn["client_seq"] = header.seq_num + header.data_len

            # Handle FIN (connection close)
            if header.flags & 0x01:  # FIN flag
                logger.info(f"Client closing connection {header.conn_id}")
                self.cleanup_connection(header.conn_id)

            # Handle RST (connection reset)
            if header.flags & 0x04:  # RST flag
                logger.info(f"Client reset connection {header.conn_id}")
                self.cleanup_connection(header.conn_id)

        except Exception as e:
            logger.error(f"Error handling ICMP packet: {e}")

    def start(self):
        """Start the tunnel server"""
        logger.info(f"Starting TCP-over-ICMP tunnel server on {self.bind_ip}")

        self.running = True

        try:
            while self.running:
                # Receive ICMP packets
                data, addr = self.icmp_socket.recvfrom(65535)
                client_ip = addr[0]

                # Handle in separate thread for concurrency
                handler_thread = threading.Thread(
                    target=self.handle_icmp_packet, args=(data, client_ip), daemon=True
                )
                handler_thread.start()

        except KeyboardInterrupt:
            logger.info("Stopping tunnel server...")
        finally:
            self.stop()

    def stop(self):
        """Stop the tunnel server"""
        self.running = False

        # Close all TCP connections
        for sock in self.tcp_sockets.values():
            sock.close()
        self.tcp_sockets.clear()

        self.icmp_socket.close()
        logger.info("Tunnel server stopped")


def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root")
        sys.exit(1)

    server = TunnelServer()
    server.start()


if __name__ == "__main__":
    import os

    main()
