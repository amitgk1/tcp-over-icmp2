#!/usr/bin/env python3
"""
TCP-over-ICMP Tunnel Server
Receives ICMP packets, extracts TCP data, and forwards to real destinations
"""

import argparse
import select
import signal
import socket
import sys
import threading
import time
from typing import Dict, List

from scapy.all import Packet, send, sniff
from scapy.layers.inet import ICMP, IP

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


class TunnelServer:
    """TCP-over-ICMP Tunnel Server"""

    def __init__(self, bind_ip: str = "0.0.0.0", debug: bool = False):
        self.bind_ip = bind_ip
        self.debug = debug
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

    def handle_icmp_packet(self, packet):
        """Handle incoming ICMP packet"""
        try:
            # Parse tunnel data
            result = TunnelProtocol.parse_icmp_packet(packet)
            if not result:
                return

            header, payload = result
            client_ip = packet[IP].src

            # Track client
            self.clients[client_ip] = time.time()

            logger.debug(
                f"Received from {client_ip}: conn_id={header.conn_id}, seq={header.seq_num}, flags={header.flags}, data_len={len(payload)}"
            )

            # Get or create connection state
            conn_state = self.conn_manager.get_connection(header.conn_id)

            if not conn_state:
                # New connection - we need to determine the target from the first packet
                # For now, we'll extract it from the payload or use a default
                # In a real implementation, you might want to parse the original TCP packet
                # For demo purposes, let's assume HTTP traffic to a specific target

                # This is a simplified approach - in reality you'd want to parse the original
                # destination from the client's first packet or have the client send it
                target_host = "httpbin.org"  # Default target for testing
                target_port = 80

                try:
                    target_ip = socket.gethostbyname(target_host)
                    conn_state = ConnectionState(
                        local_addr=(
                            self.local_ip,
                            0,
                        ),  # We'll bind to a random local port
                        remote_addr=(target_ip, target_port),
                    )
                    # conn_state.client_ip = client_ip
                    self.conn_manager.add_connection(header.conn_id, conn_state)

                    logger.info(
                        f"New connection {header.conn_id} from {client_ip} to {target_host}:{target_port}"
                    )

                except Exception as e:
                    logger.error(f"Failed to resolve target {target_host}: {e}")
                    return

            conn_state.update_activity()

            # Handle connection based on flags
            if header.flags & TunnelFlags.SYN:
                self.handle_syn(conn_state, header, payload, client_ip)
            elif header.flags & TunnelFlags.FIN:
                self.handle_fin(conn_state, header, payload, client_ip)
            elif header.flags & TunnelFlags.RST:
                self.handle_rst(conn_state, header, payload, client_ip)
            elif header.flags & TunnelFlags.DATA:
                self.handle_data(conn_state, header, payload, client_ip)

        except Exception as e:
            logger.error(f"Error handling ICMP packet: {e}")

    def handle_syn(
        self,
        conn_state: ConnectionState,
        header: TunnelHeader,
        payload: bytes,
        client_ip: str,
    ):
        """Handle SYN packet - establish connection to target"""
        try:
            if conn_state.sock is None:
                # Create TCP connection to target
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)

                logger.info(
                    f"Connecting to {conn_state.remote_addr[0]}:{conn_state.remote_addr[1]}"
                )
                sock.connect(conn_state.remote_addr)

                conn_state.sock = sock
                conn_state.state = "ESTABLISHED"

                # Start thread to handle responses from target
                thread = threading.Thread(
                    target=self.handle_target_responses,
                    args=(conn_state, header.conn_id, client_ip),
                    daemon=True,
                )
                thread.start()
                self.connection_threads.append(thread)

                # Send SYN-ACK back to client
                response_header = TunnelHeader(
                    conn_id=header.conn_id,
                    seq_num=header.ack_num,
                    ack_num=header.seq_num + 1,
                    flags=TunnelFlags.SYN | TunnelFlags.ACK,
                    data_len=0,
                )

                self.send_icmp_response(client_ip, response_header, b"")

        except Exception as e:
            logger.error(f"Failed to establish connection: {e}")
            # Send RST back to client
            response_header = TunnelHeader(
                conn_id=header.conn_id,
                seq_num=header.ack_num,
                ack_num=header.seq_num + 1,
                flags=TunnelFlags.RST,
                data_len=0,
            )
            self.send_icmp_response(client_ip, response_header, b"")

    def handle_data(
        self,
        conn_state: ConnectionState,
        header: TunnelHeader,
        payload: bytes,
        client_ip: str,
    ):
        """Handle data packet - forward to target"""
        try:
            if conn_state.sock and conn_state.state == "ESTABLISHED":
                if payload:
                    # Send data to target
                    conn_state.sock.send(payload)
                    logger.debug(f"Forwarded {len(payload)} bytes to target")

                # Send ACK back to client
                response_header = TunnelHeader(
                    conn_id=header.conn_id,
                    seq_num=header.ack_num,
                    ack_num=header.seq_num + len(payload),
                    flags=TunnelFlags.ACK,
                    data_len=0,
                )

                self.send_icmp_response(client_ip, response_header, b"")

        except Exception as e:
            logger.error(f"Error forwarding data: {e}")
            # Connection might be broken, clean up
            self.conn_manager.remove_connection(header.conn_id)

    def handle_fin(
        self,
        conn_state: ConnectionState,
        header: TunnelHeader,
        payload: bytes,
        client_ip: str,
    ):
        """Handle FIN packet - close connection"""
        try:
            if conn_state.sock:
                conn_state.sock.close()
                conn_state.sock = None
                conn_state.state = "CLOSED"

            # Send FIN-ACK back to client
            response_header = TunnelHeader(
                conn_id=header.conn_id,
                seq_num=header.ack_num,
                ack_num=header.seq_num + 1,
                flags=TunnelFlags.FIN | TunnelFlags.ACK,
                data_len=0,
            )

            self.send_icmp_response(client_ip, response_header, b"")

            # Clean up connection after a delay
            threading.Timer(
                5.0, lambda: self.conn_manager.remove_connection(header.conn_id)
            ).start()

        except Exception as e:
            logger.error(f"Error handling FIN: {e}")

    def handle_rst(
        self,
        conn_state: ConnectionState,
        header: TunnelHeader,
        payload: bytes,
        client_ip: str,
    ):
        """Handle RST packet - reset connection"""
        try:
            if conn_state.sock:
                conn_state.sock.close()
                conn_state.sock = None

            conn_state.state = "CLOSED"
            self.conn_manager.remove_connection(header.conn_id)

        except Exception as e:
            logger.error(f"Error handling RST: {e}")

    def handle_target_responses(
        self, conn_state: ConnectionState, conn_id: int, client_ip: str
    ):
        """Handle responses from target server"""
        logger.debug(f"Starting response handler for connection {conn_id}")

        seq_num = 1000  # Starting sequence number for server responses

        try:
            sock = conn_state.sock
            if sock is None:
                return
            sock.settimeout(1.0)

            while self.running and conn_state.state == "ESTABLISHED":
                try:
                    # Check if socket is ready for reading
                    ready, _, _ = select.select([sock], [], [], 1.0)
                    if not ready:
                        continue

                    # Receive data from target
                    data = sock.recv(4096)
                    if not data:
                        # Connection closed by target
                        logger.debug(f"Target closed connection {conn_id}")
                        break

                    logger.debug(
                        f"Received {len(data)} bytes from target for connection {conn_id}"
                    )

                    # Send data back to client via ICMP
                    # Split large data into chunks if necessary
                    offset = 0
                    while offset < len(data):
                        chunk_size = min(
                            TunnelProtocol.MAX_DATA_SIZE, len(data) - offset
                        )
                        chunk = data[offset : offset + chunk_size]

                        response_header = TunnelHeader(
                            conn_id=conn_id,
                            seq_num=seq_num,
                            ack_num=0,  # ACK not needed for data from server
                            flags=TunnelFlags.DATA | TunnelFlags.ACK,
                            data_len=len(chunk),
                        )

                        self.send_icmp_response(client_ip, response_header, chunk)

                        seq_num += len(chunk)
                        offset += chunk_size

                        # Small delay between chunks to avoid overwhelming
                        if offset < len(data):
                            time.sleep(0.001)

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error receiving from target: {e}")
                    break

        except Exception as e:
            logger.error(f"Error in response handler: {e}")
        finally:
            # Clean up connection
            if conn_state.sock:
                try:
                    conn_state.sock.close()
                except:
                    pass
                conn_state.sock = None

            conn_state.state = "CLOSED"

            # Send FIN to client
            try:
                fin_header = TunnelHeader(
                    conn_id=conn_id,
                    seq_num=seq_num,
                    ack_num=0,
                    flags=TunnelFlags.FIN,
                    data_len=0,
                )
                self.send_icmp_response(client_ip, fin_header, b"")
            except:
                pass

            logger.debug(f"Response handler for connection {conn_id} finished")

    def send_icmp_response(self, client_ip: str, header: TunnelHeader, payload: bytes):
        """Send ICMP response back to client"""
        try:
            # Create ICMP echo reply
            icmp_pkt = TunnelProtocol.create_icmp_packet(client_ip, header, payload)

            # Change ICMP type to echo reply
            icmp_pkt[ICMP].type = 0  # Echo Reply

            # Send packet
            send(icmp_pkt, verbose=False)
            logger.debug(
                f"Sent ICMP response to {client_ip}: conn_id={header.conn_id}, flags={header.flags}, data_len={len(payload)}"
            )

        except Exception as e:
            logger.error(f"Failed to send ICMP response: {e}")

    def packet_filter(self, packet: Packet):
        """Filter for ICMP packets"""
        return (
            packet.haslayer(IP)
            and packet.haslayer(ICMP)
            and packet[ICMP].id == TunnelProtocol.ICMP_ID
        )

    def start_icmp_listener(self):
        """Start ICMP packet listener"""
        logger.info("Starting ICMP listener...")

        try:
            # Use scapy to sniff ICMP packets
            sniff(
                filter="icmp",
                prn=self.handle_icmp_packet,
                lfilter=self.packet_filter,
                stop_filter=lambda x: not self.running,
            )
        except Exception as e:
            if self.running:
                logger.error(f"Error in ICMP listener: {e}")

        logger.info("ICMP listener stopped")

    def cleanup_stale_clients(self):
        """Clean up stale client connections"""
        while self.running:
            try:
                time.sleep(60)  # Run every minute

                now = time.time()
                stale_clients = []

                # Find stale clients (no activity for 10 minutes)
                for client_ip, last_seen in self.clients.items():
                    if now - last_seen > 600:
                        stale_clients.append(client_ip)

                # Remove stale clients
                for client_ip in stale_clients:
                    logger.info(f"Removing stale client: {client_ip}")
                    del self.clients[client_ip]

                # Clean up stale connections
                self.conn_manager.cleanup_stale_connections()

            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")

    def start(self):
        """Start the tunnel server"""
        if not is_root():
            logger.error("Server must be run as root for raw sockets")
            return False

        try:
            self.running = True

            logger.info(f"Starting tunnel server on {self.bind_ip}")
            logger.info("Waiting for ICMP tunnel connections...")

            # Start cleanup thread
            cleanup_thread = threading.Thread(
                target=self.cleanup_stale_clients, daemon=True
            )
            cleanup_thread.start()

            # Start ICMP listener (blocking)
            self.start_icmp_listener()

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

    def status(self):
        """Print server status"""
        print(f"\n=== Tunnel Server Status ===")
        print(f"Running: {self.running}")
        print(f"Active clients: {len(self.clients)}")
        print(f"Active connections: {len(self.conn_manager.connections)}")

        if self.clients:
            print(f"\nClients:")
            for client_ip, last_seen in self.clients.items():
                age = time.time() - last_seen
                print(f"  {client_ip}: last seen {age:.1f}s ago")

        if self.conn_manager.connections:
            print(f"\nConnections:")
            for conn_id, conn_state in self.conn_manager.connections.items():
                age = time.time() - conn_state.last_activity
                print(
                    f"  {conn_id}: {conn_state.local_addr} -> {conn_state.remote_addr} "
                    f"[{conn_state.state}] (idle {age:.1f}s)"
                )


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
    parser.add_argument(
        "--status", action="store_true", help="Show server status and exit"
    )

    args = parser.parse_args()

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create server
    global server
    server = TunnelServer(args.bind_ip, args.debug)

    if args.status:
        server.status()
        return

    if not server.start():
        sys.exit(1)


if __name__ == "__main__":
    main()
