import logging
import select
import socket
import threading
import time
from typing import Optional, Tuple

import netfilterqueue
from scapy.all import Raw, sniff, sr1
from scapy.layers.inet import ICMP, IP

from shared import ConnectionManager, PacketHandler, PacketType, TunnelPacket

# Linux-specific socket option for getting original destination
SO_ORIGINAL_DST = 80


class TunnelClient:
    """Client-side tunnel that receives redirected TCP traffic and tunnels it via ICMP."""

    def __init__(
        self,
        server_ip: str,
        proxy_port: int = 8080,
        icmp_id: int = 12345,
        max_retries: int = 3,
        retry_timeout: float = 1.0,
        logger: Optional[logging.Logger] = None,
    ):
        self.server_ip = server_ip
        self.proxy_port = proxy_port
        self.icmp_id = icmp_id
        self.max_retries = max_retries
        self.retry_timeout = retry_timeout
        self.logger = logger or logging.getLogger(__name__)

        self.packet_handler = PacketHandler(logger=self.logger)
        self.connection_manager = ConnectionManager(logger=self.logger)

        self.running = False
        self.proxy_socket: Optional[socket.socket] = None
        self.icmp_socket: Optional[socket.socket] = None

        # Statistics
        self.stats = {
            "connections_handled": 0,
            "packets_sent": 0,
            "packets_received": 0,
            "errors": 0,
        }

        self.logger.debug(
            f"TunnelClient initialized - Server: {server_ip}, Port: {proxy_port}, ICMP ID: {icmp_id}"
        )

    def start(self):
        """Start the tunnel client."""
        try:
            self.logger.info(f"Starting TCP-over-ICMP tunnel client...")
            self.logger.info(f"Server: {self.server_ip}")
            self.logger.info(f"Proxy port: {self.proxy_port}")

            # Start connection manager
            self.logger.debug("Starting connection manager...")
            self.connection_manager.start()

            # Create proxy socket
            self.logger.debug(f"Creating proxy socket on 127.0.0.1:{self.proxy_port}")
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.proxy_socket.bind(("127.0.0.1", self.proxy_port))
            self.proxy_socket.listen(100)
            self.proxy_socket.settimeout(1.0)
            self.logger.debug("Proxy socket created and bound successfully")

            # Create ICMP socket for sending
            self.logger.debug("Creating ICMP socket for sending packets")
            self.icmp_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            self.logger.debug("ICMP socket created successfully")

            # Start response listener thread
            self.running = True
            self.logger.debug("Starting response listener thread...")
            response_thread = threading.Thread(
                target=self._listen_for_responses, daemon=True
            )
            response_thread.start()
            self.logger.debug("Response listener thread started")

            self.logger.info("✓ Tunnel client started successfully")

            # Main proxy loop
            self.logger.debug("Entering main proxy loop...")
            self._proxy_loop()

        except Exception as e:
            self.logger.error(f"✗ Failed to start tunnel client: {e}")
            raise
        finally:
            self.stop()

    def stop(self):
        """Stop the tunnel client."""
        self.logger.debug("Stopping tunnel client...")
        self.running = False

        if self.connection_manager:
            self.logger.debug("Stopping connection manager...")
            self.connection_manager.stop()
            self.connection_manager.cleanup_all()

        if self.proxy_socket:
            try:
                self.logger.debug("Closing proxy socket...")
                self.proxy_socket.close()
            except Exception as e:
                self.logger.debug(f"Error closing proxy socket: {e}")
            self.proxy_socket = None

        if self.icmp_socket:
            try:
                self.logger.debug("Closing ICMP socket...")
                self.icmp_socket.close()
            except Exception as e:
                self.logger.debug(f"Error closing ICMP socket: {e}")
            self.icmp_socket = None

        self.logger.info("✓ Tunnel client stopped")

    def _proxy_loop(self):
        """Main proxy loop that accepts connections."""
        self.logger.debug("Proxy loop started - waiting for connections...")
        while self.running:
            try:
                if self.proxy_socket is None:
                    self.logger.debug("Proxy socket is None, breaking loop")
                    break

                client_socket, client_addr = self.proxy_socket.accept()
                self.logger.debug(f"Accepted connection from: {client_addr}")

                # Handle each connection in a separate thread
                conn_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, client_addr),
                    daemon=True,
                )
                conn_thread.start()
                self.logger.debug(
                    f"Started connection handler thread for {client_addr}"
                )

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error in proxy loop: {e}")
                    self.stats["errors"] += 1

    def _handle_connection(
        self, client_socket: socket.socket, client_addr: Tuple[str, int]
    ):
        """Handle a single client connection."""
        try:
            self.logger.debug(f"Handling connection from {client_addr}")

            # Get the original destination from the socket
            original_dest = self._get_original_destination(client_socket)
            if not original_dest:
                self.logger.warning(
                    f"Could not determine original destination for {client_addr}"
                )
                return

            # Check if this is traffic to our own proxy port (avoid infinite loops)
            if original_dest[1] == self.proxy_port:
                self.logger.warning(
                    f"Received traffic to our own proxy port {self.proxy_port}, ignoring"
                )
                return

            self.logger.info(f"New connection: {client_addr} -> {original_dest}")

            # Add connection to manager
            conn_id = self.connection_manager.add_connection(
                client_addr, original_dest, client_socket
            )
            self.logger.debug(f"Connection added to manager with ID: {conn_id}")

            # Send CONNECT packet to server
            if not self._send_connect_request(conn_id, original_dest):
                self.logger.error(
                    f"Failed to establish tunnel connection for {conn_id}"
                )
                return

            # Handle data transfer
            self.logger.debug(f"Starting data transfer for connection {conn_id}")
            self._handle_data_transfer(conn_id, client_socket)

        except Exception as e:
            self.logger.error(f"Error handling connection {client_addr}: {e}")
            self.stats["errors"] += 1
        finally:
            try:
                client_socket.close()
                self.logger.debug(f"Closed client socket for {client_addr}")
            except Exception as e:
                self.logger.debug(f"Error closing client socket: {e}")

    def _get_original_destination(
        self, sock: socket.socket
    ) -> Optional[Tuple[str, int]]:
        """Get the original destination address from a redirected socket."""
        try:
            # Use SO_ORIGINAL_DST to get the original destination
            # This is the proper way to handle iptables DNAT redirection
            import struct

            # Get the original destination address
            original_dst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)

            # Parse the sockaddr_in structure
            # struct sockaddr_in {
            #     sa_family_t sin_family;     // 2 bytes
            #     in_port_t   sin_port;       // 2 bytes
            #     struct in_addr sin_addr;    // 4 bytes
            #     char        sin_zero[8];    // 8 bytes
            # }
            family, port, addr = struct.unpack("!HHI", original_dst[:8])

            # Convert network byte order to host byte order
            port = socket.ntohs(port)
            addr = socket.inet_ntoa(struct.pack("!I", addr))

            dest = (addr, port)
            self.logger.debug(f"Original destination: {dest}")
            return dest

        except OSError as e:
            if e.errno == 92:  # ENOPROTOOPT - Protocol not available
                self.logger.error(
                    "SO_ORIGINAL_DST not available. Make sure iptables DNAT rules are properly configured."
                )
            elif e.errno == 22:  # EINVAL - Invalid argument
                self.logger.error(
                    "Socket not redirected by iptables DNAT. Check iptables configuration."
                )
            else:
                self.logger.warning(f"Could not get original destination: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error getting original destination: {e}")
            return None

    def _send_connect_request(self, conn_id: str, dest_addr: Tuple[str, int]) -> bool:
        """Send CONNECT request to server."""
        try:
            self.logger.debug(f"Sending CONNECT request for {conn_id} to {dest_addr}")

            # Create destination string
            dest_str = f"{dest_addr[0]}:{dest_addr[1]}"
            self.logger.debug(f"Destination string: {dest_str}")

            # Create CONNECT packet
            packets = self.packet_handler.create_packet(
                PacketType.CONNECT, conn_id, dest_str.encode("utf-8")
            )
            self.logger.debug(f"Created {len(packets)} CONNECT packet(s)")

            # Send packets
            for i, packet_data in enumerate(packets):
                if not self._send_icmp_packet(packet_data):
                    self.logger.error(
                        f"Failed to send CONNECT packet {i+1}/{len(packets)}"
                    )
                    return False
                self.logger.debug(f"Sent CONNECT packet {i+1}/{len(packets)}")

            self.logger.debug(f"CONNECT request sent successfully for {conn_id}")
            return True

        except Exception as e:
            self.logger.error(f"Error sending CONNECT request: {e}")
            return False

    def _send_icmp_packet(self, data: bytes) -> bool:
        """Send ICMP packet to server."""
        try:
            # Create ICMP packet
            icmp_packet = (
                IP(dst=self.server_ip) / ICMP(type=8, id=self.icmp_id) / Raw(load=data)
            )

            self.logger.debug(
                f"Sending ICMP packet to {self.server_ip} - Size: {len(data)}"
            )

            # Send packet
            response = sr1(icmp_packet, timeout=self.retry_timeout, verbose=False)

            if response:
                self.logger.debug("ICMP packet sent successfully, received response")
            else:
                self.logger.debug("ICMP packet sent, no response received")

            return True

        except Exception as e:
            self.logger.error(f"Error sending ICMP packet: {e}")
            return False

    def _handle_data_transfer(self, conn_id: str, client_socket: socket.socket):
        """Handle data transfer between client and tunnel."""
        try:
            self.logger.debug(f"Starting data transfer for connection {conn_id}")

            # Set socket to non-blocking
            client_socket.setblocking(False)
            self.logger.debug("Set client socket to non-blocking mode")

            while self.running:
                # Check if connection still exists
                conn = self.connection_manager.get_connection(conn_id)
                if not conn or conn.state.value == "CLOSED":
                    self.logger.debug(
                        f"Connection {conn_id} is closed, stopping data transfer"
                    )
                    break

                # Read from client socket
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        self.logger.debug(
                            f"No data received from client {conn_id}, closing connection"
                        )
                        break

                    self.logger.debug(
                        f"Received {len(data)} bytes from client {conn_id}"
                    )

                    # Send data through tunnel
                    if not self._send_data_packet(conn_id, data):
                        self.logger.error(f"Failed to send data packet for {conn_id}")
                        break

                except socket.error as e:
                    if e.errno == socket.EAGAIN or e.errno == socket.EWOULDBLOCK:
                        # No data available, continue
                        time.sleep(0.01)
                        continue
                    else:
                        self.logger.debug(f"Socket error for {conn_id}: {e}")
                        break

        except Exception as e:
            self.logger.error(f"Error in data transfer for {conn_id}: {e}")
        finally:
            # Send CLOSE packet
            self.logger.debug(f"Sending CLOSE packet for {conn_id}")
            self._send_close_packet(conn_id)
            self.connection_manager.close_connection(conn_id)

    def _send_data_packet(self, conn_id: str, data: bytes) -> bool:
        """Send data packet through tunnel."""
        try:
            self.logger.debug(f"Sending data packet for {conn_id} - Size: {len(data)}")

            packets = self.packet_handler.create_packet(PacketType.DATA, conn_id, data)
            self.logger.debug(f"Created {len(packets)} data packet(s)")

            for i, packet_data in enumerate(packets):
                if not self._send_icmp_packet(packet_data):
                    self.logger.error(
                        f"Failed to send data packet {i+1}/{len(packets)}"
                    )
                    return False
                self.logger.debug(f"Sent data packet {i+1}/{len(packets)}")

            self.stats["packets_sent"] += len(packets)
            self.logger.debug(
                f"Successfully sent {len(packets)} data packet(s) for {conn_id}"
            )
            return True

        except Exception as e:
            self.logger.error(f"Error sending data packet: {e}")
            return False

    def _send_close_packet(self, conn_id: str):
        """Send CLOSE packet."""
        try:
            self.logger.debug(f"Sending CLOSE packet for {conn_id}")
            packets = self.packet_handler.create_packet(PacketType.CLOSE, conn_id, b"")

            for i, packet_data in enumerate(packets):
                self._send_icmp_packet(packet_data)
                self.logger.debug(f"Sent CLOSE packet {i+1}/{len(packets)}")

        except Exception as e:
            self.logger.error(f"Error sending CLOSE packet: {e}")

    def _listen_for_responses(self):
        """Listen for ICMP responses from server."""
        try:
            self.logger.debug(f"Starting ICMP response listener for {self.server_ip}")

            # Sniff for ICMP Echo Reply packets
            sniff(
                filter=f"icmp and src {self.server_ip} and icmp[0] == 0",
                prn=self._handle_icmp_response,
                store=0,
            )
        except Exception as e:
            self.logger.error(f"Error in response listener: {e}")

    def _handle_icmp_response(self, packet):
        """Handle ICMP response from server."""
        try:
            if not packet.haslayer(Raw):
                self.logger.debug("ICMP packet has no Raw layer, ignoring")
                return

            # Parse tunnel packet
            tunnel_data = packet[Raw].load
            self.logger.debug(f"Received ICMP response - Data size: {len(tunnel_data)}")

            tunnel_packet = self.packet_handler.parse_packet(tunnel_data)

            if not tunnel_packet:
                self.logger.debug("Failed to parse tunnel packet from ICMP response")
                return

            self.stats["packets_received"] += 1
            self.logger.debug(
                f"Parsed tunnel packet - Type: {tunnel_packet.packet_type.name}, Conn: {tunnel_packet.connection_id}"
            )

            # Handle different packet types
            if tunnel_packet.packet_type == PacketType.CONNECT_RESPONSE:
                self._handle_connect_response(tunnel_packet)
            elif tunnel_packet.packet_type == PacketType.DATA:
                self._handle_data_response(tunnel_packet)
            elif tunnel_packet.packet_type == PacketType.CLOSE:
                self._handle_close_response(tunnel_packet)
            elif tunnel_packet.packet_type == PacketType.ACK:
                # Handle acknowledgment
                self.logger.debug(f"Received ACK for sequence {tunnel_packet.sequence}")
                pass

        except Exception as e:
            self.logger.error(f"Error handling ICMP response: {e}")
            self.stats["errors"] += 1

    def _handle_connect_response(self, packet: TunnelPacket):
        """Handle CONNECT response from server."""
        try:
            conn = self.connection_manager.get_connection(packet.connection_id)
            if conn:
                self.logger.info(
                    f"✓ Tunnel connection established: {packet.connection_id}"
                )
                self.stats["connections_handled"] += 1
            else:
                self.logger.warning(
                    f"CONNECT response for unknown connection: {packet.connection_id}"
                )
        except Exception as e:
            self.logger.error(f"Error handling CONNECT response: {e}")

    def _handle_data_response(self, packet: TunnelPacket):
        """Handle DATA response from server."""
        try:
            self.logger.debug(f"Handling DATA response for {packet.connection_id}")

            # Handle fragmented packets
            complete_data = self.packet_handler.handle_fragmented_packet(packet)
            if complete_data is None:
                self.logger.debug(
                    f"Still waiting for fragments for {packet.connection_id}"
                )
                return  # Still waiting for fragments

            self.logger.debug(
                f"Complete data received for {packet.connection_id} - Size: {len(complete_data)}"
            )

            # Send data to client
            conn = self.connection_manager.get_connection(packet.connection_id)
            if conn and conn.client_socket:
                try:
                    conn.client_socket.send(complete_data)
                    self.logger.debug(
                        f"Sent {len(complete_data)} bytes to client for {packet.connection_id}"
                    )
                except Exception as e:
                    self.logger.error(f"Error sending data to client: {e}")
            else:
                self.logger.warning(
                    f"Connection not found or no client socket for {packet.connection_id}"
                )

        except Exception as e:
            self.logger.error(f"Error handling DATA response: {e}")

    def _handle_close_response(self, packet: TunnelPacket):
        """Handle CLOSE response from server."""
        try:
            self.logger.debug(f"Handling CLOSE response for {packet.connection_id}")
            self.connection_manager.close_connection(packet.connection_id)
            self.logger.info(f"✓ Tunnel connection closed: {packet.connection_id}")
        except Exception as e:
            self.logger.error(f"Error handling CLOSE response: {e}")

    def get_stats(self) -> dict:
        """Get tunnel statistics."""
        stats = self.stats.copy()
        stats["active_connections"] = self.connection_manager.get_connection_count()
        self.logger.debug(f"Current stats: {stats}")
        return stats
