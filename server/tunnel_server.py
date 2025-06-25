import logging
import socket
import struct
import threading
import time
from typing import Dict, Optional, Tuple

from scapy.all import Raw, sniff, sr1
from scapy.layers.inet import ICMP, IP

from shared import ConnectionManager, PacketHandler, PacketType, TunnelPacket


class TunnelServer:
    """Server-side tunnel that receives ICMP packets and forwards TCP connections."""

    def __init__(
        self,
        listen_ip: str = "0.0.0.0",
        icmp_id: int = 12345,
        logger: Optional[logging.Logger] = None,
    ):
        self.listen_ip = listen_ip
        self.icmp_id = icmp_id
        self.logger = logger or logging.getLogger(__name__)

        self.packet_handler = PacketHandler(logger=self.logger)
        self.connection_manager = ConnectionManager(logger=self.logger)

        self.running = False

        # Statistics
        self.stats = {
            "connections_handled": 0,
            "packets_received": 0,
            "packets_sent": 0,
            "errors": 0,
        }

        self.logger.debug(
            f"TunnelServer initialized - Listen IP: {listen_ip}, ICMP ID: {icmp_id}"
        )

    def start(self):
        """Start the tunnel server."""
        try:
            self.logger.info(f"Starting TCP-over-ICMP tunnel server...")
            self.logger.info(f"Listening on: {self.listen_ip}")
            self.logger.info(f"ICMP ID: {self.icmp_id}")

            # Start connection manager
            self.logger.debug("Starting connection manager...")
            self.connection_manager.start()

            # Start ICMP listener
            self.running = True
            self.logger.debug("Tunnel server started successfully")
            self.logger.info("Waiting for ICMP packets...")

            # Start ICMP packet listener
            self.logger.debug("Starting ICMP packet listener...")
            self._listen_for_icmp()

        except Exception as e:
            self.logger.error(f"Failed to start tunnel server: {e}")
            raise
        finally:
            self.stop()

    def stop(self):
        """Stop the tunnel server."""
        self.logger.debug("Stopping tunnel server...")
        self.running = False

        if self.connection_manager:
            self.logger.debug("Stopping connection manager...")
            self.connection_manager.stop()
            self.connection_manager.cleanup_all()

        self.logger.info("Tunnel server stopped")

    def _listen_for_icmp(self):
        """Listen for ICMP Echo Request packets."""
        try:
            self.logger.debug(f"Starting ICMP listener on {self.listen_ip}")

            # Sniff for ICMP Echo Request packets with specific filtering
            # Only capture packets to our server with our ICMP ID
            filter_str = f"icmp and dst {self.listen_ip} and icmp[0] == 8 and icmp[4:2] == {self.icmp_id}"
            self.logger.debug(f"Using ICMP filter: {filter_str}")

            sniff(
                filter=filter_str,
                prn=self._handle_icmp_request,
                store=0,
            )
        except Exception as e:
            self.logger.error(f"Error in ICMP listener: {e}")

    def _handle_icmp_request(self, packet):
        """Handle ICMP Echo Request packet."""
        try:
            # Validate packet structure
            if not packet.haslayer(IP):
                self.logger.debug("Packet has no IP layer, ignoring")
                return

            if not packet.haslayer(ICMP):
                self.logger.debug("Packet has no ICMP layer, ignoring")
                return

            if not packet.haslayer(Raw):
                self.logger.debug("ICMP packet has no Raw layer, ignoring")
                return

            # Validate ICMP type (should be Echo Request = 8)
            if packet[ICMP].type != 8:
                self.logger.debug(
                    f"ICMP packet type {packet[ICMP].type} is not Echo Request, ignoring"
                )
                return

            # Validate ICMP ID matches our tunnel
            if packet[ICMP].id != self.icmp_id:
                self.logger.debug(
                    f"ICMP ID {packet[ICMP].id} doesn't match tunnel ID {self.icmp_id}, ignoring"
                )
                return

            # Get source IP
            src_ip = packet[IP].src
            self.logger.debug(f"Received ICMP request from {src_ip}")

            # Parse tunnel packet
            tunnel_data = packet[Raw].load
            self.logger.debug(f"ICMP request data size: {len(tunnel_data)}")

            # Validate minimum packet size before parsing
            if len(tunnel_data) < self.packet_handler.MIN_PACKET_SIZE:
                self.logger.debug(
                    f"Tunnel data too small: {len(tunnel_data)} bytes, ignoring"
                )
                return

            tunnel_packet = self.packet_handler.parse_packet(tunnel_data)

            if not tunnel_packet:
                self.logger.debug("Failed to parse tunnel packet from ICMP request")
                return

            self.stats["packets_received"] += 1
            self.logger.debug(
                f"Parsed tunnel packet - Type: {tunnel_packet.packet_type.name}, Conn: {tunnel_packet.connection_id}"
            )

            # Handle different packet types
            if tunnel_packet.packet_type == PacketType.CONNECT:
                self._handle_connect_request(src_ip, tunnel_packet)
            elif tunnel_packet.packet_type == PacketType.DATA:
                self._handle_data_request(src_ip, tunnel_packet)
            elif tunnel_packet.packet_type == PacketType.CLOSE:
                self._handle_close_request(src_ip, tunnel_packet)
            elif tunnel_packet.packet_type == PacketType.ACK:
                # Handle acknowledgment
                self.logger.debug(f"Received ACK for sequence {tunnel_packet.sequence}")
                pass

        except Exception as e:
            self.logger.error(f"Error handling ICMP request: {e}")
            self.stats["errors"] += 1

    def _handle_connect_request(self, src_ip: str, packet: TunnelPacket):
        """Handle CONNECT request from client."""
        try:
            self.logger.debug(
                f"Handling CONNECT request from {src_ip} for {packet.connection_id}"
            )

            # Parse destination address
            dest_str = packet.data.decode("utf-8")
            dest_ip, dest_port = self._parse_destination(dest_str)
            self.logger.debug(f"Parsed destination: {dest_ip}:{dest_port}")

            self.logger.info(f"CONNECT request: {src_ip} -> {dest_ip}:{dest_port}")

            # Create TCP connection to destination
            self.logger.debug(f"Creating TCP connection to {dest_ip}:{dest_port}")
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10.0)

            try:
                server_socket.connect((dest_ip, dest_port))
                self.logger.info(f"Connected to {dest_ip}:{dest_port}")

                # Add connection to manager with a dummy client socket
                # (we don't have the actual client socket on server side)
                dummy_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn_id = self.connection_manager.add_connection(
                    (src_ip, 0), (dest_ip, dest_port), dummy_client_socket
                )
                self.logger.debug(f"Connection added to manager with ID: {conn_id}")

                # Update with the real server socket
                self.connection_manager.update_connection_socket(conn_id, server_socket)
                self.logger.debug(f"Updated connection {conn_id} with server socket")

                # Start data transfer thread
                self.logger.debug(f"Starting data transfer thread for {conn_id}")
                transfer_thread = threading.Thread(
                    target=self._handle_server_data_transfer,
                    args=(conn_id, server_socket, src_ip),
                    daemon=True,
                )
                transfer_thread.start()

                # Send CONNECT response
                self.logger.debug(f"Sending CONNECT response to {src_ip}")
                self._send_connect_response(src_ip, conn_id)

                self.stats["connections_handled"] += 1
                self.logger.debug(f"CONNECT request handled successfully for {conn_id}")

            except Exception as e:
                self.logger.error(f"Failed to connect to {dest_ip}:{dest_port}: {e}")
                server_socket.close()
                self.logger.debug(f"Sending CONNECT error to {src_ip}")
                self._send_connect_error(src_ip, packet.connection_id)

        except Exception as e:
            self.logger.error(f"Error handling CONNECT request: {e}")
            self.stats["errors"] += 1

    def _handle_data_request(self, src_ip: str, packet: TunnelPacket):
        """Handle DATA request from client."""
        try:
            self.logger.debug(
                f"Handling DATA request from {src_ip} for {packet.connection_id}"
            )

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

            # Get connection from manager
            conn = self.connection_manager.get_connection(packet.connection_id)
            if conn and conn.server_socket:
                # Send data to destination server
                try:
                    conn.server_socket.send(complete_data)
                    self.logger.debug(
                        f"Sent {len(complete_data)} bytes to server for {packet.connection_id}"
                    )
                except Exception as e:
                    self.logger.error(f"Error sending data to server: {e}")
                    self.connection_manager.close_connection(packet.connection_id)
            else:
                self.logger.warning(f"Connection not found: {packet.connection_id}")

        except Exception as e:
            self.logger.error(f"Error handling DATA request: {e}")
            self.stats["errors"] += 1

    def _handle_close_request(self, src_ip: str, packet: TunnelPacket):
        """Handle CLOSE request from client."""
        try:
            self.logger.debug(
                f"Handling CLOSE request from {src_ip} for {packet.connection_id}"
            )
            self.connection_manager.close_connection(packet.connection_id)
            self.logger.info(f"Connection closed: {packet.connection_id}")
        except Exception as e:
            self.logger.error(f"Error handling CLOSE request: {e}")

    def _handle_server_data_transfer(
        self, conn_id: str, server_socket: socket.socket, client_ip: str
    ):
        """Handle data transfer from server back to client."""
        try:
            self.logger.debug(f"Starting server data transfer for {conn_id}")

            # Set socket to non-blocking
            server_socket.setblocking(False)
            self.logger.debug("Set server socket to non-blocking mode")

            while self.running:
                # Check if connection still exists
                conn = self.connection_manager.get_connection(conn_id)
                if not conn or conn.state.value == "CLOSED":
                    self.logger.debug(
                        f"Connection {conn_id} is closed, stopping data transfer"
                    )
                    break

                # Read from server socket
                try:
                    data = server_socket.recv(4096)
                    if not data:
                        self.logger.debug(
                            f"No data received from server {conn_id}, closing connection"
                        )
                        break

                    self.logger.debug(
                        f"Received {len(data)} bytes from server {conn_id}"
                    )

                    # Send data back to client
                    if not self._send_data_response(client_ip, conn_id, data):
                        self.logger.error(f"Failed to send data response for {conn_id}")
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
            self.logger.error(f"Error in server data transfer for {conn_id}: {e}")
        finally:
            # Send CLOSE packet to client
            self.logger.debug(f"Sending CLOSE packet to client for {conn_id}")
            self._send_close_response(client_ip, conn_id)
            self.connection_manager.close_connection(conn_id)

    def _parse_destination(self, dest_str: str) -> Tuple[str, int]:
        """Parse destination string into IP and port."""
        try:
            self.logger.debug(f"Parsing destination string: {dest_str}")
            if ":" in dest_str:
                ip, port_str = dest_str.split(":", 1)
                port = int(port_str)
            else:
                ip = dest_str
                port = 80  # Default port

            self.logger.debug(f"Parsed destination: {ip}:{port}")
            return ip, port
        except Exception as e:
            self.logger.error(f"Error parsing destination '{dest_str}': {e}")
            raise

    def _send_icmp_response(self, dst_ip: str, data: bytes) -> bool:
        """Send ICMP Echo Reply packet."""
        try:
            self.logger.debug(f"Sending ICMP response to {dst_ip} - Size: {len(data)}")

            # Create ICMP packet
            icmp_packet = (
                IP(dst=dst_ip) / ICMP(type=0, id=self.icmp_id) / Raw(load=data)
            )

            # Send packet
            response = sr1(icmp_packet, timeout=1, verbose=False)

            if response:
                self.logger.debug("ICMP response sent successfully")
            else:
                self.logger.debug("ICMP response sent, no confirmation received")

            self.stats["packets_sent"] += 1
            return True

        except Exception as e:
            self.logger.error(f"Error sending ICMP response: {e}")
            return False

    def _send_connect_response(self, dst_ip: str, conn_id: str):
        """Send CONNECT response to client."""
        try:
            self.logger.debug(f"Sending CONNECT response to {dst_ip} for {conn_id}")
            packets = self.packet_handler.create_packet(
                PacketType.CONNECT_RESPONSE, conn_id, b""
            )

            for i, packet_data in enumerate(packets):
                self._send_icmp_response(dst_ip, packet_data)
                self.logger.debug(f"Sent CONNECT response packet {i+1}/{len(packets)}")

        except Exception as e:
            self.logger.error(f"Error sending CONNECT response: {e}")

    def _send_connect_error(self, dst_ip: str, conn_id: str):
        """Send CONNECT error response to client."""
        try:
            self.logger.debug(f"Sending CONNECT error to {dst_ip} for {conn_id}")
            error_data = b"CONNECTION_FAILED"
            packets = self.packet_handler.create_packet(
                PacketType.CONNECT_RESPONSE, conn_id, error_data
            )

            for i, packet_data in enumerate(packets):
                self._send_icmp_response(dst_ip, packet_data)
                self.logger.debug(f"Sent CONNECT error packet {i+1}/{len(packets)}")

        except Exception as e:
            self.logger.error(f"Error sending CONNECT error: {e}")

    def _send_data_response(self, dst_ip: str, conn_id: str, data: bytes):
        """Send DATA response to client."""
        try:
            self.logger.debug(
                f"Sending DATA response to {dst_ip} for {conn_id} - Size: {len(data)}"
            )
            packets = self.packet_handler.create_packet(PacketType.DATA, conn_id, data)

            for i, packet_data in enumerate(packets):
                self._send_icmp_response(dst_ip, packet_data)
                self.logger.debug(f"Sent DATA response packet {i+1}/{len(packets)}")

        except Exception as e:
            self.logger.error(f"Error sending DATA response: {e}")

    def _send_close_response(self, dst_ip: str, conn_id: str):
        """Send CLOSE response to client."""
        try:
            self.logger.debug(f"Sending CLOSE response to {dst_ip} for {conn_id}")
            packets = self.packet_handler.create_packet(PacketType.CLOSE, conn_id, b"")

            for i, packet_data in enumerate(packets):
                self._send_icmp_response(dst_ip, packet_data)
                self.logger.debug(f"Sent CLOSE response packet {i+1}/{len(packets)}")

        except Exception as e:
            self.logger.error(f"Error sending CLOSE response: {e}")

    def get_stats(self) -> dict:
        """Get tunnel statistics."""
        stats = self.stats.copy()
        stats["active_connections"] = self.connection_manager.get_connection_count()
        self.logger.debug(f"Current stats: {stats}")
        return stats
