#!/usr/bin/env python3
import argparse
import os
import socket
import sys
import threading

from icmp_tunnel import ICMPTunnel, TunnelPacket
from reliability import ReliableConnection


class TunnelServer:
    def __init__(self):
        self.tunnel = ICMPTunnel(is_server=True)
        self.connections: dict = {}
        self.running = False

    def start(self):
        """Start the tunnel server"""
        if os.geteuid() != 0:
            print("This program requires root privileges for raw sockets.")
            sys.exit(1)

        self.running = True
        self.tunnel.start()

        print("Tunnel server started")
        print("Waiting for client connections...")

        # Main receive loop
        while self.running:
            try:
                result = self.tunnel.receive_packet(timeout=1.0)
                if not result:
                    continue

                packet, client_ip = result

                # Handle new connections or existing ones
                conn_id = (
                    f"{client_ip}:{packet.src_port}:{packet.dst_ip}:{packet.dst_port}"
                )

                if conn_id not in self.connections:
                    print(
                        f"New tunnel connection: {client_ip} -> {packet.dst_ip}:{packet.dst_port}"
                    )
                    self._create_connection(conn_id, client_ip, packet)

                # Forward packet to connection handler
                if conn_id in self.connections:
                    self.connections[conn_id]["queue"].put((packet, client_ip))

            except Exception as e:
                if self.running:
                    print(f"Server receive error: {e}")

    def _create_connection(
        self, conn_id: str, client_ip: str, initial_packet: TunnelPacket
    ):
        """Create a new connection handler"""
        try:
            # Create connection to target
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.connect((initial_packet.dst_ip, initial_packet.dst_port))

            # Create reliable connection
            reliable_conn = ReliableConnection(
                self.tunnel, client_ip, initial_packet.dst_port, initial_packet.src_port
            )
            reliable_conn.start()

            # Store connection info
            import queue

            self.connections[conn_id] = {
                "target_sock": target_sock,
                "reliable_conn": reliable_conn,
                "queue": queue.Queue(),
                "client_ip": client_ip,
            }

            # Start connection handler thread
            thread = threading.Thread(target=self._handle_connection, args=(conn_id,))
            thread.daemon = True
            thread.start()

        except Exception as e:
            print(f"Error creating connection {conn_id}: {e}")

    def _handle_connection(self, conn_id: str):
        """Handle individual tunnel connection"""
        conn_info = self.connections[conn_id]
        target_sock = conn_info["target_sock"]
        reliable_conn = conn_info["reliable_conn"]
        packet_queue = conn_info["queue"]
        client_ip = conn_info["client_ip"]

        def tunnel_to_target():
            """Forward data from tunnel to target"""
            while self.running and conn_id in self.connections:
                try:
                    # Get packet from tunnel
                    packet, _ = packet_queue.get(timeout=1.0)

                    if packet.flags & TunnelPacket.FLAG_DATA and packet.data:
                        # Forward to target
                        target_sock.send(packet.data)

                        # Send ACK back through tunnel
                        ack_packet = TunnelPacket(
                            seq=1000,  # Server seq
                            ack=packet.seq,
                            flags=TunnelPacket.FLAG_ACK,
                            window=10,
                            src_ip=packet.dst_ip,
                            src_port=packet.dst_port,
                            dst_ip=packet.src_ip,
                            dst_port=packet.src_port,
                            data=b"",
                        )
                        self.tunnel.send_packet(ack_packet, client_ip)

                except Exception as e:
                    if self.running:
                        print(f"Tunnel to target error: {e}")
                    break

        def target_to_tunnel():
            """Forward data from target to tunnel"""
            while self.running and conn_id in self.connections:
                try:
                    data = target_sock.recv(4096)
                    if not data:
                        break

                    # Send data back through tunnel
                    response_packet = TunnelPacket(
                        seq=1000,  # Server seq
                        ack=0,
                        flags=TunnelPacket.FLAG_DATA,
                        window=10,
                        src_ip=target_sock.getpeername()[0],
                        src_port=target_sock.getpeername()[1],
                        dst_ip=client_ip,
                        dst_port=reliable_conn.local_port,
                        data=data,
                    )
                    self.tunnel.send_packet(response_packet, client_ip)

                except Exception as e:
                    if self.running:
                        print(f"Target to tunnel error: {e}")
                    break

        # Start forwarding threads
        t1 = threading.Thread(target=tunnel_to_target)
        t2 = threading.Thread(target=target_to_tunnel)
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()

        # Wait for threads to finish
        t1.join()
        t2.join()

        # Cleanup
        try:
            target_sock.close()
            reliable_conn.stop()
            if conn_id in self.connections:
                del self.connections[conn_id]
            print(f"Connection {conn_id} closed")
        except Exception as e:
            print(f"Cleanup error: {e}")

    def stop(self):
        """Stop the tunnel server"""
        self.running = False
        self.tunnel.stop()

        for conn_info in self.connections.values():
            try:
                conn_info["target_sock"].close()
                conn_info["reliable_conn"].stop()
            except:
                pass


def main():
    parser = argparse.ArgumentParser(description="TCP over ICMP Tunnel Server")
    args = parser.parse_args()

    server = TunnelServer()

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    main()
