#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import sys
import threading

from icmp_tunnel import ICMPTunnel
from reliability import ReliableConnection

SO_ORIGINAL_DST = 80


class TunnelClient:
    def __init__(self, server_ip: str, local_port: int = 8080):
        self.server_ip = server_ip
        self.local_port = local_port
        self.tunnel = ICMPTunnel(is_server=False)
        self.connections: dict = {}
        self.running = False

        # Create transparent proxy socket
        self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Enable transparent proxy (requires root)
        try:
            self.proxy_socket.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT
        except OSError:
            print(
                "Warning: Could not enable transparent proxy. Run as root for full transparency."
            )

    def start(self):
        """Start the tunnel client"""
        if os.geteuid() != 0:
            print(
                "Warning: Running without root privileges. Some features may not work."
            )

        self.running = True
        self.tunnel.start()

        # Bind to local port
        self.proxy_socket.bind(("0.0.0.0", self.local_port))
        self.proxy_socket.listen(10)

        print(f"Tunnel client started on port {self.local_port}")
        print(f"Server: {self.server_ip}")
        print("Configure iptables to redirect traffic:")
        print(
            f"iptables -t nat -A OUTPUT -p tcp --dport 80,443 -j REDIRECT --to-port {self.local_port}"
        )

        # Start accepting connections
        while self.running:
            try:
                client_sock, addr = self.proxy_socket.accept()
                thread = threading.Thread(
                    target=self._handle_client, args=(client_sock,)
                )
                thread.daemon = True
                thread.start()
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")

    def _handle_client(self, client_sock: socket.socket):
        """Handle individual client connection"""
        # Get original destination using SO_ORIGINAL_DST
        dst_ip, dst_port = self._get_original_destination(client_sock)

        print(f"New connection: {client_sock.getpeername()} -> {dst_ip}:{dst_port}")

        # Create reliable connection through tunnel
        conn_id = f"{dst_ip}:{dst_port}"
        try:
            reliable_conn = ReliableConnection(
                self.tunnel, self.server_ip, self.local_port, dst_port
            )
            reliable_conn.start()
            self.connections[conn_id] = reliable_conn

            # Start forwarding data
            self._forward_data(client_sock, reliable_conn, dst_ip, dst_port)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_sock.close()
            if conn_id in self.connections:
                self.connections[conn_id].stop()
                del self.connections[conn_id]

    def _get_original_destination(self, sock: socket.socket) -> tuple:
        """Get original destination using SO_ORIGINAL_DST"""
        try:
            port, ip_bytes = struct.unpack(
                "!2xH4s8x", sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            )
            ip = socket.inet_ntoa(ip_bytes)

            return ip, port
        except:
            # Fallback - this won't work for transparent proxy but useful for testing
            return "8.8.8.8", 80

    def _forward_data(
        self,
        client_sock: socket.socket,
        reliable_conn: ReliableConnection,
        dst_ip: str,
        dst_port: int,
    ):
        """Forward data between client and tunnel"""

        def client_to_tunnel():
            while self.running:
                try:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    reliable_conn.send_data(data, dst_ip, dst_port)
                except Exception as e:
                    print(f"Client to tunnel error: {e}")
                    break

        def tunnel_to_client():
            while self.running:
                try:
                    data = reliable_conn.recv_data(timeout=1.0)
                    if data:
                        client_sock.send(data)
                except Exception as e:
                    print(f"Tunnel to client error: {e}")
                    break

        # Start forwarding threads
        t1 = threading.Thread(target=client_to_tunnel)
        t2 = threading.Thread(target=tunnel_to_client)
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()

        # Wait for threads to finish
        t1.join()
        t2.join()

    def stop(self):
        """Stop the tunnel client"""
        self.running = False
        self.tunnel.stop()
        self.proxy_socket.close()

        for conn in self.connections.values():
            conn.stop()


def main():
    parser = argparse.ArgumentParser(description="TCP over ICMP Tunnel Client")
    parser.add_argument("server_ip", help="Server IP address")
    parser.add_argument("--port", type=int, default=8080, help="Local proxy port")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print(
            "This program requires root privileges for raw sockets and transparent proxy."
        )
        sys.exit(1)

    client = TunnelClient(args.server_ip, args.port)

    try:
        client.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        client.stop()


if __name__ == "__main__":
    main()
