import asyncio
import logging
import socket
import threading

from scapy.all import Raw, send, sniff
from scapy.layers.inet import ICMP, IP, TCP

from common import (
    FLAG_ACK,
    FLAG_FIN,
    FLAG_PSH,
    FLAG_RST,
    FLAG_SYN,
    ICMP_ECHO_REPLY_TYPE,
    ICMP_ECHO_REQUEST_TYPE,
    TUNNEL_HEADER_LEN,
    TunnelHeader,
    parse_original_dst,
)

# --- Configuration ---
SERVER_IP = "YOUR_SERVER_IP_HERE"  # Replace with your server's public IP
CLIENT_LISTEN_PORT = 8080  # Port where iptables redirects traffic
LOG_LEVEL = logging.INFO

logging.basicConfig(level=LOG_LEVEL, format="[Client] %(levelname)s: %(message)s")


class ClientTunnel:
    def __init__(self, server_ip, listen_port):
        self.server_ip = server_ip
        self.listen_port = listen_port
        self.loop = asyncio.get_running_loop()

        # Map tunnel ID to local TCP connection handler
        self.tunnel_id_to_handler = {}  # {tunnel_id: LocalTCPConnectionHandler}
        self.next_tunnel_id = 1
        self.tunnel_id_lock = asyncio.Lock()  # For generating unique tunnel IDs

        # Raw socket for sending ICMP (Scapy uses raw sockets internally)
        # No need to explicitly manage raw socket for sending when using scapy.send()

        # Queue for incoming ICMP packets to process in the async loop
        self.icmp_packet_queue = asyncio.Queue()

        logging.info(f"Client tunnel initializing, listening on {listen_port}")
        logging.info(f"Traffic will be tunneled to server: {server_ip}")

    async def get_next_tunnel_id(self):
        async with self.tunnel_id_lock:
            tunnel_id = self.next_tunnel_id
            self.next_tunnel_id += 1
            return tunnel_id

    async def _handle_icmp_packet_from_queue(self):
        """Processes ICMP packets received by the sniff thread."""
        while True:
            raw_pkt_bytes = await self.icmp_packet_queue.get()
            try:
                packet = IP(raw_pkt_bytes)
                if packet.haslayer(ICMP) and packet[ICMP].type == ICMP_ECHO_REPLY_TYPE:
                    if packet.src == self.server_ip and packet.haslayer(Raw):
                        self.handle_incoming_tunneled_icmp(packet)
                    else:
                        logging.debug(f"Ignoring non-tunnel ICMP from {packet.src}")
                else:
                    logging.debug(f"Ignoring non-ICMP or non-reply from {packet.src}")
            except Exception as e:
                logging.error(f"Error parsing incoming ICMP packet: {e}")
            finally:
                self.icmp_packet_queue.task_done()

    def _icmp_sniff_thread(self):
        """Dedicated thread for sniffing ICMP replies, pushing to queue."""
        logging.info("Starting ICMP sniff thread...")
        # Filter for ICMP Echo Replies from our server
        # Using lfilter to process packets as they arrive efficiently
        sniff(
            filter=f"icmp and host {self.server_ip} and icmp[icmptype]=={ICMP_ECHO_REPLY_TYPE}",
            prn=lambda pkt: self.loop.call_soon_threadsafe(
                self.icmp_packet_queue.put_nowait, bytes(pkt)
            ),
            store=0,
        )

    def handle_incoming_tunneled_icmp(self, packet):
        """Decapsulates and processes an ICMP reply containing TCP data."""
        try:
            raw_tunnel_data = packet[Raw].load
            tunnel_header = TunnelHeader.unpack(raw_tunnel_data)
            tunneled_tcp_data = raw_tunnel_data[TUNNEL_HEADER_LEN:]

            tunnel_id = tunnel_header.tunnel_id
            flags = tunnel_header.flags
            seq_offset = (
                tunnel_header.seq_offset
            )  # The *original* seq from client's SYN
            ack_offset = (
                tunnel_header.ack_offset
            )  # The *original* ack from client's SYN_ACK (from server)

            if tunnel_id not in self.tunnel_id_to_handler:
                logging.warning(
                    f"Received ICMP reply for unknown tunnel ID: {tunnel_id}"
                )
                return

            handler = self.tunnel_id_to_handler[tunnel_id]

            # Reconstruct TCP packet based on the data and offsets
            # This is a VERY simplified TCP reconstruction.
            # Real implementation needs to manage seq/ack/window carefully.
            tcp_packet = TCP(tunneled_tcp_data)

            # --- TCP Sequence/ACK Number Translation (Simplified) ---
            # For data coming *back* to the client, the sequence number on this
            # TCP packet (from the remote server via tunnel server) is relative
            # to the server's side. We need to adjust it to match the client's
            # *original* expected sequence. This is the hardest part.
            # For now, we'll just forward the raw TCP data, but real-world requires
            # deep state tracking to fix sequence/ack numbers and window sizes.

            # If it's a SYN-ACK, we need to apply the initial SYN's sequence for the ACK
            if flags & FLAG_SYN and flags & FLAG_ACK:
                logging.debug(
                    f"Handler for tunnel {tunnel_id} received SYN-ACK from server."
                )
                # Apply the original sequence offset for the ACK number
                # The 'tcp_packet.seq' here is the server's initial_seq
                # The 'tcp_packet.ack' here is what the server *acked* of our client's SYN,
                # which should be our client's SYN initial seq + 1.
                # The handler needs to track the original client SYN_SEQ.
                if not handler.initial_syn_ack_received:
                    handler.initial_syn_ack_received = True
                    # Set the client's internal sequence state
                    handler.client_tcp_seq = (
                        tcp_packet.ack
                    )  # The ack from the server is our next seq
                    handler.client_tcp_ack = tcp_packet.seq + len(
                        tcp_packet.payload
                    )  # Server's seq + data length is our next ack

            # Update client's internal TCP state
            handler.client_tcp_seq += len(
                tcp_packet.payload
            )  # Increment our sequence for next data we expect to send
            handler.client_tcp_ack = tcp_packet.seq + len(
                tcp_packet.payload
            )  # Client needs to ACK the server's sequence + payload length

            # Send data to local application
            self.loop.create_task(handler.send_to_local_app(tunneled_tcp_data))

            if flags & FLAG_FIN or flags & FLAG_RST:
                logging.info(f"Tunnel {tunnel_id}: FIN/RST received. Closing tunnel.")
                self.loop.create_task(handler.close())  # Schedule close
                del self.tunnel_id_to_handler[tunnel_id]

        except Exception as e:
            logging.exception("Error handling incoming tunneled ICMP")
            # logging.error(
            #     f"Error handling incoming tunneled ICMP for tunnel ID {tunnel_id}: {e}",
            #     exc_info=True,
            # )

    async def handle_local_tcp_connection(self, reader, writer):
        """Manages a single local TCP connection from an application."""
        sock = writer.get_extra_info("socket")
        try:
            original_dst_ip, original_dst_port = parse_original_dst(sock)
            logging.info(
                f"Accepted local connection. Redirected from {original_dst_ip}:{original_dst_port}"
            )

            tunnel_id = await self.get_next_tunnel_id()
            logging.info(
                f"Assigned tunnel ID: {tunnel_id} for {original_dst_ip}:{original_dst_port}"
            )

            handler = LocalTCPConnectionHandler(
                reader,
                writer,
                original_dst_ip,
                original_dst_port,
                tunnel_id,
                self.server_ip,
                self.loop,
            )
            self.tunnel_id_to_handler[tunnel_id] = handler

            # Start reading from the local application
            await handler.run()

        except Exception as e:
            logging.error(f"Error setting up local TCP handler: {e}")
            writer.close()

    async def start(self):
        """Starts the client listener and ICMP sniffer."""
        # Start the ICMP sniff thread
        sniff_thread = threading.Thread(target=self._icmp_sniff_thread, daemon=True)
        sniff_thread.start()

        # Start the ICMP packet processor in the event loop
        self.loop.create_task(self._handle_icmp_packet_from_queue())

        # Start the local TCP server
        server = await asyncio.start_server(
            self.handle_local_tcp_connection, "127.0.0.1", self.listen_port
        )
        logging.info(
            f"Client listening for redirected TCP on 127.0.0.1:{self.listen_port}"
        )

        async with server:
            await server.serve_forever()


class LocalTCPConnectionHandler:
    def __init__(
        self,
        reader,
        writer,
        original_dst_ip,
        original_dst_port,
        tunnel_id,
        server_ip,
        loop,
    ):
        self.reader = reader
        self.writer = writer
        self.original_dst_ip = original_dst_ip
        self.original_dst_port = original_dst_port
        self.tunnel_id = tunnel_id
        self.server_ip = server_ip
        self.loop = loop
        self.closed = False

        # --- TCP Sequence Tracking (Simplified) ---
        # This is a bare minimum. A real implementation needs much more.
        # This will hold the client's *perceived* TCP sequence and ack numbers
        # to correctly respond to the application.
        # It's an *offset* from the actual client's SYN sequence number.
        self.client_initial_syn_seq = 0  # Captured from client's SYN
        self.client_tcp_seq = 0  # Next sequence number for client's outgoing data
        self.client_tcp_ack = 0  # Next acknowledgment number for client's outgoing data
        self.initial_syn_ack_received = (
            False  # Flag to indicate if server has sent SYN-ACK back
        )

    async def run(self):
        """Reads from local application and sends over tunnel."""
        try:
            while not self.closed:
                data = await self.reader.read(4096)
                if not data:
                    logging.info(
                        f"Tunnel {self.tunnel_id}: Local application closed connection."
                    )
                    break  # Connection closed by client application

                # Extract TCP flags from the data (this is highly simplified)
                # In a real scenario, you'd parse the actual TCP packet the application sends
                # and extract its sequence/ack/flags. For a raw proxy, we just see data.
                # If we're redirecting, the kernel *handles* the TCP handshake with our proxy.
                # So the first data we get is likely PSH/ACK.
                current_flags = FLAG_PSH | FLAG_ACK
                if not self.client_tcp_seq:  # First data likely from SYN
                    current_flags |= (
                        FLAG_SYN  # Mark initial data with SYN for server to initiate
                    )

                # --- TCP Sequence Numbering (Client's Outgoing) ---
                # The local client's socket is managing its own TCP sequence with *our* proxy.
                # We need to create a *synthetic* TCP packet that *appears* to come from the client
                # for the remote server.
                # For this minimal version, we will just pass a raw payload and let the server handle
                # sequence number incrementing with its target. This will break for complex TCP.
                # A proper solution would require modifying the actual TCP header of the packet
                # that the local application *would* have sent if not for the redirect.
                # For simplicity, we just use dummy values and rely on the server to establish
                # its own flow with the target.

                # Simulate a TCP packet structure that the server will understand
                # This is a dummy TCP header that only conveys original destination.
                # Server needs to rebuild this.
                # Actual data should be based on the local app's stream.
                # For a full transparent tunnel, you'd parse the actual TCP segments.
                # Here, we're just forwarding the *payload* of the local connection.

                # Create a placeholder TCP header that contains enough info for the server.
                # Server will use this to build its own TCP connection.
                # For this minimal version, we are NOT passing the client's actual TCP header,
                # just the raw data stream. The server needs to *re-synthesize* TCP segments.
                # This is where the challenge lies.

                # --- The correct approach for proxying data streams ---
                # When using `REDIRECT` and acting as a TCP proxy, your client receives
                # a *stream* of bytes over its accepted socket. It does NOT see raw
                # TCP packets with their headers and flags.
                # Therefore, we need to *synthesize* TCP packets for the tunnel server.
                # This makes the sequence tracking even more critical.

                # For the minimal POC: We'll assume the server infers TCP flags from context (e.g., first packet is SYN)
                # and manages its own sequence numbers for the remote target.
                # This *will not* be fully transparent for complex TCP.

                # For our minimal solution, the initial SYN needs to carry the original destination.
                # Subsequent packets are just data.

                # First, ensure the tunnel connection is established. This will happen on the first data.
                # If it's the very first data sent on this tunnel ID, mark it as SYN and carry original destination.
                # We'll use the current flags and a pseudo-TCP header for the server.

                # Create a dummy TCP header to encapsulate for the server, reflecting state
                # In a real scenario, you'd parse the *incoming* TCP packet from the app
                # if you were NFQUEUE'ing. Since we're a proxy, we're building a new one.

                # This means we *must* manage sequence/ack numbers ourselves for the 'virtual' TCP flow
                # between client and server over ICMP.

                # Let's simplify the initial SYN/ACK exchange for the tunnel's virtual TCP.
                # Client sends SYN-like ICMP
                # Server sends SYN-ACK-like ICMP

                # This is the client's state for the *tunneled* TCP flow.
                # Initialize these on the first packet.
                if self.client_tcp_seq == 0 and not self.initial_syn_ack_received:
                    # This is the "virtual" SYN being sent over the tunnel.
                    current_flags = FLAG_SYN
                    self.client_initial_syn_seq = (
                        1000  # Dummy initial seq for our tunnel's TCP
                    )
                    self.client_tcp_seq = (
                        self.client_initial_syn_seq + 1
                    )  # Next seq after SYN
                    # TCP payload for the tunnel is the data from the app.
                    # We send a "fake" TCP SYN header to the server for the tunnel handshake.
                    # The actual application data goes *after* this virtual TCP header.

                    # Synthesize a TCP packet for the server, conveying the original destination.
                    # This is not a real TCP packet from the client app.
                    syn_tcp_pkt = TCP(
                        sport=self.writer.get_extra_info("sockname")[
                            1
                        ],  # Client's local port
                        dport=self.original_dst_port,
                        flags="S",  # Synthesized SYN for server
                        seq=self.client_initial_syn_seq,  # Use our dummy initial seq
                        ack=0,
                        window=65535,  # Large window
                    ) / Raw(
                        load=data
                    )  # Encapsulate the actual app data as payload for first packet

                    tunneled_tcp_bytes = bytes(syn_tcp_pkt)

                else:
                    # Subsequent data packets, assume PSH/ACK
                    current_flags = FLAG_PSH | FLAG_ACK

                    # Create a dummy TCP header for data. The server will use its own sequence.
                    # We just need to give it context.
                    data_tcp_pkt = TCP(
                        sport=self.writer.get_extra_info("sockname")[1],
                        dport=self.original_dst_port,
                        flags="PA",  # PSH/ACK
                        seq=self.client_tcp_seq,
                        ack=self.client_tcp_ack,  # Use the ACK we got from server's SYN-ACK
                        window=65535,
                    ) / Raw(load=data)

                    tunneled_tcp_bytes = bytes(data_tcp_pkt)
                    self.client_tcp_seq += len(
                        data
                    )  # Update our virtual sequence for next outgoing data

                tunnel_header = TunnelHeader(
                    flags=current_flags,
                    tunnel_id=self.tunnel_id,
                    seq_offset=self.client_tcp_seq,  # Pass our current seq for server's reference
                    ack_offset=self.client_tcp_ack,  # Pass our current ack
                    tcp_len=len(tunneled_tcp_bytes),
                )

                icmp_payload = tunnel_header.pack() + tunneled_tcp_bytes

                # Construct ICMP Echo Request
                icmp_packet = (
                    IP(dst=self.server_ip)
                    / ICMP(
                        type=ICMP_ECHO_REQUEST_TYPE,
                        code=0,
                        id=self.tunnel_id,
                        seq=self.tunnel_id,
                    )
                    / Raw(load=icmp_payload)
                )

                logging.debug(
                    f"Tunnel {self.tunnel_id}: Sending {len(data)} bytes to server via ICMP."
                )
                send(icmp_packet, verbose=0)  # Send directly to server

        except Exception as e:
            logging.error(
                f"Tunnel {self.tunnel_id}: Error reading from local application: {e}",
                exc_info=True,
            )
        finally:
            await self.close()

    async def send_to_local_app(self, data):
        """Sends decapsulated TCP data back to the local application."""
        if not self.closed:
            try:
                # The data here is the raw TCP segment from the server's reply.
                # We need to send it back to the local app's TCP connection.
                # Since we are a proxy, we write it directly to the socket.
                self.writer.write(data)
                await self.writer.drain()
                logging.debug(
                    f"Tunnel {self.tunnel_id}: Sent {len(data)} bytes to local app."
                )
            except Exception as e:
                logging.error(
                    f"Tunnel {self.tunnel_id}: Error writing to local app: {e}",
                    exc_info=True,
                )
                await self.close()

    async def close(self):
        """Closes the local TCP connection and cleans up."""
        if not self.closed:
            self.closed = True
            logging.info(f"Tunnel {self.tunnel_id}: Closing local connection.")
            self.writer.close()
            # Remove from global mapping
            if self.tunnel_id in client_instance.tunnel_id_to_handler:
                del client_instance.tunnel_id_to_handler[self.tunnel_id]


async def main():
    global client_instance
    client_instance = ClientTunnel(SERVER_IP, CLIENT_LISTEN_PORT)
    await client_instance.start()


if __name__ == "__main__":
    # Ensure this runs as root for raw sockets/iptables
    # A simple check:
    if not threading.current_thread().name == "MainThread" or not hasattr(
        socket, "AF_PACKET"
    ):
        logging.warning(
            "Consider running this script as root for raw socket access and iptables rules."
        )

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Client shutting down.")
    except Exception as e:
        logging.critical(f"Unhandled exception in main: {e}", exc_info=True)
