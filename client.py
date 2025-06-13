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
                    break

                current_flags = FLAG_PSH | FLAG_ACK
                # Simplified SYN/ACK handling for the tunnel's virtual TCP flow
                if self.client_tcp_seq == 0 and not self.initial_syn_ack_received:
                    current_flags = (
                        FLAG_SYN  # Mark initial data with SYN for server to initiate
                    )
                    self.client_initial_syn_seq = (
                        1000  # Dummy initial seq for our tunnel's TCP
                    )
                    self.client_tcp_seq = self.client_initial_syn_seq + 1

                # --- The tunneled TCP packet for the server ---
                # This needs to carry enough info for the server to establish its connection.
                # The data is the actual payload from the local application.
                # The server will re-synthesize its own TCP header.
                # Here, we just send the raw data.

                # IMPORTANT: For minimal, we're not sending a "full" TCP header *from the client*
                # as part of the tunneled_tcp_bytes. We're just sending the application's
                # payload data. The server will re-create a TCP header for its outbound connection.

                # For basic HTTP, often the first few bytes are enough to kick off the connection.
                # If you need to tunnel *raw TCP segments* including their headers, then
                # `data` should be a `bytes` object that is a full TCP segment you construct,
                # and you extract its `seq`/`ack`/`flags` to put into TunnelHeader.

                # For current "minimal" design, `tunneled_tcp_bytes` is the application's raw data.
                tunneled_tcp_bytes = data

                tunnel_header = TunnelHeader(
                    flags=current_flags,
                    tunnel_id=self.tunnel_id,
                    original_dst_ip=self.original_dst_ip,  # NEW
                    original_dst_port=self.original_dst_port,  # NEW
                    seq_offset=self.client_tcp_seq,
                    ack_offset=self.client_tcp_ack,
                    tcp_len=len(tunneled_tcp_bytes),
                )

                icmp_payload = tunnel_header.pack() + tunneled_tcp_bytes

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
                send(icmp_packet, verbose=0)

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
