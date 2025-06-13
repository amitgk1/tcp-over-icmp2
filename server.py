import asyncio
import logging
import socket
import threading

from netfilterqueue import NetfilterQueue
from scapy.all import Raw, send
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
)

# --- Configuration ---
NFQUEUE_NUM = 0  # iptables queue number
LOG_LEVEL = logging.INFO

logging.basicConfig(level=LOG_LEVEL, format="[Server] %(levelname)s: %(message)s")


class ServerTunnel:
    def __init__(self, queue_num):
        self.queue_num = queue_num
        self.loop = asyncio.get_running_loop()

        # Map tunnel ID to remote TCP connection handler
        self.tunnel_id_to_handler = {}  # {tunnel_id: RemoteTCPConnectionHandler}

        # Queue for packets from NetfilterQueue to be processed in async loop
        self.nfqueue_packet_queue = asyncio.Queue()

        logging.info(f"Server tunnel initializing, listening on NFQUEUE {queue_num}")

    async def _handle_nfqueue_packet_from_queue(self):
        """Processes packets received from NFQUEUE by the dedicated thread."""
        while True:
            pkt = await self.nfqueue_packet_queue.get()
            try:
                # Convert raw payload to Scapy IP packet
                packet = IP(pkt.get_payload())

                if (
                    packet.haslayer(ICMP)
                    and packet[ICMP].type == ICMP_ECHO_REQUEST_TYPE
                ):
                    # This is our tunnel's ICMP packet from the client
                    if (
                        packet.haslayer(Raw)
                        and len(packet[Raw].load) >= TUNNEL_HEADER_LEN
                    ):
                        # Drop the packet to prevent kernel auto-reply
                        pkt.drop()
                        logging.debug(f"Dropped ICMP from {packet.src} (Tunnel).")
                        # Process tunneled data in an async task
                        self.loop.create_task(
                            self.handle_tunneled_icmp_request(
                                packet, pkt.hw_src
                            )  # pkt.hw_src for client's MAC if needed
                        )
                    else:
                        # Malformed tunnel packet
                        pkt.drop()
                        logging.warning(
                            f"Dropped malformed ICMP from {packet.src} (short payload)."
                        )
                else:
                    # Not our tunnel's ICMP, accept it
                    pkt.accept()
                    logging.debug(f"Accepted non-tunnel packet from {packet.src}.")

            except Exception as e:
                logging.error(f"Error processing NFQUEUE packet: {e}", exc_info=True)
                pkt.drop()  # Drop on error to be safe
            finally:
                self.nfqueue_packet_queue.task_done()

    def _nfqueue_listener_thread(self):
        """Dedicated thread for NetfilterQueue binding and listening."""
        logging.info(f"Starting NFQUEUE listener thread on queue {self.queue_num}...")
        try:
            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(
                self.queue_num,
                lambda pkt: self.loop.call_soon_threadsafe(
                    self.nfqueue_packet_queue.put_nowait, pkt
                ),  # type: ignore
            )
            self.nfqueue.run()  # This is a blocking call
        except Exception as e:
            logging.critical(
                f"NFQUEUE binding failed: {e}. Ensure iptables rules are set and run as root.",
                exc_info=True,
            )
        finally:
            logging.info("NFQUEUE listener thread stopped.")
            self.nfqueue.unbind()

    async def handle_tunneled_icmp_request(self, packet, client_mac):
        """Processes an incoming ICMP Echo Request containing tunneled TCP data."""
        client_ip = packet.src
        raw_tunnel_data = packet[Raw].load
        tunnel_header = TunnelHeader.unpack(raw_tunnel_data)
        tunneled_tcp_data = raw_tunnel_data[TUNNEL_HEADER_LEN:]

        tunnel_id = tunnel_header.tunnel_id
        flags = tunnel_header.flags
        # These offsets are from the client's perspective for its virtual TCP
        client_seq_offset = tunnel_header.seq_offset
        client_ack_offset = tunnel_header.ack_offset
        original_tcp_len = tunnel_header.tcp_len

        logging.debug(
            f"Tunnel {tunnel_id} from {client_ip}: Received flags={flags}, tcp_len={original_tcp_len}"
        )

        if tunnel_id not in self.tunnel_id_to_handler:
            # New tunnel connection (likely first SYN)
            # Try to parse the tunneled TCP data to get target details
            try:
                # We expect the first tunneled data to be a SYN-like TCP packet from the client.
                # This TCP packet is *synthesized* by the client, NOT the actual client's TCP.
                tunneled_tcp_pkt = TCP(tunneled_tcp_data)
                target_ip = tunneled_tcp_pkt.dst
                target_port = tunneled_tcp_pkt.dport
                logging.info(
                    f"Tunnel {tunnel_id}: New connection request from {client_ip} to {target_ip}:{target_port}"
                )

                handler = RemoteTCPConnectionHandler(
                    client_ip, target_ip, target_port, tunnel_id, self.loop, self
                )
                self.tunnel_id_to_handler[tunnel_id] = handler

                # Initiate connection to remote target and start forwarding
                await handler.start_remote_connection(
                    tunneled_tcp_data
                )  # Pass the SYN packet
            except Exception as e:
                logging.error(
                    f"Tunnel {tunnel_id}: Failed to parse initial TCP for new connection: {e}",
                    exc_info=True,
                )
                return
        else:
            # Existing tunnel connection
            handler = self.tunnel_id_to_handler[tunnel_id]

            if flags & FLAG_SYN and not handler.remote_connection_established:
                # This might be a re-SYN or the first SYN-ACK we're processing if race
                # For simplicity, if handler exists, assume it's set up
                logging.debug(
                    f"Tunnel {tunnel_id}: Received SYN on existing handler. Possibly retransmission or out of order."
                )
                await handler.send_to_remote_target(
                    tunneled_tcp_data
                )  # Re-send the SYN packet
            elif flags & FLAG_PSH:
                logging.debug(
                    f"Tunnel {tunnel_id}: Data received, forwarding to remote."
                )
                await handler.send_to_remote_target(tunneled_tcp_data)
            elif flags & FLAG_FIN:
                logging.info(
                    f"Tunnel {tunnel_id}: FIN received, closing remote target connection."
                )
                await handler.send_to_remote_target(
                    tunneled_tcp_data
                )  # Send FIN to remote
                await handler.close()  # Close our side
            elif flags & FLAG_RST:
                logging.info(
                    f"Tunnel {tunnel_id}: RST received, resetting remote target connection."
                )
                await handler.send_to_remote_target(
                    tunneled_tcp_data
                )  # Send RST to remote
                await handler.close()  # Close our side
            else:
                logging.debug(
                    f"Tunnel {tunnel_id}: Received TCP segment with flags {flags} (No PSH/FIN/RST), ignoring payload."
                )

    async def remove_handler(self, tunnel_id):
        """Removes a handler from the connection manager."""
        if tunnel_id in self.tunnel_id_to_handler:
            del self.tunnel_id_to_handler[tunnel_id]
            logging.info(f"Tunnel {tunnel_id} handler removed.")

    async def start(self):
        """Starts the server's NFQUEUE listener."""
        # Start the NFQUEUE listener in a separate thread
        nfqueue_thread = threading.Thread(
            target=self._nfqueue_listener_thread, daemon=True
        )
        nfqueue_thread.start()

        # Start the NFQUEUE packet processor in the event loop
        await self.loop.create_task(self._handle_nfqueue_packet_from_queue())


class RemoteTCPConnectionHandler:
    def __init__(
        self, client_ip, target_ip, target_port, tunnel_id, loop, server_instance
    ):
        self.client_ip = client_ip
        self.target_ip = target_ip
        self.target_port = target_port
        self.tunnel_id = tunnel_id
        self.loop = loop
        self.server_instance = server_instance  # Reference to the main server instance
        self.remote_reader = None
        self.remote_writer = None
        self.remote_connection_established = False
        self.closed = False

        # --- TCP Sequence Tracking (Server's Remote Connection) ---
        # We need to track the sequence and ack numbers of the *actual* TCP connection
        # between the server and the remote target.
        self.server_to_target_seq = 0
        self.server_to_target_ack = 0

        # This stores the initial SYN sequence from the client
        self.client_original_syn_seq = 0
        # This will store the initial SYN sequence chosen by the *target* server
        self.target_initial_syn_seq = 0

    async def start_remote_connection(self, initial_tcp_segment):
        """Establishes connection to the remote target and starts data forwarding."""
        try:
            # Parse the initial TCP segment from the client's tunnel (it's a synthesized SYN)
            initial_tunneled_tcp = TCP(initial_tcp_segment)
            self.client_original_syn_seq = (
                initial_tunneled_tcp.seq
            )  # Store client's initial seq

            # Establish actual TCP connection to target
            self.remote_reader, self.remote_writer = await asyncio.open_connection(
                self.target_ip, self.target_port
            )
            self.remote_connection_established = True
            logging.info(
                f"Tunnel {self.tunnel_id}: Connected to remote target {self.target_ip}:{self.target_port}"
            )

            # Send the initial data (e.g., HTTP request) from the client's SYN/PSH packet
            # The client's initial_tcp_segment might contain a SYN and data.
            # We already established the connection. Now send the payload.
            if initial_tunneled_tcp.payload:
                await self.send_to_remote_target(initial_tunneled_tcp.payload)

            # Start reading from the remote target
            self.loop.create_task(self._read_from_remote_target())

        except Exception as e:
            logging.error(
                f"Tunnel {self.tunnel_id}: Failed to connect to remote target {self.target_ip}:{self.target_port}: {e}",
                exc_info=True,
            )
            await self.close()

    async def _read_from_remote_target(self):
        """Reads data from the remote TCP target and encapsulates for client."""
        try:
            while not self.closed and self.remote_reader:
                data = await self.remote_reader.read(4096)
                if not data:
                    logging.info(
                        f"Tunnel {self.tunnel_id}: Remote target {self.target_ip}:{self.target_port} closed connection."
                    )
                    break  # Connection closed by remote target

                # Create a synthetic TCP packet for the client
                # This is a critical simplification. We need to maintain sequence/ack numbers
                # *relative to the original client's connection*.
                # For this minimal version, we'll just send the raw data.
                # A full implementation would track actual TCP sequence numbers from the target.

                # Simulate a TCP header for the client with proper flags (ACK/PSH)
                # The seq/ack numbers here are the *server's perception* of the client's original flow.
                # This needs careful calculation to match what the client expects.
                # Dummy values for now:
                # server_current_seq = self.target_initial_syn_seq + bytes_sent_to_client
                # client_expected_ack = self.client_original_syn_seq + bytes_received_from_client

                # Minimal: We'll create a dummy TCP header that Scapy can parse.
                # Client will extract the Raw payload.
                response_tcp_pkt = TCP(
                    sport=self.target_port,
                    dport=self.client_original_syn_seq,  # Use client's original seq as a dummy dport
                    flags="PA",
                    seq=1,  # Dummy sequence for now
                    ack=1,  # Dummy ack for now
                    window=65535,
                ) / Raw(load=data)

                tunneled_tcp_bytes = bytes(response_tcp_pkt)

                tunnel_header = TunnelHeader(
                    flags=FLAG_PSH | FLAG_ACK,  # Assume it's data
                    tunnel_id=self.tunnel_id,
                    seq_offset=1,  # Dummy for now
                    ack_offset=1,  # Dummy for now
                    tcp_len=len(tunneled_tcp_bytes),
                )

                icmp_payload = tunnel_header.pack() + tunneled_tcp_bytes

                # Construct ICMP Echo Reply
                icmp_packet = (
                    IP(dst=self.client_ip)
                    / ICMP(
                        type=ICMP_ECHO_REPLY_TYPE,
                        code=0,
                        id=self.tunnel_id,
                        seq=self.tunnel_id,
                    )
                    / Raw(load=icmp_payload)
                )

                logging.debug(
                    f"Tunnel {self.tunnel_id}: Sending {len(data)} bytes to client {self.client_ip} via ICMP reply."
                )
                send(icmp_packet, verbose=0)

        except Exception as e:
            logging.error(
                f"Tunnel {self.tunnel_id}: Error reading from remote target: {e}",
                exc_info=True,
            )
        finally:
            await self.close()

    async def send_to_remote_target(self, data):
        """Sends decapsulated TCP data to the remote target."""
        if self.remote_writer and not self.closed:
            try:
                # Data here is the raw TCP segment received from the client.
                # We need to write its payload to the remote socket.
                # If the client sent a full TCP segment via Raw(load=bytes(TCP(...))),
                # then we can extract its payload.
                # For our minimal solution, we're assuming 'data' IS the TCP segment.

                tcp_pkt = TCP(data)
                self.remote_writer.write(
                    tcp_pkt[Raw].load  # TODO: this was tcp_pkt.payload
                )
                await self.remote_writer.drain()
                logging.debug(
                    f"Tunnel {self.tunnel_id}: Sent {len(tcp_pkt.payload)} bytes to remote target."
                )
            except Exception as e:
                logging.error(
                    f"Tunnel {self.tunnel_id}: Error writing to remote target: {e}",
                    exc_info=True,
                )
                await self.close()

    async def close(self):
        """Closes the remote TCP connection and cleans up."""
        if not self.closed:
            self.closed = True
            logging.info(f"Tunnel {self.tunnel_id}: Closing remote connection.")
            if self.remote_writer:
                self.remote_writer.close()
                await self.remote_writer.wait_closed()  # Ensure it's closed
            await self.server_instance.remove_handler(
                self.tunnel_id
            )  # Remove from server's map


async def main():
    global server_instance
    server_instance = ServerTunnel(NFQUEUE_NUM)
    await server_instance.start()


if __name__ == "__main__":
    # Ensure this runs as root for NFQUEUE and raw sockets
    # A simple check:
    if not threading.current_thread().name == "MainThread" or not hasattr(
        socket, "AF_PACKET"
    ):
        logging.warning(
            "Consider running this script as root for NFQUEUE access and iptables rules."
        )

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    except Exception as e:
        logging.critical(f"Unhandled exception in main: {e}", exc_info=True)
