import asyncio
import logging
import os
import socket

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet as NetfilterQueuePacket
from scapy.all import Packet as ScapyPacket
from scapy.all import Raw, send
from scapy.layers.inet import ICMP, IP

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

        self.nfqueue = NetfilterQueue()
        # Bind the callback to process packets directly into the queue
        self.nfqueue.bind(self.queue_num, self._nfqueue_to_async_queue_callback)

        self.tunnel_id_to_handler = {}

        # Asyncio Queue to pass raw NetfilterQueue packets to the main event loop
        self.nfqueue_async_queue = asyncio.Queue[bytes]()

        logging.info(f"Server tunnel initializing, listening on NFQUEUE {queue_num}")

    def _nfqueue_to_async_queue_callback(self, pkt: NetfilterQueuePacket):
        """
        This synchronous callback is called by netfilterqueue.run(block=False).
        It puts the raw nfqueue packet into our asyncio.Queue.
        """
        # We need to capture essential info *before* NetfilterQueue's internal buffer
        # releases the packet's payload (after pkt.drop() or pkt.accept()).
        # So we clone it or extract necessary parts.
        raw_payload = pkt.get_payload()
        # hw_src = (
        #     pkt.hw_src
        # )  # MAC address, might be useful for logging/specific filtering

        # We also need to decide the verdict *here* to prevent auto-replies.
        # But we also need to parse our custom header *before* deciding,
        # which means parsing in this synchronous context.
        # Let's adjust for this:
        try:
            packet = IP(raw_payload)
            if packet.haslayer(ICMP) and packet[ICMP].type == ICMP_ECHO_REQUEST_TYPE:
                if packet.haslayer(Raw) and len(packet[Raw].load) >= TUNNEL_HEADER_LEN:
                    # It's our tunnel packet, drop it immediately to prevent kernel auto-reply
                    pkt.drop()
                    # Schedule its processing in the async loop
                    # We pass the raw_payload so async task can re-parse it
                    self.loop.call_soon_threadsafe(
                        self.nfqueue_async_queue.put_nowait, raw_payload
                    )
                else:
                    # Malformed tunnel packet or short ICMP. Drop to be safe.
                    pkt.drop()
                    logging.warning(
                        f"Dropped malformed ICMP from {packet.src} (short payload)."
                    )
            else:
                # Not our tunnel's ICMP, accept it
                pkt.accept()
                logging.debug(f"Accepted non-tunnel packet from {packet.src}.")

        except Exception as e:
            logging.error(
                f"Error in _nfqueue_to_async_queue_callback: {e}", exc_info=True
            )
            pkt.drop()  # Drop on error to be safe

    async def _process_nfqueue_packets_from_queue(self):
        """
        Async task that continuously processes packets from the asyncio.Queue.
        This runs cooperatively in the event loop.
        """
        while True:
            raw_payload = await self.nfqueue_async_queue.get()
            try:
                packet = IP(raw_payload)  # Re-parse the packet in the async context
                # Now call the actual handler for tunneled data
                await self.handle_tunneled_icmp_request(packet)
            except Exception as e:
                logging.error(
                    f"Error processing packet from NFQUEUE async queue: {e}",
                    exc_info=True,
                )
            finally:
                self.nfqueue_async_queue.task_done()

    async def handle_tunneled_icmp_request(self, packet: ScapyPacket):
        """Processes an incoming ICMP Echo Request containing tunneled TCP data."""
        client_ip = packet.src
        raw_tunnel_data = packet[Raw].load
        tunnel_header = TunnelHeader.unpack(raw_tunnel_data)
        tunneled_tcp_data = raw_tunnel_data[TUNNEL_HEADER_LEN:]

        tunnel_id = tunnel_header.tunnel_id
        flags = tunnel_header.flags
        # Extract new fields from header
        client_seq_offset = tunnel_header.seq_offset
        client_ack_offset = tunnel_header.ack_offset
        original_tcp_len = tunnel_header.tcp_len

        # Convert IP int back to string
        target_ip = tunnel_header.original_dst_ip
        target_port = tunnel_header.original_dst_port

        logging.debug(
            f"Tunnel {tunnel_id} from {client_ip}: Received flags={flags}, tcp_len={original_tcp_len}"
        )

        if tunnel_id not in self.tunnel_id_to_handler:
            # New tunnel connection (likely first SYN)
            logging.info(
                f"Tunnel {tunnel_id}: New connection request from {client_ip} to {target_ip}:{target_port}"
            )

            handler = RemoteTCPConnectionHandler(
                client_ip, target_ip, target_port, tunnel_id, self.loop, self
            )
            self.tunnel_id_to_handler[tunnel_id] = handler

            # Start connection to remote target and pass the first data/SYN
            await handler.start_remote_connection(
                tunneled_tcp_data
            )  # This `tunneled_tcp_data` is the raw app data
        else:
            handler = self.tunnel_id_to_handler[tunnel_id]

            if flags & FLAG_SYN and not handler.remote_connection_established:
                logging.debug(
                    f"Tunnel {tunnel_id}: Received SYN on existing handler. Possibly retransmission or out of order."
                )
                await handler.send_to_remote_target(tunneled_tcp_data)
            elif flags & FLAG_PSH:
                logging.debug(
                    f"Tunnel {tunnel_id}: Data received, forwarding to remote."
                )
                # Send raw app data
                await handler.send_to_remote_target(tunneled_tcp_data)
            elif flags & FLAG_FIN:
                logging.info(
                    f"Tunnel {tunnel_id}: FIN received, closing remote target connection."
                )
                await handler.send_to_remote_target(tunneled_tcp_data)
                await handler.close()
            elif flags & FLAG_RST:
                logging.info(
                    f"Tunnel {tunnel_id}: RST received, resetting remote target connection."
                )
                await handler.send_to_remote_target(tunneled_tcp_data)
                await handler.close()
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
        """Starts the server's NFQUEUE listener and processing task."""
        # Add the NFQUEUE file descriptor to the asyncio event loop's readers
        self.loop.add_reader(
            self.nfqueue.get_fd(), lambda: self.nfqueue.run(block=False)
        )
        logging.info("Server NFQUEUE FD added to asyncio event loop.")

        # Start the async task that processes packets from the queue
        self.loop.create_task(self._process_nfqueue_packets_from_queue())
        logging.info("Server NFQUEUE async processing task initiated.")

        # Keep the main async loop running indefinitely
        await asyncio.Event().wait()


class RemoteTCPConnectionHandler:
    def __init__(
        self, client_ip, target_ip, target_port, tunnel_id, loop, server_instance
    ):
        self.client_ip = client_ip
        self.target_ip = target_ip
        self.target_port = target_port
        self.tunnel_id = tunnel_id
        self.loop = loop
        self.server_instance = server_instance
        self.remote_reader = None
        self.remote_writer = None
        self.remote_connection_established = False
        self.closed = False

        self.server_to_target_seq = 0
        self.server_to_target_ack = 0
        self.client_original_syn_seq = 0
        self.target_initial_syn_seq = 0

    async def start_remote_connection(self, initial_app_data):  # Renamed for clarity
        try:
            # No need to parse TCP(initial_app_data) here if it's just raw app data
            # self.client_original_syn_seq = initial_tunneled_tcp.seq # This line might not be needed if not full TCP state

            self.remote_reader, self.remote_writer = await asyncio.open_connection(
                self.target_ip, self.target_port
            )
            self.remote_connection_established = True
            logging.info(
                f"Tunnel {self.tunnel_id}: Connected to remote target {self.target_ip}:{self.target_port}"
            )

            if initial_app_data:  # If client sent data with SYN
                await self.send_to_remote_target(initial_app_data)  # Send raw app data

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
                    break

                tunneled_tcp_bytes = data

                tunnel_header = TunnelHeader(
                    flags=FLAG_PSH | FLAG_ACK,
                    tunnel_id=self.tunnel_id,
                    original_dst_ip=self.target_ip,
                    original_dst_port=self.target_port,
                    seq_offset=1,  # Dummy for now
                    ack_offset=1,  # Dummy for now
                    tcp_len=len(tunneled_tcp_bytes),
                )

                icmp_payload = tunnel_header.pack() + tunneled_tcp_bytes

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

    async def send_to_remote_target(self, app_data):  # Renamed for clarity
        if self.remote_writer and not self.closed:
            try:
                # NO: tcp_pkt = TCP(data) # 'data' is raw app data, not a TCP segment here
                self.remote_writer.write(app_data)  # Just write the raw app data
                await self.remote_writer.drain()
                logging.debug(
                    f"Tunnel {self.tunnel_id}: Sent {len(app_data)} bytes to remote target."
                )
            except Exception as e:
                logging.error(
                    f"Tunnel {self.tunnel_id}: Error writing to remote target: {e}",
                    exc_info=True,
                )
                await self.close()

    async def close(self):
        if not self.closed:
            self.closed = True
            logging.info(f"Tunnel {self.tunnel_id}: Closing remote connection.")
            if self.remote_writer:
                self.remote_writer.close()
                await self.remote_writer.wait_closed()
            await self.server_instance.remove_handler(self.tunnel_id)


async def main():
    global server_instance
    server_instance = ServerTunnel(NFQUEUE_NUM)
    await server_instance.start()


if __name__ == "__main__":
    if not hasattr(socket, "AF_PACKET") or not os.getuid() == 0:
        logging.critical(
            "This script requires root privileges to run NFQUEUE/raw sockets and iptables rules."
        )
        logging.critical("Exiting.")
        exit(1)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    except Exception as e:
        logging.critical(f"Unhandled exception in main: {e}", exc_info=True)
