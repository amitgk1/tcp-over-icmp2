import queue
import threading
import time
from typing import Dict, Optional

from icmp_tunnel import ICMPTunnel, TunnelPacket


class ReliableConnection:
    def __init__(
        self, tunnel: ICMPTunnel, remote_ip: str, local_port: int, remote_port: int
    ):
        self.tunnel = tunnel
        self.remote_ip = remote_ip
        self.local_port = local_port
        self.remote_port = remote_port

        # Sequence numbers
        self.send_seq = 1000
        self.recv_seq = 0
        self.recv_ack = 0

        # Sliding window
        self.window_size = 10
        self.send_window: Dict[int, TunnelPacket] = {}
        self.recv_buffer: Dict[int, TunnelPacket] = {}

        # Queues
        self.send_queue = queue.Queue()
        self.recv_queue = queue.Queue()

        # Threading
        self.running = False
        self.threads = []

        # Retransmission
        self.rto = 1.0  # Retransmission timeout
        self.last_send_time: Dict[int, float] = {}

    def start(self):
        """Start the reliable connection"""
        self.running = True

        # Start worker threads
        self.threads.append(threading.Thread(target=self._send_worker, daemon=True))
        self.threads.append(threading.Thread(target=self._recv_worker, daemon=True))
        self.threads.append(
            threading.Thread(target=self._retransmit_worker, daemon=True)
        )

        for thread in self.threads:
            thread.start()

    def stop(self):
        """Stop the reliable connection"""
        self.running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=1.0)

    def send_data(self, data: bytes, dst_ip: str, dst_port: int):
        """Queue data for reliable sending"""
        packet = TunnelPacket(
            seq=self.send_seq,
            ack=self.recv_seq,
            flags=TunnelPacket.FLAG_DATA,
            window=self.window_size,
            src_ip="0.0.0.0",  # Will be filled by kernel
            src_port=self.local_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            data=data,
        )
        self.send_queue.put(packet)
        self.send_seq += 1

    def recv_data(self, timeout: float = 1.0) -> Optional[bytes]:
        """Receive data reliably"""
        try:
            packet = self.recv_queue.get(timeout=timeout)
            return packet.data
        except queue.Empty:
            return None

    def _send_worker(self):
        """Worker thread for sending packets"""
        while self.running:
            try:
                packet = self.send_queue.get(timeout=0.1)

                # Check if we can send (window not full)
                while len(self.send_window) >= self.window_size and self.running:
                    time.sleep(0.01)

                if not self.running:
                    break

                # Add to send window
                self.send_window[packet.seq] = packet
                self.last_send_time[packet.seq] = time.time()

                # Send packet
                self.tunnel.send_packet(packet, self.remote_ip)

            except queue.Empty:
                continue
            except Exception as e:
                print(f"Send worker error: {e}")

    def _recv_worker(self):
        """Worker thread for receiving packets"""
        while self.running:
            try:
                result = self.tunnel.receive_packet(timeout=0.1)
                if not result:
                    continue

                packet, src_ip = result

                # Process ACKs
                if packet.flags & TunnelPacket.FLAG_ACK:
                    self._process_ack(packet.ack)

                # Process data packets
                if packet.flags & TunnelPacket.FLAG_DATA:
                    self._process_data_packet(packet)

            except Exception as e:
                print(f"Recv worker error: {e}")

    def _retransmit_worker(self):
        """Worker thread for retransmissions"""
        while self.running:
            current_time = time.time()

            # Check for packets that need retransmission
            for seq, packet in list(self.send_window.items()):
                if seq in self.last_send_time:
                    if current_time - self.last_send_time[seq] > self.rto:
                        # Retransmit
                        self.tunnel.send_packet(packet, self.remote_ip)
                        self.last_send_time[seq] = current_time

            time.sleep(0.1)

    def _process_ack(self, ack_num: int):
        """Process ACK and remove acknowledged packets from send window"""
        to_remove = []
        for seq in self.send_window:
            if seq <= ack_num:
                to_remove.append(seq)

        for seq in to_remove:
            if seq in self.send_window:
                del self.send_window[seq]
            if seq in self.last_send_time:
                del self.last_send_time[seq]

    def _process_data_packet(self, packet: TunnelPacket):
        """Process incoming data packet"""
        # Send ACK
        ack_packet = TunnelPacket(
            seq=self.send_seq,
            ack=packet.seq,
            flags=TunnelPacket.FLAG_ACK,
            window=self.window_size,
            src_ip="0.0.0.0",
            src_port=self.local_port,
            dst_ip=packet.src_ip,
            dst_port=packet.src_port,
            data=b"",
        )
        self.tunnel.send_packet(ack_packet, self.remote_ip)

        # Check if packet is in order
        if packet.seq == self.recv_seq + 1:
            # In order packet
            self.recv_seq = packet.seq
            self.recv_queue.put(packet)

            # Check if we can deliver buffered packets
            while (self.recv_seq + 1) in self.recv_buffer:
                self.recv_seq += 1
                buffered_packet = self.recv_buffer.pop(self.recv_seq)
                self.recv_queue.put(buffered_packet)

        elif packet.seq > self.recv_seq + 1:
            # Out of order packet, buffer it
            self.recv_buffer[packet.seq] = packet
