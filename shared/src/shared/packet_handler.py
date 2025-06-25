import logging
import struct
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .utils import calculate_checksum


class PacketType(Enum):
    DATA = 1
    FRAGMENT = 2
    ACK = 3
    CONNECT = 4
    CONNECT_RESPONSE = 5
    CLOSE = 6


@dataclass
class TunnelPacket:
    """Represents a tunnel packet."""

    packet_type: PacketType
    sequence: int
    connection_id: str
    data: bytes
    fragment_id: Optional[int] = None
    total_fragments: Optional[int] = None
    fragment_offset: Optional[int] = None
    timestamp: Optional[float] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


class PacketHandler:
    """Handles ICMP packet encapsulation and decapsulation."""

    # ICMP payload size limit (accounting for IP and ICMP headers)
    MAX_ICMP_PAYLOAD = 65507  # 65535 - 20 (IP) - 8 (ICMP)

    # Tunnel protocol overhead
    TUNNEL_HEADER_SIZE = (
        20  # packet_type(1) + sequence(4) + conn_id_len(1) + conn_id(16) + checksum(2)
    )
    FRAGMENT_HEADER_SIZE = 8  # fragment_id(4) + total_fragments(2) + offset(2)

    # Maximum data size per packet
    MAX_DATA_SIZE = MAX_ICMP_PAYLOAD - TUNNEL_HEADER_SIZE - FRAGMENT_HEADER_SIZE

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.sequence_counter = 0
        self.fragment_counter = 0
        self.lock = threading.Lock()
        self.fragment_buffers: Dict[str, Dict[int, Dict[int, bytes]]] = {}
        self.fragment_timeouts: Dict[str, float] = {}
        self.fragment_cleanup_time = 30.0  # 30 seconds

        self.logger.debug(
            f"PacketHandler initialized - MAX_DATA_SIZE: {self.MAX_DATA_SIZE}"
        )

    def _get_next_sequence(self) -> int:
        """Get the next sequence number."""
        with self.lock:
            self.sequence_counter = (self.sequence_counter + 1) % 0xFFFFFFFF
            self.logger.debug(f"Generated sequence number: {self.sequence_counter}")
            return self.sequence_counter

    def _get_next_fragment_id(self) -> int:
        """Get the next fragment ID."""
        with self.lock:
            self.fragment_counter = (self.fragment_counter + 1) % 0xFFFFFFFF
            self.logger.debug(f"Generated fragment ID: {self.fragment_counter}")
            return self.fragment_counter

    def _cleanup_old_fragments(self):
        """Clean up old fragment buffers."""
        current_time = time.time()
        to_remove = []

        for conn_id, timeout in self.fragment_timeouts.items():
            if current_time - timeout > self.fragment_cleanup_time:
                to_remove.append(conn_id)

        if to_remove:
            self.logger.debug(
                f"Cleaning up {len(to_remove)} old fragment buffers: {to_remove}"
            )

        for conn_id in to_remove:
            del self.fragment_buffers[conn_id]
            del self.fragment_timeouts[conn_id]

    def create_packet(
        self, packet_type: PacketType, connection_id: str, data: bytes = b""
    ) -> List[bytes]:
        """Create tunnel packet(s) from data."""
        self.logger.debug(
            f"Creating packet - Type: {packet_type.name}, Conn: {connection_id}, Data size: {len(data)}"
        )

        if len(data) <= self.MAX_DATA_SIZE:
            # Single packet
            packet = TunnelPacket(
                packet_type=packet_type,
                sequence=self._get_next_sequence(),
                connection_id=connection_id,
                data=data,
            )
            serialized = self._serialize_packet(packet)
            self.logger.debug(
                f"Created single packet - Size: {len(serialized)}, Sequence: {packet.sequence}"
            )
            return [serialized]
        else:
            # Fragmentation needed
            self.logger.debug(
                f"Data too large ({len(data)} bytes), creating fragmented packets"
            )
            return self._create_fragmented_packets(packet_type, connection_id, data)

    def _create_fragmented_packets(
        self, packet_type: PacketType, connection_id: str, data: bytes
    ) -> List[bytes]:
        """Create fragmented packets for large data."""
        fragment_id = self._get_next_fragment_id()
        total_fragments = (len(data) + self.MAX_DATA_SIZE - 1) // self.MAX_DATA_SIZE
        packets = []

        self.logger.debug(
            f"Creating {total_fragments} fragments for {len(data)} bytes of data"
        )

        for i in range(total_fragments):
            offset = i * self.MAX_DATA_SIZE
            fragment_data = data[offset : offset + self.MAX_DATA_SIZE]

            packet = TunnelPacket(
                packet_type=packet_type,
                sequence=self._get_next_sequence(),
                connection_id=connection_id,
                data=fragment_data,
                fragment_id=fragment_id,
                total_fragments=total_fragments,
                fragment_offset=offset,
            )

            serialized = self._serialize_packet(packet)
            packets.append(serialized)

            self.logger.debug(
                f"Created fragment {i+1}/{total_fragments} - Size: {len(serialized)}, Offset: {offset}"
            )

        self.logger.debug(
            f"Created {len(packets)} fragmented packets with fragment_id: {fragment_id}"
        )
        return packets

    def _serialize_packet(self, packet: TunnelPacket) -> bytes:
        """Serialize a tunnel packet to bytes."""
        self.logger.debug(
            f"Serializing packet - Type: {packet.packet_type.name}, Seq: {packet.sequence}, Conn: {packet.connection_id}"
        )

        # Pack the header
        header = struct.pack(
            "!BIIIH",
            packet.packet_type.value,
            packet.sequence,
            len(packet.connection_id),
            0,  # Reserved
            0,
        )  # Checksum placeholder

        # Add connection ID
        conn_id_bytes = packet.connection_id.encode("utf-8")
        header += conn_id_bytes

        # Add fragment info if needed
        if packet.fragment_id is not None:
            fragment_header = struct.pack(
                "!IHH",
                packet.fragment_id,
                packet.total_fragments or 0,
                packet.fragment_offset or 0,
            )
            self.logger.debug(
                f"Added fragment header - ID: {packet.fragment_id}, Total: {packet.total_fragments}, Offset: {packet.fragment_offset}"
            )
        else:
            fragment_header = struct.pack("!IHH", 0, 0, 0)

        # Combine all parts
        packet_data = header + fragment_header + packet.data

        # Calculate and insert checksum
        checksum = calculate_checksum(packet_data, self.logger)
        packet_data = packet_data[:8] + struct.pack("!H", checksum) + packet_data[10:]

        self.logger.debug(
            f"Serialized packet - Total size: {len(packet_data)}, Checksum: 0x{checksum:04x}"
        )
        return packet_data

    def parse_packet(self, data: bytes) -> Optional[TunnelPacket]:
        """Parse bytes into a tunnel packet."""
        self.logger.debug(f"Parsing packet - Data size: {len(data)}")

        try:
            if len(data) < self.TUNNEL_HEADER_SIZE:
                self.logger.debug(
                    f"Packet too small: {len(data)} < {self.TUNNEL_HEADER_SIZE}"
                )
                return None

            # Parse header
            header = data[: self.TUNNEL_HEADER_SIZE]
            packet_type_val, sequence, conn_id_len, reserved, checksum = struct.unpack(
                "!BIIIH", header[:16]
            )

            self.logger.debug(
                f"Parsed header - Type: {packet_type_val}, Seq: {sequence}, Conn ID len: {conn_id_len}, Checksum: 0x{checksum:04x}"
            )

            # Validate checksum
            calculated_checksum = calculate_checksum(
                data[:8] + b"\x00\x00" + data[10:], self.logger
            )
            if calculated_checksum != checksum:
                self.logger.warning(
                    f"Checksum mismatch - Expected: 0x{checksum:04x}, Calculated: 0x{calculated_checksum:04x}"
                )
                return None

            # Parse connection ID
            conn_id_start = 16
            conn_id_end = conn_id_start + conn_id_len
            if conn_id_end > len(data):
                self.logger.debug(
                    f"Connection ID extends beyond packet: {conn_id_end} > {len(data)}"
                )
                return None

            connection_id = data[conn_id_start:conn_id_end].decode("utf-8")
            self.logger.debug(f"Parsed connection ID: {connection_id}")

            # Parse fragment info
            fragment_start = conn_id_end
            fragment_end = fragment_start + self.FRAGMENT_HEADER_SIZE
            if fragment_end > len(data):
                self.logger.debug(
                    f"Fragment header extends beyond packet: {fragment_end} > {len(data)}"
                )
                return None

            fragment_id, total_fragments, fragment_offset = struct.unpack(
                "!IHH", data[fragment_start:fragment_end]
            )

            self.logger.debug(
                f"Parsed fragment info - ID: {fragment_id}, Total: {total_fragments}, Offset: {fragment_offset}"
            )

            # Get data
            packet_data = data[fragment_end:]
            self.logger.debug(f"Extracted data - Size: {len(packet_data)}")

            # Create packet
            packet = TunnelPacket(
                packet_type=PacketType(packet_type_val),
                sequence=sequence,
                connection_id=connection_id,
                data=packet_data,
                fragment_id=fragment_id if fragment_id != 0 else None,
                total_fragments=total_fragments if total_fragments != 0 else None,
                fragment_offset=fragment_offset if fragment_offset != 0 else None,
            )

            self.logger.debug(
                f"Successfully parsed packet - Type: {packet.packet_type.name}, Conn: {packet.connection_id}"
            )
            return packet

        except (struct.error, UnicodeDecodeError, ValueError) as e:
            self.logger.error(f"Failed to parse packet: {e}")
            return None

    def handle_fragmented_packet(self, packet: TunnelPacket) -> Optional[bytes]:
        """Handle fragmented packet and return complete data if available."""
        if packet.fragment_id is None:
            self.logger.debug(f"Non-fragmented packet, returning data directly")
            return packet.data

        self.logger.debug(
            f"Handling fragmented packet - Fragment ID: {packet.fragment_id}, Offset: {packet.fragment_offset}, Total: {packet.total_fragments}"
        )

        # Clean up old fragments
        self._cleanup_old_fragments()

        # Initialize fragment buffer for this connection
        if packet.connection_id not in self.fragment_buffers:
            self.fragment_buffers[packet.connection_id] = {}
            self.fragment_timeouts[packet.connection_id] = time.time()
            self.logger.debug(
                f"Initialized fragment buffer for connection: {packet.connection_id}"
            )

        # Store fragment
        fragment_key = packet.fragment_id
        if fragment_key not in self.fragment_buffers[packet.connection_id]:
            self.fragment_buffers[packet.connection_id][fragment_key] = {}

        fragment_offset = packet.fragment_offset or 0
        self.fragment_buffers[packet.connection_id][fragment_key][
            fragment_offset
        ] = packet.data
        self.fragment_timeouts[packet.connection_id] = time.time()

        self.logger.debug(
            f"Stored fragment {fragment_offset} for connection {packet.connection_id}"
        )

        # Check if we have all fragments
        fragments = self.fragment_buffers[packet.connection_id][fragment_key]
        total_fragments = packet.total_fragments or 0
        current_fragments = len(fragments)

        self.logger.debug(
            f"Fragment status - Have: {current_fragments}/{total_fragments}"
        )

        if current_fragments == total_fragments:
            # Reassemble data
            self.logger.debug(f"All fragments received, reassembling data")
            data_parts = []
            for i in range(total_fragments):
                offset = i * self.MAX_DATA_SIZE
                if offset in fragments:
                    data_parts.append(fragments[offset])
                else:
                    # Missing fragment
                    self.logger.warning(f"Missing fragment at offset {offset}")
                    return None

            # Clean up fragment buffer
            del self.fragment_buffers[packet.connection_id][fragment_key]
            if not self.fragment_buffers[packet.connection_id]:
                del self.fragment_buffers[packet.connection_id]
                del self.fragment_timeouts[packet.connection_id]

            reassembled_data = b"".join(data_parts)
            self.logger.debug(
                f"Successfully reassembled {len(reassembled_data)} bytes of data"
            )
            return reassembled_data

        self.logger.debug(
            f"Still waiting for {total_fragments - current_fragments} more fragments"
        )
        return None

    def create_ack_packet(self, sequence: int, connection_id: str) -> bytes:
        """Create an acknowledgment packet."""
        self.logger.debug(
            f"Creating ACK packet for sequence {sequence}, connection {connection_id}"
        )
        packet = TunnelPacket(
            packet_type=PacketType.ACK,
            sequence=sequence,
            connection_id=connection_id,
            data=b"",
        )
        return self._serialize_packet(packet)
