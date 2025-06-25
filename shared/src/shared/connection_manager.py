import logging
import socket
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Set, Tuple


class ConnectionState(Enum):
    ESTABLISHED = "ESTABLISHED"
    CLOSED = "CLOSED"
    TIMEOUT = "TIMEOUT"


@dataclass
class Connection:
    """Represents a tunnel connection."""

    connection_id: str
    client_addr: Tuple[str, int]
    server_addr: Tuple[str, int]
    client_socket: Optional[socket.socket]
    server_socket: Optional[socket.socket]
    state: ConnectionState
    created_at: float
    last_activity: float

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()
        if self.last_activity is None:
            self.last_activity = time.time()


class ConnectionManager:
    """Manages tunnel connections."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.connections: Dict[str, Connection] = {}
        self.lock = threading.RLock()
        self.running = False
        self.cleanup_thread: Optional[threading.Thread] = None
        self.connection_timeout = 300.0  # 5 minutes
        self.cleanup_interval = 30.0  # 30 seconds

    def start(self):
        """Start the connection manager."""
        self.logger.debug("Starting ConnectionManager")
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        self.logger.debug("ConnectionManager started successfully")

    def stop(self):
        """Stop the connection manager."""
        self.logger.debug("Stopping ConnectionManager")
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5.0)
        self.logger.debug("ConnectionManager stopped")

    def add_connection(
        self,
        client_addr: Tuple[str, int],
        server_addr: Tuple[str, int],
        client_socket: Optional[socket.socket] = None,
    ) -> str:
        """Add a new connection."""
        with self.lock:
            # Generate connection ID
            conn_id = (
                f"{client_addr[0]}:{client_addr[1]}-{server_addr[0]}:{server_addr[1]}"
            )

            self.logger.debug(f"Adding connection: {conn_id}")
            self.logger.debug(f"  Client: {client_addr}")
            self.logger.debug(f"  Server: {server_addr}")

            # Create connection
            connection = Connection(
                connection_id=conn_id,
                client_addr=client_addr,
                server_addr=server_addr,
                client_socket=client_socket,
                server_socket=None,
                state=ConnectionState.ESTABLISHED,
                created_at=time.time(),
                last_activity=time.time(),
            )

            self.connections[conn_id] = connection
            self.logger.debug(f"Connection added successfully: {conn_id}")
            return conn_id

    def get_connection(self, connection_id: str) -> Optional[Connection]:
        """Get a connection by ID."""
        with self.lock:
            connection = self.connections.get(connection_id)
            if connection:
                connection.last_activity = time.time()
                self.logger.debug(f"Retrieved connection: {connection_id}")
            else:
                self.logger.debug(f"Connection not found: {connection_id}")
            return connection

    def update_connection_socket(
        self, connection_id: str, server_socket: socket.socket
    ):
        """Update the server socket for a connection."""
        with self.lock:
            connection = self.connections.get(connection_id)
            if connection:
                connection.server_socket = server_socket
                connection.last_activity = time.time()
                self.logger.debug(
                    f"Updated server socket for connection: {connection_id}"
                )
            else:
                self.logger.warning(
                    f"Cannot update socket - connection not found: {connection_id}"
                )

    def close_connection(self, connection_id: str):
        """Close a connection."""
        with self.lock:
            connection = self.connections.get(connection_id)
            if connection:
                self.logger.debug(f"Closing connection: {connection_id}")

                # Close sockets
                if connection.client_socket:
                    try:
                        connection.client_socket.close()
                        self.logger.debug(f"Closed client socket for: {connection_id}")
                    except Exception as e:
                        self.logger.debug(f"Error closing client socket: {e}")

                if connection.server_socket:
                    try:
                        connection.server_socket.close()
                        self.logger.debug(f"Closed server socket for: {connection_id}")
                    except Exception as e:
                        self.logger.debug(f"Error closing server socket: {e}")

                # Update state
                connection.state = ConnectionState.CLOSED
                del self.connections[connection_id]
                self.logger.debug(f"Connection closed and removed: {connection_id}")
            else:
                self.logger.debug(
                    f"Cannot close - connection not found: {connection_id}"
                )

    def get_connection_count(self) -> int:
        """Get the number of active connections."""
        with self.lock:
            count = len(self.connections)
            self.logger.debug(f"Active connections: {count}")
            return count

    def cleanup_all(self):
        """Clean up all connections."""
        with self.lock:
            self.logger.debug(f"Cleaning up all {len(self.connections)} connections")
            for conn_id in list(self.connections.keys()):
                self.close_connection(conn_id)
            self.logger.debug("All connections cleaned up")

    def _cleanup_loop(self):
        """Background cleanup loop."""
        self.logger.debug("Starting cleanup loop")
        while self.running:
            try:
                time.sleep(self.cleanup_interval)
                self._cleanup_timeout_connections()
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")

    def _cleanup_timeout_connections(self):
        """Clean up timed-out connections."""
        current_time = time.time()
        to_remove = []

        with self.lock:
            for conn_id, connection in self.connections.items():
                if current_time - connection.last_activity > self.connection_timeout:
                    to_remove.append(conn_id)

        if to_remove:
            self.logger.debug(
                f"Cleaning up {len(to_remove)} timed-out connections: {to_remove}"
            )
            for conn_id in to_remove:
                self.close_connection(conn_id)
        else:
            self.logger.debug("No timed-out connections to clean up")

    def get_connection_stats(self) -> Dict[str, object]:
        """Get connection statistics."""
        with self.lock:
            stats = {
                "total_connections": len(self.connections),
                "established_connections": len(
                    [
                        c
                        for c in self.connections.values()
                        if c.state == ConnectionState.ESTABLISHED
                    ]
                ),
                "closed_connections": len(
                    [
                        c
                        for c in self.connections.values()
                        if c.state == ConnectionState.CLOSED
                    ]
                ),
                "connection_ids": list(self.connections.keys()),
            }
            self.logger.debug(f"Connection stats: {stats}")
            return stats
