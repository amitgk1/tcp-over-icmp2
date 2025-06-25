import argparse
import atexit
import signal
import sys
from typing import Optional

from tunnel_server import TunnelServer

from shared import setup_logging


class TunnelServerApp:
    """Main application class for the tunnel server."""

    def __init__(self, logger):
        self.logger = logger
        self.tunnel_server: Optional[TunnelServer] = None
        self.running = False

    def setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown."""

        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, shutting down...")
            self.cleanup()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        atexit.register(self.cleanup)

    def cleanup(self):
        """Clean up resources."""
        if self.running:
            self.running = False

            if self.tunnel_server:
                self.logger.info("Stopping tunnel server...")
                self.tunnel_server.stop()
                self.tunnel_server = None

    def run(self, listen_ip: str = "0.0.0.0", icmp_id: int = 12345):
        """Run the tunnel server."""
        try:
            self.logger.info("=" * 60)
            self.logger.info("TCP-over-ICMP Tunnel Server")
            self.logger.info("=" * 60)
            self.logger.debug(
                f"Starting tunnel server with listen_ip={listen_ip}, icmp_id={icmp_id}"
            )

            # Set up signal handlers
            self.logger.debug("Setting up signal handlers...")
            self.setup_signal_handlers()

            # Initialize tunnel server
            self.logger.info("Initializing tunnel server...")
            self.logger.debug(
                f"Creating TunnelServer with listen_ip={listen_ip}, icmp_id={icmp_id}"
            )
            self.tunnel_server = TunnelServer(
                listen_ip=listen_ip, icmp_id=icmp_id, logger=self.logger
            )

            self.running = True
            self.logger.debug("Tunnel server application is now running")

            self.logger.info("=" * 60)
            self.logger.info("Tunnel server is now active!")
            self.logger.info(f"Listening on: {listen_ip}")
            self.logger.info(f"ICMP ID: {icmp_id}")
            self.logger.info("=" * 60)
            self.logger.info("Waiting for client connections...")
            self.logger.info("Press Ctrl+C to stop the server")
            self.logger.info("=" * 60)

            # Start the server
            self.logger.debug("Starting tunnel server...")
            self.tunnel_server.start()

        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
        except Exception as e:
            self.logger.error(f"Error: {e}")
            sys.exit(1)
        finally:
            self.cleanup()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TCP-over-ICMP Tunnel Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Listen on all interfaces
  %(prog)s --ip 192.168.1.100        # Listen on specific IP
  %(prog)s --icmp-id 54321           # Use custom ICMP ID
  %(prog)s --log-level DEBUG         # Enable debug logging
        """,
    )

    parser.add_argument(
        "--ip",
        "-i",
        default="0.0.0.0",
        help="IP address to listen on (default: 0.0.0.0)",
    )

    parser.add_argument(
        "--icmp-id",
        "-id",
        type=int,
        default=12345,
        help="ICMP ID to use (default: 12345)",
    )

    parser.add_argument(
        "--log-level",
        "-l",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Log level (default: INFO)",
    )

    parser.add_argument("--log-file", help="Log file path (optional)")

    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    args = parser.parse_args()

    # Set up logging
    logger = setup_logging(
        name="tcp-over-icmp-server", level=args.log_level, log_file=args.log_file
    )

    # Validate arguments
    if not (1 <= args.icmp_id <= 65535):
        logger.error("ICMP ID must be between 1 and 65535")
        sys.exit(1)

    # Check if running as root (for raw socket access)
    try:
        import os

        if os.geteuid() != 0:
            logger.error("This script must be run as root or with sudo")
            logger.error("Usage: sudo uv run server")
            sys.exit(1)
    except AttributeError:
        # Windows or other non-Unix system
        pass

    # Run the application
    app = TunnelServerApp(logger)
    app.run(args.ip, args.icmp_id)


if __name__ == "__main__":
    main()
