import argparse
import atexit
import signal
import sys
from typing import Optional

from iptables_manager import IptablesManager
from tunnel_client import TunnelClient

from shared import setup_logging


class TunnelClientApp:
    """Main application class for the tunnel client."""

    def __init__(self, logger):
        self.logger = logger
        self.iptables_mgr: Optional[IptablesManager] = None
        self.tunnel_client: Optional[TunnelClient] = None
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

            if self.tunnel_client:
                self.logger.info("Stopping tunnel client...")
                self.tunnel_client.stop()
                self.tunnel_client = None

            if self.iptables_mgr:
                self.logger.info("Cleaning up iptables rules...")
                self.iptables_mgr.cleanup()
                self.iptables_mgr = None

    def run(self, server_ip: str, proxy_port: int = 8080):
        """Run the tunnel client."""
        try:
            self.logger.info("=" * 60)
            self.logger.info("TCP-over-ICMP Tunnel Client")
            self.logger.info("=" * 60)
            self.logger.debug(
                f"Starting tunnel client with server_ip={server_ip}, proxy_port={proxy_port}"
            )

            # Set up signal handlers
            self.logger.debug("Setting up signal handlers...")
            self.setup_signal_handlers()

            # Initialize iptables manager
            self.logger.info("Setting up iptables rules...")
            self.logger.debug(f"Creating IptablesManager with proxy_port={proxy_port}")
            self.iptables_mgr = IptablesManager(
                proxy_port=proxy_port, logger=self.logger
            )
            self.iptables_mgr.setup()

            # Initialize tunnel client
            self.logger.info("Initializing tunnel client...")
            self.logger.debug(
                f"Creating TunnelClient with server_ip={server_ip}, proxy_port={proxy_port}"
            )
            self.tunnel_client = TunnelClient(
                server_ip=server_ip, proxy_port=proxy_port, logger=self.logger
            )

            self.running = True
            self.logger.debug("Tunnel client application is now running")

            self.logger.info("=" * 60)
            self.logger.info("Tunnel is now active!")
            self.logger.info(f"All TCP traffic is being redirected through ICMP tunnel")
            self.logger.info(f"Server: {server_ip}")
            self.logger.info(f"Proxy: 127.0.0.1:{proxy_port}")
            self.logger.info("=" * 60)
            self.logger.info("Press Ctrl+C to stop the tunnel")
            self.logger.info("=" * 60)

            # Start the tunnel
            self.logger.debug("Starting tunnel client...")
            self.tunnel_client.start()

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
        description="TCP-over-ICMP Tunnel Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100                    # Connect to server at 192.168.1.100
  %(prog)s 10.0.0.5 --port 9090            # Use custom proxy port 9090
  %(prog)s 192.168.1.100 --log-level DEBUG # Enable debug logging
        """,
    )

    parser.add_argument("server_ip", help="IP address of the tunnel server")

    parser.add_argument(
        "--port", "-p", type=int, default=8080, help="Local proxy port (default: 8080)"
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
        name="tcp-over-icmp-client", level=args.log_level, log_file=args.log_file
    )

    # Validate arguments
    if not (1 <= args.port <= 65535):
        logger.error("Port must be between 1 and 65535")
        sys.exit(1)

    # Check if running as root
    try:
        import os

        if os.geteuid() != 0:
            logger.error("This script must be run as root or with sudo")
            logger.error("Usage: sudo uv run client <server_ip>")
            sys.exit(1)
    except AttributeError:
        # Windows or other non-Unix system
        pass

    # Run the application
    app = TunnelClientApp(logger)
    app.run(args.server_ip, args.port)


if __name__ == "__main__":
    main()
