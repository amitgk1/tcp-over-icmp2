import argparse
import atexit
import ipaddress
import logging
import signal

from client import ClientPacketHandler
from logger import setup_logging
from server import ServerPacketHandler
from tunnel import PacketHandler, Tunnel

logger = logging.getLogger(__name__)


def parse_args():
    common_parser = Tunnel.generate_common_arg_parser()

    parser = argparse.ArgumentParser(
        description="TCP-over-ICMP Tunnel CLI APP",
        parents=[common_parser],
    )
    subparsers = parser.add_subparsers(
        dest="mode",
        required=True,
        help="Choose between 'server' or 'client'.",
    )
    server_parser = subparsers.add_parser(
        "server",
        parents=[common_parser],
        help="Run as the server (Proxy)",
    )
    server_parser.add_argument(
        "--client_ip",
        type=ipaddress.IPv4Address,
        required=True,
        help="The IP address of the client to connect to.",
    )
    client_parser = subparsers.add_parser(
        "client",
        parents=[common_parser],
        help="Run as the client",
    )
    client_parser.add_argument(
        "--server_ip",
        type=ipaddress.IPv4Address,
        required=True,
        help="The IP address of the server to connect to.",
    )

    parser.add_argument(
        "--log-level",
        choices=logging.getLevelNamesMapping().keys(),
        default="INFO",
        help="Set the logging level (default: INFO)",
    )
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    setup_logging(args.log_level)
    packet_handler: PacketHandler
    match args.mode:
        case "client":
            packet_handler = ClientPacketHandler(str(args.server_ip))
        case "server":
            packet_handler = ServerPacketHandler(str(args.client_ip))
        case _:
            raise ValueError("mode should only be 'server' or 'client'")

    tunnel = Tunnel(Tunnel.parser_args_to_tunnel_options(args), packet_handler)

    def cleanup(sig: int, frame):
        exit(0)

    atexit.register(packet_handler.cleanup)
    atexit.register(tunnel.cleanup)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cleanup)

    try:
        tunnel.start()
    except KeyboardInterrupt:
        pass
    except Exception:
        logger.exception("Unexpected Error")


if __name__ == "__main__":
    main()
