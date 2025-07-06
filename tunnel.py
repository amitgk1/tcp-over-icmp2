import argparse
import itertools
import logging
import threading
from abc import ABC, abstractmethod
from typing import Callable

from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet as NetfilterQueuePacket

from iptable_manager import (
    IPTablesManager,
    NetFilterQueueOptions,
    TunnelIPTablesRules,
    TunnelNetFilterQueueOptions,
)

logger = logging.getLogger(__name__)


def positive_int(value):
    """
    Custom type function for argparse to validate positive integers.
    """
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"'{value}' is an invalid positive int value")
    return ivalue


class PacketHandler(ABC):
    def __init__(self) -> None:
        self.seq_count = map(lambda x: x & 0xFFFF, itertools.count())

    @abstractmethod
    def get_rules(self) -> TunnelIPTablesRules:
        pass

    @abstractmethod
    def handle_tcp(self, nf_pkt: NetfilterQueuePacket) -> None:
        pass

    @abstractmethod
    def handle_icmp(self, nf_pkt: NetfilterQueuePacket) -> None:
        pass


class Tunnel:
    def __init__(
        self,
        tunnel_queue_options: TunnelNetFilterQueueOptions,
        packet_handler: PacketHandler,
    ) -> None:
        self.packet_handler = packet_handler
        self.queue_options = tunnel_queue_options
        self.iptables_manager = IPTablesManager(
            self.packet_handler.get_rules(), tunnel_queue_options
        )

    @staticmethod
    def generate_common_arg_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--tcp-thread-count",
            default=1,
            type=positive_int,
            help="How many concurrent threads and NFQUEUE binding to set for TCP traffic",
        )
        parser.add_argument(
            "--tcp-queue-size",
            default=1024,
            type=positive_int,
            help="sets the largest number of packets that can be in each TCP queue; new packets are dropped if the size of the queue reaches this number",
        )
        parser.add_argument(
            "--icmp-thread-count",
            default=1,
            type=positive_int,
            help="How many concurrent threads and NFQUEUE binding to set for ICMP traffic",
        )
        parser.add_argument(
            "--icmp-queue-size",
            default=1024,
            type=positive_int,
            help="sets the largest number of packets that can be in each ICMP queue; new packets are dropped if the size of the queue reaches this number",
        )
        return parser

    @staticmethod
    def parser_args_to_tunnel_options(args):
        tunnel_options = TunnelNetFilterQueueOptions(
            icmp=NetFilterQueueOptions(
                queue_number_range=range(args.icmp_thread_count),
                max_queue_size=args.icmp_queue_size,
            ),
            tcp=NetFilterQueueOptions(
                queue_number_range=range(
                    args.icmp_thread_count,
                    args.icmp_thread_count + args.tcp_thread_count,
                ),
                max_queue_size=args.tcp_queue_size,
            ),
        )
        logger.debug("parsed tunnel options: %s", tunnel_options)
        return tunnel_options

    def start(self):
        self.iptables_manager.start()

        icmp_threads = [
            threading.Thread(
                target=self._start_worker,
                args=(
                    q,
                    self.packet_handler.handle_icmp,
                    self.queue_options.icmp.max_queue_size,
                ),
                daemon=True,
            )
            for q in self.queue_options.icmp.queue_number_range
        ]
        tcp_threads = [
            threading.Thread(
                target=self._start_worker,
                args=(
                    q,
                    self.packet_handler.handle_tcp,
                    self.queue_options.tcp.max_queue_size,
                ),
                daemon=True,
            )
            for q in self.queue_options.tcp.queue_number_range
        ]

        for t in itertools.chain(icmp_threads, tcp_threads):
            t.start()
        logger.info("Tunnel is up!")

        # block until stopped
        for t in itertools.chain(icmp_threads, tcp_threads):
            t.join()
        logger.info("Tunnel is down.")

    def cleanup(self):
        self.iptables_manager.stop()

    def _start_worker(
        self,
        q_num: int,
        callback: Callable[[NetfilterQueuePacket], None],
        q_size: int,
    ):
        logger.debug("starting binding on q_num: %d with size %d", q_num, q_size)
        nf = NetfilterQueue()
        nf.bind(q_num, callback, max_len=q_size)
        try:
            nf.run()
        except KeyboardInterrupt:
            logger.debug("Ctrl+C pressed - Shutting down NFQUEUE %d thread")
        except Exception:
            logger.exception(
                "error on queue thread %d. This will cause dropped packets", q_num
            )
        finally:
            nf.unbind()
            logger.debug("unbind q_num: %d", q_num)
