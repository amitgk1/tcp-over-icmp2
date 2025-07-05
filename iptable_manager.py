from typing import NamedTuple

import iptc


class IPTableRule(NamedTuple):
    chain: str
    rule: iptc.Rule


class NetFilterQueueOptions(NamedTuple):
    queue_number_range: range
    max_queue_size: int


class TunnelNetFilterQueueOptions(NamedTuple):
    tcp: NetFilterQueueOptions
    icmp: NetFilterQueueOptions


class TunnelIPTablesRules(NamedTuple):
    tcp: IPTableRule
    icmp: IPTableRule


class IPTablesManager:
    def __init__(
        self,
        tunnel_rules: TunnelIPTablesRules,
        tunnel_queue_options: TunnelNetFilterQueueOptions,
    ) -> None:
        self.table = iptc.Table(iptc.Table.MANGLE)
        self.table.autocommit = False

        icmp_target = tunnel_rules.icmp.rule.create_target("NFQUEUE")
        if len(tunnel_queue_options.icmp.queue_number_range) > 1:
            icmp_target.set_parameter(
                "queue-balance",
                f"{tunnel_queue_options.icmp.queue_number_range.start}:{tunnel_queue_options.icmp.queue_number_range.stop - 1}",
            )
        else:
            icmp_target.set_parameter(
                "queue-num", str(tunnel_queue_options.icmp.queue_number_range.start)
            )

        tcp_target = tunnel_rules.tcp.rule.create_target("NFQUEUE")
        if len(tunnel_queue_options.tcp.queue_number_range) > 1:
            tcp_target.set_parameter(
                "queue-balance",
                f"{tunnel_queue_options.icmp.queue_number_range.stop}:{tunnel_queue_options.icmp.queue_number_range.stop + tunnel_queue_options.tcp.queue_number_range.stop - 1}",
            )
        else:
            tcp_target.set_parameter(
                "queue-num", str(tunnel_queue_options.icmp.queue_number_range.stop)
            )
        self.tunnel_rules = tunnel_rules

    def start(self):
        for chain, rule in self.tunnel_rules:
            c = iptc.Chain(self.table, chain)
            c.insert_rule(rule)
        self.table.commit()

    def stop(self):
        for chain, rule in reversed(self.tunnel_rules):
            c = iptc.Chain(self.table, chain)
            c.delete_rule(rule)
        self.table.commit()
