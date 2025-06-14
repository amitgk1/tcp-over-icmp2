from collections import defaultdict
from typing import Any, DefaultDict, List, Optional, Tuple

from scapy.layers.inet import IP, BadFragments, _defrag_iter_and_check_offsets
from scapy.packet import Packet
from scapy.sessions import DefaultSession


def _fixed_defrag_ip_pkt(pkt, frags):
    """
    Defragment a single IP pkt.

    :param pkt: the new pkt
    :param frags: a defaultdict(list) used for storage
    :return: a tuple (fragmented, defragmented_value)
    """
    ip = pkt[IP]
    if pkt.frag != 0 or ip.flags.MF:
        # fragmented !
        uid = (ip.id, ip.src, ip.dst, ip.proto)
        if ip.len is None or ip.ihl is None:
            fraglen = len(ip.payload)
        else:
            fraglen = ip.len - (ip.ihl << 2)
        # (pkt, frag offset, frag len)
        frags[uid].append((pkt, ip.frag << 3, fraglen))
        if _check_no_more_frags(frags[uid]):  # no more fragments = last fragment
            curfrags = sorted(frags[uid], key=lambda x: x[1])  # sort by offset
            try:
                data = b"".join(_defrag_iter_and_check_offsets(curfrags))
            except ValueError:
                # bad fragment
                badfrags = frags[uid]
                del frags[uid]
                raise BadFragments(frags=badfrags)
            # re-build initial pkt without fragmentation
            p = curfrags[0][0].copy()
            pay_class = p[IP].payload.__class__
            p[IP].flags.MF = False
            p[IP].remove_payload()
            p[IP].len = None
            p[IP].chksum = None
            # append defragmented payload
            p /= pay_class(data)
            # cleanup
            del frags[uid]
            return True, p
        return True, None
    return False, pkt


def _check_no_more_frags(frags):
    first_pkt_found = None
    last_pkt_found = None

    for i, pkt_tuple in enumerate(frags):
        if pkt_tuple[1] == 0 and pkt_tuple[0][IP].flags.MF and first_pkt_found is None:
            first_pkt_found = i
        if not pkt_tuple[0][IP].flags.MF and last_pkt_found is None:
            last_pkt_found = i

        if (
            first_pkt_found is not None
            and last_pkt_found is not None
            and first_pkt_found != last_pkt_found
        ):
            return True
    return False


class FixedIPSession(DefaultSession):
    """Defragment IP packets 'on-the-flow'.

    Usage:
    >>> sniff(session=IPSession)
    """

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        DefaultSession.__init__(self, *args, **kwargs)
        self.fragments = defaultdict(
            list
        )  # type: DefaultDict[Tuple[Any, ...], List[Packet]]  # noqa: E501

    def process(self, pkt: Packet) -> Optional[Packet]:
        if not pkt:
            return None
        if IP not in pkt:
            return pkt
        return _fixed_defrag_ip_pkt(pkt, self.fragments)[1]  # type: ignore
