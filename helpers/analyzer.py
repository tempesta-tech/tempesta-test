"""
Instruments for network traffic analysis.
"""
from __future__ import print_function
import abc
import os
from threading import Thread
from time import sleep
from scapy.all import *
from . import remote, tf_cfg, error

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


class Sniffer(object, metaclass=abc.ABCMeta):
    def __init__(self, node, host, count=0,
                 timeout=30, ports=(80,),
                 node_close=True):
        self.node = node
        self.ports = ports
        self.thread = None
        self.captured = 0
        self.packets = []
        self.dump_file = '/tmp/tmp_packet_dump'
        str_ports = ' or '.join(('tcp port %s' % p) for p in ports)
        # TODO #120: it's bad to use timeout(1). Instead we should run
        # the tcpdump process and kill it when the test is done.
        cmd = 'timeout %s tcpdump -i any -n %s -w - %s || true'
        count_flag = ('-c %s' % count) if count else ''
        self.cmd = cmd % (timeout, count_flag, str_ports)
        self.err_msg = ' '.join(["Can't %s sniffer on", host])
        self.node_side_close = node_close

    def sniff(self):
        '''Thread function for starting system sniffer and saving
        its output. We need to use temporary file here, because
        scapy.sniff(offline=file_obj) interface does not support
        neither StringIO objects nor paramiko file objects.
        '''
        stdout, stderr = self.node.run_cmd(self.cmd, timeout=None,
                                           err_msg=(self.err_msg % 'start'))
        match = re.search(r'(\d+) packets captured', stderr.decode())
        if match:
            self.captured = int(match.group(1))
        with open(self.dump_file, 'wb') as f:
            f.write(stdout)

    def start(self):
        self.thread = Thread(target=self.sniff)
        self.thread.start()
        # TODO #120: the sniffer thread may not start with lower timeout like
        # 0.001, so we use longer timeout here. Instead we should check whether
        # the tcpdump process is running and wait for it otherwise.
        # See appropriate comments in remote.py and analyzer.py.
        sleep(0.1)

    def stop(self):
        if self.thread:
            self.thread.join()
            if os.path.exists(self.dump_file):
                self.packets = sniff(count=self.captured,
                                     offline=self.dump_file)
                os.remove(self.dump_file)
            else:
                error.bug('Dump file "%s" does not exist!' % self.dump_file)

    @abc.abstractmethod
    def check_results(self):
        """Analyzing captured packets. Should be called after start-stop cycle.
        Should be redefined in sublasses.
        """
        return True


class AnalyzerCloseRegular(Sniffer):

    def __init__(self, *args, **kwargs):
        Sniffer.__init__(self, *args, **kwargs)
        self.port = self.ports[0]

    def portcmp(self, packet, invert=False):
        if self.node_side_close and invert:
            return packet[TCP].dport == self.port
        elif self.node_side_close and not invert:
            return packet[TCP].sport == self.port
        elif not self.node_side_close and invert:
            return packet[TCP].sport == self.port
        else:
            return packet[TCP].dport == self.port

    def check_results(self):
        """Four-way (FIN-ACK-FIN-ACK) and
        three-way (FIN-ACK/FIN-ACK) handshake order checking.
        """
        if not self.packets:
            return False

        dbg_dump(5, self.packets, 'AnalyzerCloseRegular: FIN sequence:')

        count_seq = 0
        l_seq = 0
        for p in self.packets:
            if p[TCP].flags & RST:
                return False
            if count_seq >= 4:
                return False
            if count_seq == 0 and p[TCP].flags & FIN and self.portcmp(p):
                l_seq = p[TCP].seq + p[IP].len - p[IP].ihl * 4 \
                        - p[TCP].dataofs * 4
                count_seq += 1
                continue
            if count_seq == 1 and p[TCP].flags & ACK \
                    and self.portcmp(p, invert=True):
                if p[TCP].ack > l_seq:
                    count_seq += 1
            if count_seq == 2 and p[TCP].flags & FIN \
                    and self.portcmp(p, invert=True):
                l_seq = p[TCP].seq + p[IP].len - p[IP].ihl * 4 \
                        - p[TCP].dataofs * 4
                count_seq += 1
                continue
            if count_seq == 3 and p[TCP].flags & ACK and self.portcmp(p):
                if  p[TCP].ack > l_seq:
                    count_seq += 1

        if count_seq != 4:
            return False

        return True


class AnalyzerTCPSegmentation(Sniffer):
    """ Compare TCP segments generated by the original server with segments
    generated by Tempesta TLS: we should see not smaller TCP segments here.
    However, this shouldn't be strict - in some circumstances TCP/IP stack
    may split skbs in non optimal way. Probably the test must be relaxed in
    some sense.
    """

    def __init__(self, *args, **kwargs):
        Sniffer.__init__(self, *args, **kwargs)
        self.tfw_port = self.ports[0]
        self.srv_port = self.ports[1]
        self.srv_pkts = []
        self.tfw_pkts = []

    def check_results(self):
        res = True
        for p in self.packets:
            plen = p[IP].len - p[TCP].dataofs
            if p[TCP].sport == self.tfw_port:
                self.tfw_pkts += [int(plen)]
            elif p[TCP].sport == self.srv_port:
                self.srv_pkts += [int(plen)]
        (tfw_n, srv_n) = (len(self.tfw_pkts), len(self.srv_pkts))
        assert tfw_n and srv_n, "Traffic wasn't captured"
        assert tfw_n > 3, "Captured the number of packets less than" \
                          " the TCP/TLS overhead"
        if tfw_n > srv_n + 2:
            tf_cfg.dbg(4, "Tempesta TLS generates more packets (%d) than" \
                          " original server (%d) plus the TLS overhead (2 segs)"
                          % (tfw_n, srv_n))
            res = False
        # We're good if Tempesta generates less number of packets than
        # the server. We skip the initial TCP SYN-ACK, and the TLS 1.2
        # 2-RTT handshake overhead. This may fail for TLS 1.3.
        for i in range(3, tfw_n):
            if i - 2 >= srv_n:
                tf_cfg.dbg(4, "Extra packet %d, size=%d"
                              % (i, self.tfw_pkts[i]))
                res = False
            elif self.tfw_pkts[i] < self.srv_pkts[i - 2]:
                tf_cfg.dbg(4, "Tempesta packet %d less than server's" \
                               " (%d < %d)"
                               % (i, self.tfw_pkts[i], self.srv_pkts[i]))
                res = False
        if not res:
            tf_cfg.dbg(2, "Tempesta segments: %s\nServer segments: %s"
                       % (str(self.tfw_pkts), str(self.srv_pkts)))
        return res


def dbg_dump(level, packets, msg):
    if tf_cfg.v_level() >= level:
        print(msg, file=sys.stderr)
        for p in packets:
            print(p.show(), file=sys.stderr)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
