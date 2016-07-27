"""
Base packet reader implementation.  Will iterate over packets
specified by a subclass.
"""

import dpkt

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class PacketReader:

    def __init__(self, capture):
        self.capture = capture
        self.reader  = dpkt.pcap.Reader(capture)
        self.seen = {}

    def __iter__(self):
        for timestamp, data in self.reader:
            packets = self._parseForTargetPacket(data)

            if packets:
                packet1, packet2 = packets

                if packet1 is not None:
                    if packet1.getHash() not in self.seen:
                        yield packet1
                    self.seen[packet1.getHash()] = 1

                if packet2 is not None:
                    if packet2.getHash() not in self.seen:
                        yield packet2
                    self.seen[packet2.getHash()] = 1

    def _parseForTargetPacket(self, data):
        assert False
