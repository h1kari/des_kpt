"""
The parse command.

"""
import base64
import sys
import binascii
from itertools import cycle

from des_kpt.commands.Command import Command
from des_kpt.commands.ParseCommand import ParseCommand
from des_kpt.readers.KerbPacketReader import KerbPacketReader
#from des_kpt.state.MultiKerbStateManager import MultiKerbStateManager

__author__    = "David Hulton"
__license__   = "BSD"
__copyright__ = "Copyright 2016, David Hulton"

class KerbCommand(ParseCommand):

    def __init__(self, argv):
        Command.__init__(self, argv, "i", "")

    def execute(self):
        inputFile  = self._getInputFile()
        capture    = open(inputFile)
        reader     = KerbPacketReader(capture)
        print "parsing inputFile = %s\n" % inputFile

        msg_type    = range(0, 14)
        ticket_type = range(0, 14)
        client_type = range(0, 14)

        msg_type[10]    = "AS-REQ"
        msg_type[11]    = "AS-REP"
        msg_type[12]    = "TGS-REQ"
        msg_type[13]    = "TGS-REP"

        ticket_type[10] = "Authenticator"
        ticket_type[11] = "Ticket Granting Ticket"
        ticket_type[12] = "Ticket Granting Ticket"
        ticket_type[13] = "Service Ticket"

        client_type[10] = "Authenticator"
        client_type[11] = "enc-part"
        client_type[12] = "Authenticator"
        client_type[13] = "enc-part"

        for packet in reader:
            rep = packet.getRep()
            desc = ticket_type[rep] if packet.getIsTicket() else client_type[rep]
            print "%s %s -> %s: %s@%s -> %s@%s (%s):" % (
                msg_type[packet.getRep()],
                packet.getServerAddress(),
                packet.getClientAddress(),
                packet.getCName(), packet.getCRealm(),
                packet.getTName(), packet.getTRealm(),
                desc)
            self._printParameters(packet.getPlaintext(),
                packet.getMask(), None, None,
                packet.getCiphertext(), None, None, None, 0)
            print ""

    def _getInputFile(self):
        inputFile = self._getOptionValue("-i");

        if not inputFile:
            self.printError("Missing input file (-i)");

        return inputFile

    @staticmethod
    def printHelp():
        print(
"""Extracts info from PCAP file containing a Kerberos authentication and creates a crack.sh submission token.

  kerb 

  Arguments:
    -i <input> : The capture file
""")
