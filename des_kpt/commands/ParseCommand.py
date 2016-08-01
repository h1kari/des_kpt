"""
The parse command.

"""
import base64
import sys
import binascii
from itertools import cycle

from des_kpt.commands.Command import Command

__author__    = "David Hulton"
__license__   = "BSD"
__copyright__ = "Copyright 2016, David Hulton"

class ParseCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "pmc", "e")

    def execute(self):
        plaintext  = self._getPlaintext()
        mask       = self._getMask()
        ciphertext = self._getCiphertext()
        encrypt    = self._getEncrypt()

        if encrypt:
            ciphertext = ''.join(chr(ord(c1) & ord(c2)) for c1, c2 in zip(ciphertext, cycle(mask)))
        else:
            plaintext = ''.join(chr(ord(c1) & ord(c2)) for c1, c2 in zip(plaintext, cycle(mask)))

        self._printParameters(plaintext, mask, None, None, ciphertext, None, None, None, encrypt)

    def _bin(self, s):
        return str(s) if s <=1 else bin(s>>1) + str(s&1)

    def _removeParity(self, parity_key):
        bits = bin(int(binascii.hexlify(parity_key), 16))[2:].rjust(64, "0")
        i = 0
        noparity = str()
        for bit in bits:
            if (i % 8) != 7:
                noparity = noparity + bit
            i = i + 1
        return binascii.unhexlify("%x" % int(noparity, 2))

    def _getPlaintext(self):
        plaintext = self._getOptionValue("-p")

        if not plaintext:
            self.printError("Missing plaintext (-p)")

        plaintext = binascii.unhexlify(plaintext.replace(":", ""))

        if len(plaintext) != 8:
            self.printError("Invalid plaintext length %d" % len(plaintext))

        return plaintext

    def _getMask(self):
        mask = self._getOptionValue("-m")

        if not mask:
            self.printError("Missing mask (-m)")

        mask = binascii.unhexlify(mask.replace(":", ""))

        if len(mask) != 8:
            self.printError("Invalid mask length %d" % len(mask))

        return mask

    def _getCiphertext(self):
        ciphertext = self._getOptionValue("-c")

        if not ciphertext:
            self.printError("Missing ciphertext (-c)")

        ciphertext = binascii.unhexlify(ciphertext.replace(":", ""))

        if len(ciphertext) != 8:
            self.printError("Invalid ciphertext length %d" % len(ciphertext))

        return ciphertext

    def _getEncrypt(self):
        return self._containsOption("-e")

    def _printParameters(self, plaintext, mask, iv, pi, ciphertext, ci, key, key_parity, encrypt):
        if plaintext is not None:
            print "                 PT = %s" % plaintext.encode("hex")
        if mask is not None:
            print "                  M = %s" % mask.encode("hex")
        if iv is not None:
            print "                 IV = %s" % iv.encode("hex")
        if pi is not None:
            print "              PT+IV = %s" % pi.encode("hex")
        if ciphertext is not None:
            print "                 CT = %s" % ciphertext.encode("hex")
        if ci is not None:
            print "              CT+IV = %s" % ci.encode("hex")
        if key is not None:
            print "                  K = %s" % key.encode("hex")

        if key is not None:
            print "                 KP = %s" % key_parity.encode("hex")

        if encrypt is not None:
            print "                  E = %d" % encrypt

        if plaintext is not None and mask is not None and ciphertext is not None:
            print "crack.sh Submission = $%s$%s" % ("97" if encrypt else "98", base64.b64encode("%s%s%s" % (plaintext, mask, ciphertext)))

    @staticmethod
    def printHelp():
        print(
"""Parses arguments and creates a crack.sh submission token.

  parse

  Arguments:
    -p <plaintext>  : The known plaintext value in hexidecimal format
    -m <mask>       : The known plaintext mask in hexidecimal format
    -c <ciphertext> : The known ciphertext value in hexidecimal format
""")
