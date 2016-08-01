"""
The decrypt command. Accepts "ciphertext" and "key" parameters.

Accepts "ciphertext" and "key" parameters and calculates "plaintext" by performing a des_decrypt().
"""
from passlib.utils import des
from Crypto.Cipher import DES
import sys
import binascii
from itertools import cycle

from des_kpt.commands.Command import Command
from des_kpt.commands.ParseCommand import ParseCommand

__author__    = "David Hulton"
__license__   = "BSD"
__copyright__ = "Copyright 2016, David Hulton"

class DecryptCommand(ParseCommand):

    def __init__(self, argv):
        Command.__init__(self, argv, "cki", "");

    def execute(self):
        ciphertext = self._getCiphertext()
        key       = self._getKey()
        iv        = self._getIV()
        ci        = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(ciphertext, cycle(iv)))

        key_parity = des.expand_des_key(key)
        des_obj = DES.new(key_parity, DES.MODE_ECB)
        plaintext = des_obj.decrypt(ci)

        self._printParameters(plaintext, None, iv, None, ciphertext, ci, key, key_parity, False)

    def _getKey(self):
        key = self._getOptionValue("-k")

        if not key:
            self.printError("Missing key (-k)")

        key = binascii.unhexlify(key.replace(":", ""))

        if len(ley) == 8:
            key = self._removeParity(key)
        elif len(key) != 7:
            self.printError("Invalid key length %d" % len(key))

        return key

    def _getIV(self):
        iv = self._getOptionValue("-i")

        if not iv:
            iv = "00" * 8

        iv = binascii.unhexlify(iv.replace(":", ""))

        if len(iv) != 8:
            self.printError("Invalid IV length %d" % len(iv))

        return iv

    @staticmethod
    def printHelp():
        print(
"""Decrypts ciphertext with key and displays the plaintext output.

  decrypt

  Arguments:
    -c <ciphertext> : The ciphertext in hexidecimal format
    -k <key>        : The key in hexidecimal format
    -i <iv>         : The iv in hexidecimal format (optional)
""")

