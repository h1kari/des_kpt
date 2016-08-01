"""
The encrypt command. Accepts "plaintext" and "key" parameters.

Accepts "plaintext" and "key" parameters and calculates "ciphertext" by performing a des_encrypt().
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

class EncryptCommand(ParseCommand):

    def __init__(self, argv):
        Command.__init__(self, argv, "pki", "");

    def execute(self):
        plaintext = self._getPlaintext()
        key       = self._getKey()
        iv        = self._getIV()
        pi        = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(plaintext, cycle(iv)))

        key_parity = des.expand_des_key(key)
        des_obj = DES.new(key_parity, DES.MODE_ECB)
        ciphertext = des_obj.encrypt(pi)

        self._printParameters(plaintext, None, iv, pi, ciphertext, None, key, key_parity, True)

    def _getKey(self):
        key = self._getOptionValue("-k")

        if not key:
            self.printError("Missing key (-k)")

        key = binascii.unhexlify(key.replace(":", ""))

        if len(key) == 8:
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
"""Encrypts plaintext with key and displays the ciphertext output.

  encrypt

  Arguments:
    -p <plaintext> : The plaintext in hexidecimal format
    -k <key>       : The key in hexidecimal format
    -i <iv>        : The iv in hexidecimal format (optional)
""")

