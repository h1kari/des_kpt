#!/usr/bin/env python

"""A tool for calculating known plaintext test vectors"""

import sys
from des_kpt.commands.HelpCommand import HelpCommand
from des_kpt.commands.EncryptCommand import EncryptCommand
from des_kpt.commands.DecryptCommand import DecryptCommand
from des_kpt.commands.ParseCommand import ParseCommand

__author__ = "David Hulton"
__license__ = "BSD"
__copyright__ = "Copyright 2016, David Hulton"

def main(argv):
    if len(argv) < 1:
        HelpCommand.printGeneralUsage("Missing command")

    if argv[0] == 'parse':
        ParseCommand(argv[1:]).execute()
    elif argv[0] == 'encrypt':
        EncryptCommand(argv[1:]).execute()
    elif argv[0] == 'decrypt':
        DecryptCommand(argv[1:]).execute()
    elif argv[0] == 'help':
        HelpCommand(argv[1:]).execute()
    else:
        HelpCommand.printGeneralUsage("Unknown command: %s" % argv[0])

if __name__ == '__main__':
    main(sys.argv[1:])
