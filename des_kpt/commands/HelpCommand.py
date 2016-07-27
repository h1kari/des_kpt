"""
The help command. Describes the usage of des_kpt
"""

import sys
from des_kpt.commands.EncryptCommand import EncryptCommand
from des_kpt.commands.DecryptCommand import DecryptCommand
from des_kpt.commands.ParseCommand import ParseCommand
from des_kpt.commands.KerbCommand import KerbCommand

__author__  = "David Hulton"
__license__ = "BSD"
__copyright__ = "Copyright 2016, David Hulton"

class HelpCommand:

    COMMANDS = {'parse' : ParseCommand, 'encrypt' : EncryptCommand, 'decrypt' : DecryptCommand, 'kerb' : KerbCommand}

    def __init__(self, argv):
        self.argv = argv

    def execute(self):
        if len(self.argv) <= 0:
            self.printGeneralUsage(None)
            return

        if self.argv[0] in HelpCommand.COMMANDS:
            HelpCommand.COMMANDS[self.argv[0]].printHelp()
        else:
            self.printGeneralUsage("Unknown command: %s" % self.argv[0])

    def printHelp(self):
        print(
            """Provides help for individual commands.

            help <command>
            """)

    @staticmethod
    def printGeneralUsage(message):
        if message:
            print ("Error: %s\n" % message)

        sys.stdout.write(
            """des_kpt.py
            
    Commands (use "des_kpt.py help <command>" to see more):
      parse   -p <plaintext> -m <mask> -c <ciphertext> [-e]
      encrypt -p <plaintext> -k <key> [-i <iv>]
      decrypt -c <ciphertext> -k <key> [-i <iv>]
      kerb    -i <input>
      help    <command>
""")

        sys.exit(-1)
