"""Base class for commands.  Handles parsing supplied arguments."""

import getopt
import sys

__author__    = "David Hulton"
__license__   = "BSD"
__copyright__ = "Copyright 2016, David Hulton"

class Command:

    def __init__(self, argv, options, flags, allowArgRemainder=False):
        try:
            self.flags                     = flags
            self.options                   = ":".join(options) + ":"
            self.values, self.argRemainder = getopt.getopt(argv, self.options + self.flags)

            if not allowArgRemainder and self.argRemainder:
                self.printError("Too many arguments: %s" % self.argRemainder)
        except getopt.GetoptError as e:
            self.printError(e)

    def _getOptionValue(self, flag):
        for option, value in self.values:
            if option == flag:
                return value

        return None

    def _containsOption(self, flag):
        for option, value in self.values:
            if option == flag:
                return True

        return False

    def printError(self, error):
        sys.stderr.write("ERROR: %s\n" % error)
        sys.exit(-1)
