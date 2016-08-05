"""
A class to encapsulate and parse a Kerberos Packet.
"""

import sys
import binascii
import base64
import datetime
from itertools import cycle

__author__    = "David Hulton"
__license__   = "BSD"
__copyright__ = "Copyright 2016, David Hulton"

class KerbPacket:

    def __init__(self, asn, src, dst, rep, cname, crealm, tname, trealm, enc, is_ticket, timestamp):
        self.asn    = asn 
        self.src    = src
        self.dst    = dst
        self.rep    = rep
        self.cname  = cname
        self.crealm = crealm
        self.tname  = tname
        self.trealm = trealm
        self.enc    = enc
        self.is_ticket = is_ticket
        self.mask   = str()
        self.timestamp = timestamp
        self.pt     = self._calcPT()

    def getServerAddress(self):
        return self.dst

    def getClientAddress(self):
        return self.src

    def getRep(self):
        return self.rep

    def getCRealm(self):
        return self.crealm

    def getCName(self):
        return self.cname

    def getTRealm(self):
        return self.trealm

    def getTName(self):
        return self.tname

    def getEnc(self):
        return self.enc

    def getIsTicket(self):
        return self.is_ticket

    def getCiphertext(self):
        return self.enc[16:24]

    def _getKPTAuth(self):
        kpt = str()

        now = datetime.datetime.utcfromtimestamp(self.timestamp)
        month = "%02d" % now.month
        kpt_str = "180f32303%s3%s3%s3%s" % (str(now.year)[2], str(now.year)[3], month[0], month[1])
        kpt = binascii.unhexlify(kpt_str)

        self.mask = binascii.unhexlify("ffffffffffffffff");

        return kpt

    def _getKPTTicket(self):
        # take encrypted length, subtract:
        #   Confounder   - 8
        #   CRC          - 4
        #   ASN.1 header - 3
        #   Padding      - 8
        # then mask off lower 3 bits to get known 5 bits
        enc_len = len(self.enc) & 0xff8
        enc_len_min = enc_len-23
        enc_len_max = enc_len-16

        # We'll figure out a way to gracefully create 2 tokens for cracking both cases in this situation, but for now throw an error
        if enc_len_max < 128:
            kpt_str  = "00a0070305000000"
            mask_str = "80ffffffffffff00"
        elif enc_len_min >= 256 and enc_len_max < 512:
            kpt_str  = "8200000a07030500"
            mask_str = "fffe000fffffffff"
        elif enc_len_min >= 128 and enc_len_max < 256:
            kpt_str  = "8180a00703050000"
            mask_str = "ff80ffffffffffff"
        else:
            raise ValueError("length of ticket creates unknown condition for predicting known plaintext.")

        kpt = binascii.unhexlify(kpt_str)
        self.mask = binascii.unhexlify(mask_str)

        return kpt

    def _getKPTTGS(self):
        # take encrypted length, subtract:
        #   Confounder   - 8
        #   CRC          - 4
        #   ASN.1 header - 3
        #   Padding      - 8
        # then mask off lower 3 bits to get known 5 bits
        enc_len = len(self.enc) & 0xff8
        enc_len_min = enc_len-23
        enc_len_max = enc_len-16

        # We'll figure out a way to gracefully create 2 tokens for cracking both cases in this situation, but for now throw an error
        if enc_len_max < 128:
            kpt_str  = "00a0133011a00302"
            mask_str = "80ffffffffffffff"
        elif enc_len_min >= 256 and enc_len_max < 512:
            kpt_str  = "820000a0133011a0"
            mask_str = "fffe000fffffffff"
        elif enc_len_min >= 128 and enc_len_max < 256:
            kpt_str  = "8180a0133011a003"
            mask_str = "ff80ffffffffffff"
        else:
            raise ValueError("length of ticket creates unknown condition for predicting known plaintext.")

        kpt = binascii.unhexlify(kpt_str)
        self.mask = binascii.unhexlify(mask_str)

        return kpt
        
    def _calcPT(self):
        c2 = self.enc[8:16]
        kpt = str()

        if self.rep == 10 or self.rep == 12:
            kpt = self._getKPTAuth()

        elif self.rep == 11 or self.rep == 13:
            if self.is_ticket:
                kpt = self._getKPTTicket()
            else:
                kpt = self._getKPTTGS()
        
        # pt = (c2 ^ kpt) & m
        c2_kpt = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(c2, kpt))
        pt     = ''.join(chr(ord(c1) & ord(c2)) for c1, c2 in zip(c2_kpt, self.mask))
        return pt

    def getPlaintext(self):
        return self.pt;

    def getMask(self):
        return self.mask;

    def getHash(self):
        return base64.b64encode("%s%s%s%s%s%s%s%s%d" % (self.src, self.dst, self.rep, self.cname, self.crealm, self.tname, self.trealm, self.enc, self.is_ticket));
