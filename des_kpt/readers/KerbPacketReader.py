"""
Given a packet capture, this class will iterate over
the Kerberos packets in that capture.
"""

from des_kpt.packets.KerbPacket import KerbPacket
from des_kpt.readers.PacketReader import PacketReader
from pyasn1.codec.ber import decoder
from pyasn1.type import univ
from impacket.krb5.asn1 import AS_REQ, AP_REQ, TGS_REQ, AS_REP, AP_REP, TGS_REP, EncryptedData
from impacket.krb5 import constants
from impacket.krb5.crypto import Enctype

__author__    = "David Hulton"
__license__   = "BSD"
__copyright__ = "Copyright 2016, David Hulton"

import socket
import dpkt

class KerbPacketReader(PacketReader):

    def __init__(self, capture):
        PacketReader.__init__(self, capture)

    def _getPrinc(self, princ):
        if princ is None:
            return None

        ns = princ['name-string']

        try:
            return ns[0] +"/"+ ns[1]
        except:
            return ns[0]

    def _parseForREQ(self, asn_data, ip_packet):
        # decode data just to parse to see if it's a KDC_REQ packet
        try:
            asn = decoder.decode(asn_data)[0]
            if asn[0] != 5:
                return None
        except:
            return None

        # check to see if it's an AS_REQ or TGS_REQ
        if asn[1] != constants.ApplicationTagNumbers.AS_REQ.value and asn[1] != constants.ApplicationTagNumbers.TGS_REQ.value:
            return None

        # try decoding (both AS_REQ and TGS_REQ are KDC_REQ packets)
        try:
            req = decoder.decode(asn_data, asn1Spec = AS_REQ())[0]
        except:
            req = decoder.decode(asn_data, asn1Spec = TGS_REQ())[0]

        crealm = req['req-body']['realm']
        cname  = self._getPrinc(req['req-body']['cname'])
        trealm = req['req-body']['realm']
        tname  = self._getPrinc(req['req-body']['sname'])

        for padata in req['padata']:
            # extract encrypted authenticators from AS_REQ packets
            if padata['padata-type'] == constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value:
                auth = decoder.decode(padata['padata-value'], asn1Spec = EncryptedData())[0]
                if auth['etype'] == Enctype.DES_CRC:
                    cenc = str(auth['cipher'])

            # extract encrypted ticket data from TGS_REQ packets
            if padata['padata-type'] == constants.PreAuthenticationDataTypes.PA_TGS_REQ.value:
                asn1 = decoder.decode(padata['padata-value'])[0]

                if asn1[0] != 5 or asn1[1] != 14:
                    return None

                ap = decoder.decode(padata['padata-value'], asn1Spec = AP_REQ())[0]
                trealm = ap['ticket']['realm']
                tname  = self._getPrinc(ap['ticket']['sname'])
                
                if ap['authenticator']['etype'] == Enctype.DES_CRC:
                    cenc = str(ap['authenticator']['cipher'])

                if ap['ticket']['enc-part']['etype'] == Enctype.DES_CRC:
                    tenc = str(ap['ticket']['enc-part']['cipher'])

        try:
            tenc_packet = KerbPacket(asn,
                socket.inet_ntoa(ip_packet.src),
                socket.inet_ntoa(ip_packet.dst), asn[1],
                cname, crealm, tname, trealm, tenc, 1)
        except:
            tenc_packet = None

        try:
            cenc_packet = KerbPacket(asn,
                socket.inet_ntoa(ip_packet.src),
                socket.inet_ntoa(ip_packet.dst), asn[1],
                cname, crealm, tname, trealm, cenc, 0)
        except:
            cenc_packet = None

        return tenc_packet, cenc_packet

                

    def _parseForREP(self, asn_data, ip_packet):
        # check to see if it's KRB packet
        try:
            asn = decoder.decode(asn_data)[0]
            if asn[0] != 5:
                return None
        except:
            return None

        # check to see if it's an AS_REP or TGS_REP
        if asn[1] != constants.ApplicationTagNumbers.AS_REP.value and asn[1] != constants.ApplicationTagNumbers.TGS_REP.value:
            return None

        # try decoding (both AS_REP and TGS_REP are KDC_REP packets)
        try:
            rep = decoder.decode(asn_data, asn1Spec = AS_REP())[0]
        except:
            rep = decoder.decode(asn_data, asn1Spec = TGS_REP())[0]


        crealm = rep['crealm']
        cname  = self._getPrinc(rep['cname'])
        trealm = rep['ticket']['realm']
        tname  = self._getPrinc(rep['ticket']['sname'])

        if rep['ticket']['enc-part']['etype'] == Enctype.DES_CRC:
            tenc   = str(rep['ticket']['enc-part']['cipher'])

        if rep['enc-part']['etype'] == Enctype.DES_CRC:
            cenc   = str(rep['enc-part']['cipher'])

        try:
            tenc_packet = KerbPacket(asn,
                socket.inet_ntoa(ip_packet.src),
                socket.inet_ntoa(ip_packet.dst), asn[1],
                cname, crealm, tname, trealm, tenc, 1)
        except:
            tenc_packet = None

        try:
            cenc_packet = KerbPacket(asn,
                socket.inet_ntoa(ip_packet.src),
                socket.inet_ntoa(ip_packet.dst), asn[1],
                cname, crealm, tname, trealm, cenc, 0)
        except:
            cenc_packet = None

        return tenc_packet, cenc_packet

    def _parseForTargetPacket(self, data):
        eth_packet = dpkt.ethernet.Ethernet(data)

        if isinstance(eth_packet.data, dpkt.ip.IP):
            ip_packet = eth_packet.data

            # check to see if packet is an AS-REP or TGS-REP
            asn_data = None
            test_rep = False
            test_req = False
            if ip_packet.get_proto(ip_packet.p) == dpkt.tcp.TCP and hasattr(ip_packet.data, 'data'):
                tcp_packet = ip_packet.data
                asn_data = tcp_packet.data[4:]

                if tcp_packet.sport == 88:
                    test_rep = True
                elif tcp_packet.dport == 88:
                    test_req = True

            if ip_packet.get_proto(ip_packet.p) == dpkt.udp.UDP and hasattr(ip_packet.data, 'data'):
                udp_packet = ip_packet.data
                asn_data = udp_packet.data

                if udp_packet.sport == 88:
                    test_rep = True
                elif udp_packet.dport == 88:
                    test_req = True

            if test_rep:
                return self._parseForREP(asn_data, ip_packet)

            if test_req:
                return self._parseForREQ(asn_data, ip_packet)

        return None


