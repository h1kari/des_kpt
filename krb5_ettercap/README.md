krb5_ettercap
-------------

I've provided a couple of ettercap filters for downgrading kerberos to `des-cbc-crc`. Once `des-cbc-md5` support is added to `des_kpt`, it should be trival to change the python scripts to downgrade to `des-cbc-md5` instead, but it doesn't seem to be as common as `des-cbc-crc`.

It's recommended that you use the `*-asreq.*` scripts as they're the most reliable at this point.

The `*-preauth.*` scripts require adjusting the packet size which can cause issues with tcp MITM with ettercap and needs some more work.

**Running the downgrade attack**

First edit the `krb5-downgrade-asreq.sh` file to specify the `KDC`, `TARGET`, and `ETH` adapter:

```
$ vi krb5-downgrade-asreq.sh

...
export KDC="192.168.1.11"
export TARGET="192.168.1.27"
export ETH="enp0s3"
...
```

Then just run the script:

```
$ ./krb5-downgrade-asreq.sh
```

This will MITM the connection between the `KDC` and `TARGET` and replace the supported encryption types in all of the `TARGET` -> `KDC` `AS-REQ` packets with `des-cbc-crc` and should downgrade all encrypted communication (TGS, Authenticators, etc) to `des-cbc-crc` and log it to `/tmp/ettercap.pcap` which you can then use to crack using `des_kpt`:

```
$ cd ..
$ ./des_kpt.py kerb -i /tmp/ettercap.pcap
```

See `../README.md` for more detailed usage of `des_kpt.py`.
