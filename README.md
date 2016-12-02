des_kpt
=======

This code allows you to submit known plaintext cracking jobs to the https://crack.sh DES cracking system by providing a way to verify your implementation matches and package up your job info into a token that can be submitted.

Ubuntu Install Notes
--------------------

To install all of the dependencies on Ubuntu, run the following commands:

```
$ sudo apt-get install python-pyasn1
$ git clone https://github.com/CoreSecurity/impacket
$ cd impacket
$ sudo python setup.py install
```

Verifying Encryption
--------------------

To verify your implementation you can use the `encrypt` command:

```
$ ./des_kpt.py encrypt -p 0000000000000000 -k 1044ca254cddc4 -i 0123456789abcdef
                 PT = 0000000000000000
                 IV = 0123456789abcdef
              PT+IV = 0123456789abcdef
                 CT = 825f48ccfd6829f0
                  K = 1044ca254cddc4
                 KP = 1023324554677689
                  E = 1
```

This command allows you to specify the `plaintext`, `key`, and optional `iv` (in the case of cracking CBC/PCBC encrypted data).

Verifying Decryption
--------------------

You can also verify using the `decrypt` command:

```
$ ./des_kpt.py decrypt -c 837c0dab74c3e41f -k 1044ca254cddc4 -i 0123456789abcdef
                 PT = 0123456789abcdef
                 IV = 0123456789abcdef
                 CT = 837c0dab74c3e41f
              CT+IV = 825f48ccfd6829f0
                  K = 1044ca254cddc4
                 KP = 1023324554677689
                  E = 0
```

This allows you to specify the `ciphertext`, `key`, and optional `iv` (in the case of cracking CFB, OFB, CTR, etc). Keep in mind that in these different modes the `iv` is counted as the value that's XORed with the `ciphertext`, not the IV that is used as the plaintext input to des_encrypt().

**NOTE:** When you enter an 8-byte key, `des_kpt.py` will remove parity from the key and then recalculate parity to generate `K` and `KP`. If `KP` doesn't match the key you specified, it's probably because the parity is being corrected.

Submit a Decrypt Job
----------------------

Now, once you've verified your implementation matches, you can submit your job to https://crack.sh. To do that, enter in your parameters using the `parse` command:

```
$ ./des_kpt.py parse -p 0123456789abcdef -m ffffffffffff0000 -c 825f48ccfd6829f0
                 PT = 0123456789ab0000
                  M = ffffffffffff0000
                 CT = 825f48ccfd6829f0
                  E = 0
crack.sh Submission = $98$ASNFZ4mrze////////8AAIJfSMz9aCnw
```

This is an example of a job that's performing a brute force decrypt (notice `E = 0`) and returns all keys that result in a `plaintext` which matches `x & M == PT`. Notice also that `PT` has been already masked by `M` as the masked out bits aren't needed.

Submit an Encrypt Job
----------------------

Here is another example:

```
$ ./des_kpt.py parse -p 0123456789abcdef -m ffffffffffff0000 -c 825f48ccfd6829f0 -e
                 PT = 0123456789abcdef
                  M = ffffffffffff0000
                 CT = 825f48ccfd680000
                  E = 1
crack.sh Submission = $97$ASNFZ4mrze////////8AAIJfSMz9aAAA
```

In this case we're performing a brute force encrypt (notice `E = 1`) which will return all keys that result in a `ciphertext` which matches `x & M == CT`. Note also that `CT` has already been masked by `M` like `PT` is in decrypt mode.

**NOTE:** Results from crack.sh are 7-byte (56-bit) keys without parity. You can use `des_kpt.py encrypt` or `decrypt` to add parity to the key if needed.

Kerberos
--------

To crack kerberos exchanges, simply point the tool toward a .pcap file containing kerberos5 AS-REQ, AS-REP, TGS-REQ, or TGS-REP messages:

```
$ ./des_kpt.py kerb -i kerb.pcap
parsing inputFile = kerb.pcap

AS-REQ 192.168.1.11 -> 192.168.1.27: test3@DOMAIN -> krbtgt/DOMAIN@DOMAIN (Authenticator):
                 PT = 37008d069d43a296
                  M = ff00ffffffffffff
                 CT = de3dcc5ca0bb182f
                  E = 0
crack.sh Submission = $98$NwCNBp1Dopb/AP///////949zFyguxgv
...
```

This option extracts the encrypted data from the kerberos5 messages and assembles a submission token using static known plaintext for the messages. These are the values that it extracts:

```
AS-REQ ::= [APPLICATION 10] KDC-REQ
TGS-REQ ::= [APPLICATION 12] KDC-REQ
KDC-REQ ::= SEQUENCE {
    pvno[1]     INTEGER,
    msg-type[2] INTEGER,
    # Contains encapsulated AP-REQ (for TGS-REQ) or Authenticator (for AS-REQ)
    padata[3]   SEQUENCE OF PA-DATA OPTIONAL,
    req-body[4] KDC-REQ-BODY
}

AS-REP ::= [APPLICATION 11] KDC-REP
TGS-REP ::= [APPLICATION 13] KDC-REP
KDC-REP ::= SEQUENCE {
    pvno[0]             INTEGER,
    msg-type[1]         INTEGER,
    padata[2]           SEQUENCE OF PA-DATA OPTIONAL,
    crealm[3]           Realm,
    cname[4]            PrincipalName,
    # Contains TGT (for AS-REP) or ST (for TGS-REP)
    ticket[5]           Ticket,     -- Ticket
    # Contains encrypted session key data
    enc-part[6]         EncryptedData   -- EncKDCRepPart
}

# padata in AS-REQ or TGS-REQ Packet
PA-DATA ::= SEQUENCE {
    # == PA_TGS_REQ (TGS-REQ TGT) or == PA_ENC_TIMESTAMP (AS-REQ Authenticator)
    padata-type[1]  INTEGER,
    pa-data[2]  OCTET STRING -- might be encoded AP-REQ
}

# For padata-type == PA_TGS_REQ (TGS-REQ TGT)
AP-REQ ::= [APPLICATION 14] SEQUENCE {
    pvno[0]             INTEGER,
    msg-type[1]         INTEGER,
    ap-options[2]       APOptions,
    # TGT
    ticket[3]           Ticket,
    # Authenticator encrypted with client session key
    authenticator[4]    EncryptedData   -- Authenticator
}

# Ticket in encapsulated AP-REQ in TGS-REQ
Ticket ::=  [APPLICATION 1] SEQUENCE {
    tkt-vno[0]  INTEGER,
    realm[1]    Realm,
    sname[2]    PrincipalName,
    # TGT encrypted with KDC's master key
    enc-part[3] EncryptedData   -- EncTicketPart
}

# Actual encrypted data is associated with etype and optional kvno
EncryptedData ::=   SEQUENCE {
    # We check to see if etype == DES_CBC_CRC (1)
    etype[0]    INTEGER, -- EncryptionType
    kvno[1]     INTEGER OPTIONAL,
    # Actual ciphertext
    cipher[2]   OCTET STRING -- CipherText
}
```

| Packet    | Ciphertext                                  | Type          | Key                | Contains                   |
| --------- | ------------------------------------------- | ------------- | ------------------ | -------------------------- |
| `AS-REQ`  | `padata[PA_ENC_TIMESTAMP].cipher`           | Authenticator | Client Master      | Timestamp                  |
| `AS-REP`  | `ticket.enc-part.cipher`                    | TGT           | KDC Master         | KDC/Client Session Key     |
| `AS-REP`  | `enc-part.cipher`                           | TGS enc-part  | Client Master      | KDC/Client Session Key     |
| `TGS-REQ` | `padata[PA_TGS_REQ].ticket.enc-part.cipher` | TGT           | KDC Master         | KDC/Client Session Key     | 
| `TGS-REQ` | `padata[PA_TGS_REQ].authenticator.cipher`   | Authenticator | KDC/Client Session | Timestamp                  |
| `TGS-REP` | `ticket.enc-part.cipher`                    | ST            | Service Master     | Service/Client Session Key |
| `TGS-REP` | `enc-part.cipher`                           | TGS enc-part  | KDC/Client Session | Service/Client Session Key |

Determining Plaintext
---------------------

The ASN.1 format of the messages that are encrypted has a number of known plaintext components as DER is a canonical form of BER there are certain parts of the format that must always exist in the plaintext. Here is an outline of the plaintext for the different encrypted portions:

**Authenticator**

```
00: 7aec 646d 6134 d6e1  z.dma4.. # P1 - Confounder
08: 230f af7a 301a a011  #..z0... # P2 - [8:12] = CRC, [12:16] = ASN.1
                                  #      30 - Sequence(
                                  #      1a -   Length=26)
                                  #      a0 - .Idx(0,
                                  #      11 -   Length=17,
10: 180f 3230 3136 3037  ..201607 # P3 - ASN.1                          # Static
                                  #      18 -   GeneralizedTime(        # Static
                                  #      0f -     Length=15, Value=     # Static
                                  #      323031363037 - "201607"        # Easily derived from current year/month
18: 3231 3230 3138 3335  21201835 # P4 - ASN.1
                                  #      3231323031383335 - "21201835"
20: 5aa1 0502 030c 85ba  Z....... # P5 - ASN.1
                                  #      5a -     "Z")),
                                  #      a1 - .Idx(1,
                                  #      05 -   Length=5,
                                  #      02 -   Integer(
                                  #      03 -     Length=3,
                                  #      0c85ba - Value=820666)
```

We've identified the 3rd block of Plaintext `P3` as the one we're going to target. Because everything is encrypted with DES-CBC, it will be xor'ed with the Ciphertext of the previous block, so to determine our plaintext we'll do:

```
PT = CT2 ^ "\x18\x0f"+date("YYYYMM")
CT = CT3
M  = ffffffffffffffff
```

If you're iffy on the exact month that the server/client have their clock set to, you can adjust the mask so the job works regardless:

```
M  = ffffffffffffff00
```

**Tickets (TGT or ST)**

```
00: 194c b18f 1b9c ebf7  .L...... # P1 - Confounder
08: 0600 7f55 6381 d630  ...Uc..0 # P2 - [8:12] = CRC, [12:16] = ASN.1
                                  #      63 - Application(Tag=3,
                                  #      81d6 - Length=214)
                                  #      30 -   .Sequence(
10: 81d3 a007 0305 0000  ........ # P3 - ASN.1
                                  #      81d3 -   Length=211)           # Mostly determined from the encrypted data size (adjust mask for padding)
                                  #      a0 -     .Idx(0,               # Static
                                  #      07 -       Length=7)           # Static
                                  #      03 -       .BitString(         # Static
                                  #      05 -         Length=5, Value=  # Static
                                  #      0000 -       "\x00\x00"...     # Static (I think)
...
```

It's pretty safe to assume that `P3` will be mostly static, the overall length of the message will change (and can be roughly determined by the encrypted message size) but the ASN.1 will stay the same. The following shows the rough calculation of PT for messages where the .Length value is between 128 and 255. The PT ASN.1 should be generated according to the actual enc-part length. To stay on the safe side, we currently only support message sizes between 128-256 and just use the top length bit as known plaintext (as it should always be high when the length extension is set to 81).

```
PT = CT2 ^ "\x81"+len(enc-part)-15-8+"\xa0\x07\x03\x05\x0000"
CT = CT3
M  = ff80ffffffffffff
```

**TGS enc-part**

```
00: e293 cade 03ca 8663  .......c # P1 - Confounder
08: 9b78 56e2 7a81 f030  .xV.z..0 # P2 - [8:12] = CRC, [12:16] = ASN.1
                                  #      7a - Application(Tag=26,
                                  #      81f0 - Length=240)
                                  #      30 -   .Sequence(
10: 81ed a013 3011 a003  ....0... # P3 - ASN.1
                                  #      813d     Length=237)           # Mostly determined from the encrypted data size (adjust mask for padding)
                                  #      a0       .Idx(0,               # Static
                                  #      13         Length=19)          # Static
                                  #      30         .Sequence(          # Static
                                  #      11           Length=17)        # Static
                                  #      a0           .Idx(0,           # Static
                                  #      03             Length=3)       # Static
...
```

Same for this message, the only dynamic part of `P3` is the length which can be roughly determined based on the enc-part length:

```
PT = CT2 ^ "\x81"+len(enc-part)-15-8+"\xa0\x13\x30\x11\xa0\x03"
CT = CT3
M  = ff80ffffffffffff
```

**DES-CBC-MD5?**

Note that all of these techniques can be easily adapted to work against DES-CBC-MD5. The only differnce is that the checksum is 8 bytes instead of 4 bytes with DES-CBC-CRC which then pushes the ASN.1 over. There's relatively the same amount of known plaintext to work with in both cases and support will be added in the near future.

Printed Parameters
------------------

| Parameter | Description                                                       |
| --------- | ----------------------------------------------------------------- |
| `PT`      | Plaintext                                                         |
| `M`       | Mask                                                              |
| `IV`      | Initialization Vector, xor'ed with `PT` or `CT` depending on `E`  |
| `PT+IV`   | `PT` xor'ed with `IV`                                             |
| `CT`      | Ciphertext                                                        |
| `CT+IV`   | `CT` xor'ed with `IV`                                             |
| `K`       | 56-bit Key                                                        |
| `KP`      | 64-bit Key with Parity                                            |
| `E`       | 1 = Encrypt, 0 = Decrypt                                          |

Bug tracker
-----------

Have a bug? Please create an issue here on GitHub!

https://github.com/h1kari/des_kpt/issues

Copyright
---------

Copyright 2016 David Hulton

Licensed under the BSD 3-Clause License: https://opensource.org/licenses/BSD-3-Clause
