des_kpt
=======

This code allows you to submit known plaintext cracking jobs to the https://crack.sh DES cracking system by providing a way to verify your implementation matches and package up your job info into a token that can be submitted.

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

This is an example of a job that's performing a brute force decrypt (notice E = 0) and returns all keys that result in a `plaintext` which matches `x & M == PT`. Notice also that `PT` has been already masked by `M` as the masked out bits aren't needed.

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

In this case we're performing a brute force encrypt (notice E = 1) which will return all keys that result in a `ciphertext` which matches `x & M == CT`. Note also that `CT` has already been masked by `M` like `PT` is in decrypt mode.

Printed Parameters
------------------

| Parameter | Description |
| --------- | ----------- |
| `PT`      | Plaintext   |
| `M`       | Mask        |
| `IV`      | Initialization Vector, xor'ed with PT or CT depending on E |
| `PT+IV`   | PT xor'ed with IV |
| `CT`      | Ciphertext  |
| `CT+IV`   | CT xor'ed with IV |
| `K`       | 56-bit Key  |
| `KP`      | 64-bit Key with Parity |
| `E`       | 1 = Encrypt, 0 = Decrypt |


Bug tracker
-----------

Have a bug? Please create an issue here on GitHub!

https://github.com/h1kari/des_kpt/issues

Copyright
---------

Copyright 2016 David Hulton

Licensed under the BSD 3-Clause License: https://opensource.org/licenses/BSD-3-Clause
