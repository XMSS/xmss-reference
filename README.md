## XMSS reference code [![Build Status](https://travis-ci.org/XMSS/xmss-reference.svg?branch=master)](https://travis-ci.org/XMSS/xmss-reference)

This repository contains the reference implementation that accompanies [RFC 8391: _"XMSS: eXtended Merkle Signature Scheme"_](https://tools.ietf.org/html/rfc8391).

This reference implementation supports all parameter sets as defined in the RFC at run-time (specified by prefixing the public and private keys with a 32-bit `oid`). Implementations that want to use compile-time parameter sets can remove the `struct xmss_params` function parameter, and globally replace the use of its attributes by compile-time constants.

Please note that this reference implementation is **intended for cross-validation and experimenting**. Deploying cryptographic code in practice requires careful consideration of the specific deployment scenario and relevant threat model. This holds perhaps doubly so for stateful signature schemes such as XMSS.

_When using the current code base, please be careful, expect changes and watch this document for further documentation. In particular, `xmss_core_fast.c` is long due for a serious clean-up. While this will not change its public API or output, it may affect the storage format of the BDS state (i.e. part of the secret key)._

### Dependencies

For the SHA-2 hash functions (i.e. SHA-256 and SHA-512), we rely on OpenSSL. Make sure to install the OpenSSL development headers. On Debian-based systems, this is achieved by installing the OpenSSL development package `libssl-dev`.

### License

This reference implementation was written by Andreas Hülsing and Joost Rijneveld. All included code is available under the CC0 1.0 Universal Public Domain Dedication.
