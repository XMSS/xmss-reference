## XMSS reference code

This repository contains the reference implementation that accompanies the Internet Draft _"XMSS: Extended Hash-Based Signatures"_, [`draft-irtf-cfrg-xmss-hash-based-signatures`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/).

This reference implementation supports all parameter sets as defined in the Draft at run-time (specified by prefixing the public and private keys with a 32-bit `oid`). Implementations that want to use compile-time parameter sets can remove the `struct xmss_params` function parameter.

_While the behavior of the code in this repository is supposed to be stable, the API is not yet fully complete. In particular, the wrapper for run-time parameters does not yet support the back-end functions that make use of BDS traversal (TODO). We will also add more extensive test functionality, making it easier to compare to other XMSS implementations (TODO)._

_When using the current code base, please be careful, expect changes and watch this document for further documentation._
