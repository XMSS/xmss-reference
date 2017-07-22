## XMSS reference code

This repository contains the reference implementation that accompanies the Internet Draft _"XMSS: Extended Hash-Based Signatures"_, [`draft-irtf-cfrg-xmss-hash-based-signatures`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/).

**Note:** while the behaviour of the code in this repository is supposed to be stable, the API will still vary. Notably, the current codebase does not account for the XDR definitions of the parameter sets as specified in the Internet Draft, but instead allows the user to set individual parameters.

_In this branch of the repository, we evaluate the use of parameters based on `#define` clauses. This trivially enables compile-time parameter sets (as is illustrated by the [params.h.py](params.h.py) file), but may also make it easier to create a wrapper that parses the XDR definitions. This is work in progress._
