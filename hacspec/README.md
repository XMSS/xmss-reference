# XMSS hacspec

hacspec is a specification language for crypto primitives [https://hacs-workshop.github.io/hacspec/](https://hacs-workshop.github.io/hacspec/).

Note: hacspec is still in development and might change. This works with the current release `hacspec-0.0.1.dev3`.

## Code
This folder contains all necessary code for `XMSS_SHA2_10_256`, SHA-256 in `sha256.py`, WOTS in `wots.py` and XMSS in `xmss.py`.
Each algorithm is acompanied by a short test file to check its correctness.

Note that the XMSS hacspec implementation currently only supports signature verification.

## Usage
Install hacspec:

    pip install hacspec

Run tests for primitives:

    python -O sha256_test.py
    python -O wots_test.py
    python -O xmss_test.py

The `-O` runs python in optimised mode and thus disables type checking. Running the tests without it will work as well but will take considerably longer.

Validity of the hacspec files can be checked as follows:

    hacspec-check sha256.py
    hacspec-check wots.py
    hacspec-check xmss.py

This checks that the specs don't use any python constructs that are not allowed in hacspec and provide proper typing.
