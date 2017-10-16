CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -Wextra

all: test/test_wots \
test/test_xmss_core \
test/test_xmss_core_fast \
test/test_xmss \
test/test_xmssmt_core_fast \
test/test_xmssmt_core \
test/test_xmssmt

.PHONY: clean

test/test_wots: params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_commons.c test/test_wots.c params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss_commons.h
	$(CC) $(CFLAGS) params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_commons.c test/test_wots.c -o $@ -lcrypto -lm

test/test_xmss_core: params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c test/test_xmss_core.c params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core.h xmss_commons.h
	$(CC) $(CFLAGS) params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c test/test_xmss_core.c -o $@ -lcrypto -lm

test/test_xmss_core_fast: params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core_fast.c xmss_commons.c test/test_xmss_core_fast.c params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core_fast.h xmss_commons.h
	$(CC) $(CFLAGS) params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core_fast.c xmss_commons.c test/test_xmss_core_fast.c -o $@ -lcrypto -lm

test/test_xmssmt_core: params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c test/test_xmssmt_core.c params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core.h xmss_commons.h
	$(CC) $(CFLAGS) params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c test/test_xmssmt_core.c -o $@ -lcrypto -lm

test/test_xmssmt_core_fast: params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core_fast.c xmss_commons.c test/test_xmssmt_core_fast.c params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core_fast.h xmss_commons.h
	$(CC) $(CFLAGS) params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core_fast.c xmss_commons.c test/test_xmssmt_core_fast.c -o $@ -lcrypto -lm

test/test_xmss: params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c xmss.c test/test_xmss.c params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core.h xmss_commons.h xmss.h
	$(CC) $(CFLAGS) params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c xmss.c test/test_xmss.c -o $@ -lcrypto -lm

test/test_xmssmt: params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c xmss.c test/test_xmssmt.c params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core.h xmss_commons.h xmss.h
	$(CC) $(CFLAGS) params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c xmss.c test/test_xmssmt.c -o $@ -lcrypto -lm

clean:
	-rm test/test_wots
	-rm test/test_xmss_core
	-rm test/test_xmss_core_fast
	-rm test/test_xmss
	-rm test/test_xmssmt_core
	-rm test/test_xmssmt_core_fast
	-rm test/test_xmssmt
