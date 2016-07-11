CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -Wextra

all: test/test_wots \
test/test_xmss \
test/test_xmss_fast \
test/test_xmssmt_fast \
test/test_xmssmt

test/test_wots: hash.c hash_address.c randombytes.c wots.c xmss_commons.c test/test_wots.c hash.h hash_address.h randombytes.h wots.h xmss_commons.h 
	$(CC) $(CFLAGS) hash.c hash_address.c randombytes.c wots.c xmss_commons.c test/test_wots.c -o $@ -lcrypto -lm
	
test/test_xmss: hash.c hash_address.c randombytes.c wots.c xmss.c xmss_commons.c test/test_xmss.c hash.h hash_address.h randombytes.h wots.h xmss.h xmss_commons.h 
	$(CC) $(CFLAGS) hash.c hash_address.c randombytes.c wots.c xmss.c xmss_commons.c test/test_xmss.c -o $@ -lcrypto -lm

test/test_xmss_fast: hash.c hash_address.c randombytes.c wots.c xmss_fast.c xmss_commons.c test/test_xmss_fast.c hash.h hash_address.h randombytes.h wots.h xmss_fast.h xmss_commons.h
	$(CC) $(CFLAGS) hash.c hash_address.c randombytes.c wots.c xmss_fast.c xmss_commons.c test/test_xmss_fast.c -o $@ -lcrypto -lm

test/test_xmssmt: hash.c hash_address.c randombytes.c wots.c xmss.c xmss_commons.c test/test_xmssmt.c hash.h hash_address.h randombytes.h wots.h xmss.h xmss_commons.h 
	$(CC) $(CFLAGS) hash.c hash_address.c randombytes.c wots.c xmss.c xmss_commons.c test/test_xmssmt.c -o $@ -lcrypto -lm
	
test/test_xmssmt_fast: hash.c hash_address.c randombytes.c wots.c xmss_fast.c xmss_commons.c test/test_xmssmt_fast.c hash.h hash_address.h randombytes.h wots.h xmss_fast.h xmss_commons.h
	$(CC) $(CFLAGS) hash.c hash_address.c randombytes.c wots.c xmss_fast.c xmss_commons.c test/test_xmssmt_fast.c -o $@ -lcrypto -lm

.PHONY: clean

clean:
	-rm *.o *.s
	-rm test/test_wots
	-rm test/test_xmss
	-rm test/test_xmss_fast
	-rm test/test_xmssmt
	-rm test/test_xmssmt_fast


