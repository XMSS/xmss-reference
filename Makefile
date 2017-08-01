CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -Wextra

all: test/test_wots \
test/test_xmss_core_XMSS_SHA2-256_W16_H10 \
test/test_xmss_core_fast_XMSS_SHA2-256_W16_H10 \
test/test_xmssmt_core_fast_XMSSMT_SHA2-256_W16_H20_D4 \
test/test_xmssmt_core_XMSSMT_SHA2-256_W16_H20_D4 \

.PHONY: clean
.PRECIOUS: params_%.h

params_%.h: params.h.py
	python3 params.h.py $(patsubst params_%.h,%,$@) > $@

test/test_wots: params_XMSS_SHA2-256_W16_H10.h hash.c fips202.c hash_address.c randombytes.c wots.c xmss_commons.c test/test_wots.c hash.h fips202.h hash_address.h randombytes.h wots.h xmss_commons.h
	ln -sf params_XMSS_SHA2-256_W16_H10.h params.h
	$(CC) $(CFLAGS) hash.c fips202.c hash_address.c randombytes.c wots.c xmss_commons.c test/test_wots.c -o $@ -lcrypto -lm

test/test_xmss_core_XMSS_%: params_XMSS_%.h hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c test/test_xmss_core.c hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core.h xmss_commons.h
	ln -sf params_XMSS_$(patsubst test/test_xmss_core_XMSS_%,%,$@).h params.h
	$(CC) $(CFLAGS) hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c test/test_xmss_core.c -o $@ -lcrypto -lm

test/test_xmss_core_fast_XMSS_%: params_XMSS_%.h hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core_fast.c xmss_commons.c test/test_xmss_core_fast.c hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core_fast.h xmss_commons.h
	ln -sf params_XMSS_$(patsubst test/test_xmss_core_fast_XMSS_%,%,$@).h params.h
	$(CC) $(CFLAGS) hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core_fast.c xmss_commons.c test/test_xmss_core_fast.c -o $@ -lcrypto -lm

test/test_xmssmt_core_XMSSMT_%: params_XMSSMT_%.h hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c test/test_xmssmt_core.c hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core.h xmss_commons.h
	ln -sf params_XMSSMT_$(patsubst test/test_xmssmt_core_XMSSMT_%,%,$@).h params.h
	$(CC) $(CFLAGS) hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core.c xmss_commons.c test/test_xmssmt_core.c -o $@ -lcrypto -lm

test/test_xmssmt_core_fast_XMSSMT_%: params_XMSSMT_%.h hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core_fast.c xmss_commons.c test/test_xmssmt_core_fast.c hash.h fips202.h hash_address.h randombytes.h wots.h xmss_core_fast.h xmss_commons.h
	ln -sf params_XMSSMT_$(patsubst test/test_xmssmt_core_fast_XMSSMT_%,%,$@).h params.h
	$(CC) $(CFLAGS) hash.c fips202.c hash_address.c randombytes.c wots.c xmss_core_fast.c xmss_commons.c test/test_xmssmt_core_fast.c -o $@ -lcrypto -lm

clean:
	-rm *.o *.s
	-rm test/test_wots
	-rm test/test_xmss_core_XMSS*
	-rm test/test_xmss_core_fast_XMSS*
	-rm test/test_xmssmt_core_XMSS*
	-rm test/test_xmssmt_core_fast_XMSS*

distclean:
	-rm params.h
	-rm params_XMSS*.h