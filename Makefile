CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -Wextra -Wpedantic
LDLIBS =  -lcrypto

SOURCES = params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c
HEADERS = params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h

SOURCES_FAST = $(subst core,core_fast,$(SOURCES))
HEADERS_FAST = $(subst core,core_fast,$(HEADERS))

TESTS = test/test_wots \
		test/test_xmss_core \
		test/test_xmss_core_fast \
		test/test_xmss \
		test/test_xmssmt_core_fast \
		test/test_xmssmt_core \
		test/test_xmssmt \
		test/test_determinism \

UI = ui/xmss_keypair \
	 ui/xmss_sign \
	 ui/xmss_open \
	 ui/xmssmt_keypair \
	 ui/xmssmt_sign \
	 ui/xmssmt_open \

all: $(TESTS) $(UI)

.PHONY: clean

test/%_fast: test/%_fast.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/%: test/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/test_wots: params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_commons.c test/test_wots.c params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss_commons.h
	$(CC) $(CFLAGS) params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss_commons.c test/test_wots.c -o $@ -lcrypto

ui/xmss_%: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

ui/xmssmt_%: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

clean:
	-$(RM) $(TESTS)
	-$(RM) $(UI)
