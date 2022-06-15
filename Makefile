CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -Wextra -Wpedantic #-fsanitize-address-use-after-return=always -fsanitize=address
LDLIBS = -lcrypto -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib

SOURCES = params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c
HEADERS = params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

TESTS = test/wots \
		test/oid \
		test/speed \
		test/xmss_determinism \
		test/xmss \
		test/xmss_fast \
		test/xmssmt \
		test/xmssmt_fast \
		test/maxsigsxmss \
		test/maxsigsxmssmt \
		test/nist_test

UI = ui/xmss_keypair \
	 ui/xmss_sign \
	 ui/xmss_open \
	 ui/xmssmt_keypair \
	 ui/xmssmt_sign \
	 ui/xmssmt_open \
	 ui/xmss_keypair_fast \
	 ui/xmss_sign_fast \
	 ui/xmss_open_fast \
	 ui/xmssmt_keypair_fast \
	 ui/xmssmt_sign_fast \
	 ui/xmssmt_open_fast \

all: tests ui

tests: $(TESTS)
ui: $(UI)

test: $(TESTS:=.exec)

.PHONY: clean test

test/%.exec: test/%
	@$<

test/nist_test: nist.c nist_test.c nist_params.h api.h $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) nist_test.c $< $(LDLIBS)

test/xmss_fast: test/xmss.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DXMSS_SIGNATURES=1024 $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/xmss: test/xmss.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/xmssmt_fast: test/xmss.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DXMSSMT -DXMSS_SIGNATURES=1024 $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/xmssmt: test/xmss.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

# test/speed: test/speed.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
# 	$(CC) -DXMSSMT -DXMSS_VARIANT=\"XMSSMT-SHA2_20/2_256\" $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/speed: test/speed.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DXMSS_SIGNATURES=64 $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/speedmt: test/speed.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DXMSSMT -DXMSS_SIGNATURES=64 $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/vectors: test/vectors.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)
	
test/maxsigsxmss: test/xmss_max_signatures.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/maxsigsxmssmt: test/xmss_max_signatures.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)
	
test/%: test/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

ui/xmss_%_fast: ui/%.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

ui/xmssmt_%_fast: ui/%.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

ui/xmss_%: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

ui/xmssmt_%: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

clean:
	-$(RM) $(TESTS)
	-$(RM) test/vectors
	-$(RM) $(UI)
