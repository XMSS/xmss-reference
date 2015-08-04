CC=gcc
CFLAGS="-Wall"

debug:clean
	$(CC) $(CFLAGS) -g -o xmss_ref main.c
stable:clean
	$(CC) $(CFLAGS) -o xmss_ref main.c
clean:
	rm -vfr *~ xmss_ref
