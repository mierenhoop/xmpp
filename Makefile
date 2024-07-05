LDFLAGS= -lmbedtls -lmbedcrypto -lmbedx509
CFLAGS+= -Wall -Wno-unused -Wno-pointer-sign

all:
	mkdir -p o
	$(CC) -I. -DXMPP_RUNTEST -o o/main yxml.c xmpp.c $(CFLAGS) $(LDFLAGS)

run: all
	./o/main

.PHONY: all clean

clean:
	rm -rf o
