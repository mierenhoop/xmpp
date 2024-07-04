LDFLAGS= -lmbedtls -lmbedcrypto -lmbedx509

all:
	mkdir -p o
	$(CC) -I. -DXMPP_RUNTEST -o o/main yxml.c xmpp.c $(LDFLAGS)

run: all
	./o/main

.PHONY: all clean

clean:
	rm -rf o
