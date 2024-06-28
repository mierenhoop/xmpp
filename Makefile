LDFLAGS= /usr/lib/x86_64-linux-gnu/libmbedcrypto.a

all:
	mkdir -p o
	$(CC) -I. -DXMPP_RUNTEST -o o/main yxml.c xmpp.c $(LDFLAGS)

run: all
	./o/main

.PHONY: all clean

clean:
	rm -rf o
