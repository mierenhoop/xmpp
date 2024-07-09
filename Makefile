LDFLAGS= -lmbedtls -lmbedcrypto -lmbedx509
CFLAGS+= -Wall -Wno-unused -Wno-pointer-sign

all: o/test

o:
	mkdir -p o

o/main: | o
	$(CC) -I. -DXMPP_RUNTEST -o o/main yxml.c xmpp.c $(CFLAGS) $(LDFLAGS)

o/test: | o
	mkdir -p o
	$(CC) -I. -DXMPP_RUNTEST -o o/test yxml.c xmpp.c $(CFLAGS) $(LDFLAGS)

test: o/test
	./o/test

.PHONY: all o/main o/test test

clean:
	rm -rf o
