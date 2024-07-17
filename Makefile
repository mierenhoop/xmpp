LDFLAGS= -lmbedtls -lmbedcrypto -lmbedx509
CFLAGS+= -g -Wall -Wno-unused -Wno-pointer-sign -fmax-errors=4

all: o/test o/im

o:
	mkdir -p o

o/main: | o
	$(CC) -I. -DXMPP_RUNTEST -o o/main yxml.c xmpp.c $(CFLAGS) $(LDFLAGS)

o/test: | o
	$(CC) -I. -DXMPP_RUNTEST -o o/test yxml.c xmpp.c $(CFLAGS) $(LDFLAGS)

o/im: | o
	$(CC) -I. -o o/im examples/im.c $(CFLAGS) $(LDFLAGS) -lsqlite3 -lreadline

test: o/test
	./o/test

runim: o/im
	./o/im

prosody:
	docker-compose -f test/docker-compose.yml up -d --build

stop-prosody:
	docker-compose -f test/docker-compose.yml down

.PHONY: all o/main o/test test prosody o/im runim

clean:
	rm -rf o
