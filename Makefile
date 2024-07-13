LDFLAGS= -lmbedtls -lmbedcrypto -lmbedx509
CFLAGS+= -g -Wall -Wno-unused -Wno-pointer-sign

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
	docker-compose -f test/docker-compose.yml up -d

stop-prosody:
	docker-compose -f test/docker-compose.yml rm -f

# append a nul byte
o/localhost.crt:
	sudo cat /var/lib/prosody/localhost.crt | awk '{print $0}END{printf "%s", "\0"}' > $@

o/cacert.h: o/localhost.crt
	xxd -i o/localhost.crt > $@

.PHONY: all o/main o/test test prosody o/im runim

clean:
	rm -rf o
