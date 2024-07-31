LDFLAGS= -lmbedtls -lmbedcrypto -lmbedx509
CFLAGS+= -g -Wall -Wno-unused -Wno-pointer-sign -fmax-errors=4 -I.

all: o/test o/im

o:
	mkdir -p o

o/xmpp.o: xmpp.c | o
	$(CC) -c -o $@ $(CFLAGS) xmpp.c

o/test: o/xmpp.o
	$(CC) -DXMPP_RUNTEST -o o/test yxml.c xmpp.c $(CFLAGS) $(LDFLAGS)

o/im: o/xmpp.o
	$(CC) -o o/im examples/im.c yxml.c o/xmpp.o $(CFLAGS) $(LDFLAGS) -DIM_NATIVE

ESPIDF_DOCKERCMD=docker run --rm -v ${PWD}:/project -u $(shell id -u) -w /project -e HOME=/tmp espressif/idf idf.py

esp-im: | o
	 $(ESPIDF_DOCKERCMD) -B o/example-esp-im -C examples/esp-im build

size-esp-im: | o
	 $(ESPIDF_DOCKERCMD) -B o/example-esp-im -C examples/esp-im size-files

test: o/test
	LD_LIBRARY_PATH=/usr/local/lib ./o/test

runim: o/im
	LD_LIBRARY_PATH=/usr/local/lib rlwrap ./o/im

prosody:
	docker-compose -f test/docker-compose.yml up -d --build

stop-prosody:
	docker-compose -f test/docker-compose.yml down

.PHONY: all o/test test prosody o/im runim

clean:
	rm -rf o
