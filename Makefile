LDFLAGS= -lmbedtls -lmbedcrypto -lmbedx509
CFLAGS+= -g -Wall -Wno-unused -Wno-pointer-sign -fmax-errors=4 -I.

all: o/test o/im o/test-omemo

o:
	mkdir -p o

o/xmpp.o: xmpp.c | o
	$(CC) -c -o $@ $(CFLAGS) xmpp.c

o/test: o/xmpp.o
	$(CC) -DXMPP_RUNTEST -o o/test yxml.c xmpp.c $(CFLAGS) $(LDFLAGS)

o/test-omemo:
	$(CC) -o o/test-omemo curve25519.c omemo.c $(CFLAGS) $(LDFLAGS)

o/im: o/xmpp.o
	$(CC) -o o/im examples/im.c yxml.c o/xmpp.o $(CFLAGS) $(LDFLAGS) -DIM_NATIVE

LIBOMEMO_DIR=o/libomemo-c-0.5.0

$(LIBOMEMO_DIR).tar.gz: | o
	wget -O $@ https://github.com/dino/libomemo-c/archive/refs/tags/v0.5.0.tar.gz

$(LIBOMEMO_DIR): $(LIBOMEMO_DIR).tar.gz
	tar -xzf $< -C o
	patch -d $(LIBOMEMO_DIR) -p1 < build/amalg.patch

CURVE_DIR=$(LIBOMEMO_DIR)/src/curve25519
DEST_AMALG_C=$(CURVE_DIR)/amalg.c

# TODO patch: typedef crypto_*int* to stdint types, remove malloc from ed25519/additions?
curve25519.c: $(LIBOMEMO_DIR)
	cp build/amalg.c $(DEST_AMALG_C)
	echo "#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n#include <stdint.h>\n" > $@
	cpp $(DEST_AMALG_C) -I $(CURVE_DIR)/ed25519/nacl_includes/ -I $(CURVE_DIR)/ed25519/additions/ -I $(CURVE_DIR)/ed25519 \
		| awk '/# 5 .*amalg\.c.*/ {k=1} /# / {next} k {print $0}' >> $@

ESPIDF_DOCKERCMD=docker run --rm -v ${PWD}:/project -u $(shell id -u) -w /project -e HOME=/tmp espressif/idf idf.py

esp-im: | o
	 $(ESPIDF_DOCKERCMD) -B o/example-esp-im -C examples/esp-im build

size-esp-im: | o
	 $(ESPIDF_DOCKERCMD) -B o/example-esp-im -C examples/esp-im size-files

# TODO: remove LD_LIBRARY_PATH, it's needed for MbedTls being installed in /usr/local.
test: o/test
	LD_LIBRARY_PATH=/usr/local/lib ./o/test

test-omemo: o/test-omemo
	LD_LIBRARY_PATH=/usr/local/lib ./o/test-omemo

runim: o/im
	LD_LIBRARY_PATH=/usr/local/lib rlwrap ./o/im

prosody:
	docker-compose -f test/docker-compose.yml up -d --build

stop-prosody:
	docker-compose -f test/docker-compose.yml down

.PHONY: all o/test test test-omemo o/test-omemo prosody o/im runim

clean:
	rm -rf o
