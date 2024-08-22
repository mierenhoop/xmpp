CFLAGS+= -g -Wall -Wno-unused -Wno-pointer-sign -fmax-errors=4 -I.

all: o/test o/im o/test-omemo

o:
	mkdir -p o

o/xmpp.o: xmpp.c | o
	$(CC) -c -o $@ $(CFLAGS) xmpp.c

# TODO: when we eventually move away from integration tests in
# test/xmpp.c (keep those integrations tests in the IM example), we can
# remove mbedtls and mbedx509
o/test: o/xmpp.o test/cacert.inc
	$(CC) -o o/test yxml.c test/xmpp.c $(CFLAGS) -lmbedcrypto -lmbedtls -lmbedx509

o/test-omemo: test/omemo.c omemo.c c25519.c | o curve25519.c
	$(CC) -o o/test-omemo curve25519.c c25519.c test/omemo.c $(CFLAGS) -lmbedcrypto

o/im: o/xmpp.o examples/im.c test/cacert.inc omemo.c c25519.c
	$(CC) -o o/im examples/im.c yxml.c omemo.c c25519.c curve25519.c o/xmpp.o $(CFLAGS) -DIM_NATIVE -lmbedcrypto -lmbedtls -lmbedx509

LIBOMEMO_DIR=o/libomemo-c-0.5.0

CURVE_DIR=$(LIBOMEMO_DIR)/src/curve25519
DEST_AMALG_C=$(CURVE_DIR)/amalg.c

# TODO patch: typedef crypto_*int* to stdint types, remove malloc from ed25519/additions?
curve25519.c: | o
	wget -O $(LIBOMEMO_DIR).tar.gz https://github.com/dino/libomemo-c/archive/refs/tags/v0.5.0.tar.gz
	echo "03195a24ef7a86c339cdf9069d7f7569ed511feaf55e853bfcb797d2698ba983  $(LIBOMEMO_DIR).tar.gz" \
		| sha256sum -c -
	tar -xzf $(LIBOMEMO_DIR).tar.gz -C o
	patch -d $(LIBOMEMO_DIR) -p1 < build/amalg.patch
	cp build/amalg.c $(DEST_AMALG_C)
	echo "#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n#include <stdint.h>\n" > $@
	cpp $(DEST_AMALG_C) -I $(CURVE_DIR)/ed25519/nacl_includes/ -I $(CURVE_DIR)/ed25519/additions/ -I $(CURVE_DIR)/ed25519 \
		| awk '/# 5 .*amalg\.c.*/ {k=1} /# / {next} k {print $0}' >> $@

test/localhost.crt:
	openssl req -new -x509 -key test/localhost.key -out $@ -days 3650 -config test/localhost.cnf

test/cacert.inc: test/localhost.crt
	(cat test/localhost.crt; printf "\0") | xxd -i -name cacert_pem > $@

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

start-prosody: test/localhost.crt
	docker-compose -f test/docker-compose.yml up -d --build

stop-prosody:
	docker-compose -f test/docker-compose.yml down

.PHONY: start-prosody stop-prosody test test-omemo runim clean full-clean

clean:
	rm -rf o

full-clean: clean
	rm -f test/cacert.inc test/localhost.crt curve25519.c
