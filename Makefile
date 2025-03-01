CFLAGS+= -g -std=c99 -Wall -Wno-pointer-sign -fmax-errors=4 -I. \
		 -Wno-unused

all: o/test o/im o/test-omemo

o:
	mkdir -p o

o/xmpp.o: xmpp.c xmpp.h | o
	$(CC) -c -o $@ $(CFLAGS) xmpp.c

o/test: o/xmpp.o test/cacert.inc test/xmpp.c
	$(CC) -o $@ yxml.c test/xmpp.c $(CFLAGS) -lmbedcrypto -lmbedtls -lmbedx509

o/test-omemo: test/omemo.c omemo.c c25519.c omemo.h | o
	$(CC) -o $@ c25519.c test/omemo.c $(CFLAGS) -lmbedcrypto

o/im: o/xmpp.o examples/im.c test/cacert.inc omemo.c c25519.c omemo.h
	$(CC) -o $@ examples/im.c yxml.c omemo.c c25519.c o/xmpp.o $(CFLAGS) -DIM_NATIVE -lmbedcrypto -lmbedtls -lmbedx509 -lsqlite3

o/generatestore: test/generatestore.c omemo.c c25519.c omemo.h | o
	$(CC) -o $@ c25519.c omemo.c test/generatestore.c $(CFLAGS) -lmbedcrypto

test/localhost.crt:
	openssl req -new -x509 -key test/localhost.key -out $@ -days 3650 -config test/localhost.cnf

test/cacert.inc: test/localhost.crt
	(cat test/localhost.crt; printf "\0") | xxd -i -name cacert_pem > $@

test/store.inc: o/generatestore
	o/generatestore | xxd -i -name store > $@

ESP_DEV?=/dev/ttyUSB0

ifneq (,$(wildcard $(ESP_DEV)))
	ESP_DEVARG= --device=$(ESP_DEV)
endif

ESPIDF_DOCKERCMD=docker run -it --rm -v ${PWD}:/project -u $(shell id -u) -w /project -e HOME=/tmp $(ESP_DEVARG) espressif/idf idf.py -B o/example-esp-im -C examples/esp-im

.PHONY: esp-im
esp-im: | o
	$(ESPIDF_DOCKERCMD) build

.PHONY: size-esp-im
size-esp-im: | o
	$(ESPIDF_DOCKERCMD) size-files

.PHONY: esp-upload
esp-upload:
	$(ESPIDF_DOCKERCMD) flash

.PHONY: esp-console
esp-console:
	rlwrap -- socat - $(ESP_DEV),b115200,cfmakeraw,ignoreeof

.PHONY: esp-monitor
esp-monitor:
	$(ESPIDF_DOCKERCMD) monitor

.PHONY: test
test: o/test
	./o/test

.PHONY: test-omemo
test-omemo: o/test-omemo
	./o/test-omemo

define IM_INPUT
/login admin@localhost
adminpass
endef
export IM_INPUT

.PHONY: runim
runim: o/im
	rlwrap -P "$$IM_INPUT" ./o/im

.PHONY: start-prosody
start-prosody: test/localhost.crt
	docker-compose -f test/docker-compose.yml up -d --build

.PHONY: stop-prosody
stop-prosody:
	docker-compose -f test/docker-compose.yml down

test/bot-venv/:
	python -m venv test/bot-venv/
	./test/bot-venv/bin/pip install slixmpp==1.8.5
	./test/bot-venv/bin/pip install slixmpp-omemo==1.0.0

start-omemo-bot: | test/bot-venv/
	./test/bot-venv/bin/python test/bot-omemo.py

.PHONY: tags
tags:
	ctags-exuberant --c-kinds=+p -R --exclude=o --exclude=test/bot-venv

.PHONY: clean
clean:
	rm -rf o

.PHONY: full-clean
full-clean: clean
	rm -rf test/cacert.inc test/store.inc test/localhost.crt test/bot-venv
