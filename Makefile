CFLAGS+= -g -Wall -Wno-pointer-sign -fmax-errors=4 -I. \
		 -Wno-unused

all: o/test o/im o/test-omemo

o:
	mkdir -p o

o/xmpp.o: xmpp.c xmpp.h | o
	$(CC) -c -o $@ $(CFLAGS) xmpp.c

o/test: o/xmpp.o test/cacert.inc test/xmpp.c
	$(CC) -o o/test yxml.c test/xmpp.c $(CFLAGS) -lmbedcrypto -lmbedtls -lmbedx509

o/test-omemo: test/omemo.c omemo.c c25519.c | o curve25519.c
	$(CC) -o o/test-omemo curve25519.c c25519.c test/omemo.c $(CFLAGS) -lmbedcrypto

o/im: o/xmpp.o examples/im.c test/cacert.inc omemo.c c25519.c
	$(CC) -o o/im examples/im.c yxml.c omemo.c c25519.c curve25519.c o/xmpp.o $(CFLAGS) -DIM_NATIVE -lmbedcrypto -lmbedtls -lmbedx509

test/localhost.crt:
	openssl req -new -x509 -key test/localhost.key -out $@ -days 3650 -config test/localhost.cnf

test/cacert.inc: test/localhost.crt
	(cat test/localhost.crt; printf "\0") | xxd -i -name cacert_pem > $@

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

# can also monitor with $ rlwrap -- socat - /dev/ttyUSB0,b115200
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
	./test/bot-venv/bin/pip install slixmpp
	./test/bot-venv/bin/pip install slixmpp-omemo

start-omemo-bot: | test/bot-venv/
	./test/bot-venv/bin/python test/bot-omemo.py

.PHONY: tags
tags:
	ctags-exuberant -R --exclude=o --exclude=test/bot-venv

.PHONY: clean
clean:
	rm -rf o

.PHONY: full-clean
full-clean: clean
	rm -rf test/cacert.inc test/localhost.crt curve25519.c test/bot-venv
