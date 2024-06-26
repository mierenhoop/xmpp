LDFLAGS= /usr/lib/x86_64-linux-gnu/libmbedcrypto.a

all:
	mkdir -p o
	$(CC) -I. -o o/main yxml.c test.c sasl.c $(LDFLAGS)

run: all
	./o/main

.PHONY: all clean

clean:
	rm -rf o
