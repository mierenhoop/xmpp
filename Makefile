
all:
	mkdir -p o
	$(CC) -I. -o o/main main.c yxml.c

run: all
	./o/main

.PHONY: all clean

clean:
	rm -rf o
