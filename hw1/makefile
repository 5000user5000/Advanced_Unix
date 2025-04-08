CC = gcc
CFLAGS = -Wall -fPIC -O2 -ldl

all: libzpoline.so.1 libzpoline.so.2 libzpoline.so logger.so

libzpoline.so.1: libzpoline1.c
	$(CC) -Wall -O2 -fPIC -shared -o $@ $^

libzpoline.so.2: libzpoline2.c
	$(CC) $(CFLAGS) -shared -o $@ $^

libzpoline.so: libzpoline.c
	$(CC) $(CFLAGS) -shared -o $@ $^

logger.so: logger.c
	$(CC) $(CFLAGS) -shared -o $@ $^

clean:
	rm -f *.so
