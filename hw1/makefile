CC = gcc
CFLAGS = -Wall -O2 -fPIC -shared

all: libzpoline.so.1 libzpoline.so.2 libzpoline.so logger.so

libzpoline.so.1: libzpoline1.c
	$(CC) $(CFLAGS) -o $@ $^

libzpoline.so.2: libzpoline2.c
	$(CC) $(CFLAGS) -o $@ $^ -lopcodes

libzpoline.so: libzpoline.c
	$(CC) $(CFLAGS) -shared -o $@ $^

logger.so: logger.c
	$(CC) $(CFLAGS) -shared -o $@ $^

clean:
	rm -f *.so *.so.* *.o
