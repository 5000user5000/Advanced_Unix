.PHONY: all clean run

CC = gcc
CFLAGS = -Wall -g -fPIC
SHARED_LIB = -lgotoku -L.
# 如果需要讓執行時能正確找到共享庫，可以加上 -Wl,-rpath,$(shell pwd)

SOURCE = gotoku.c
TARGET = gotoku.local

LIB = libgotoku_dummy.c
LIBFLAGS = -Wall -shared -fPIC
LIBTARGET = libgotoku.so

PRELOAD_LIB = libsolver.c
PRELOAD_LIBTARGET = libsolver.so

all: $(LIBTARGET) $(TARGET) $(PRELOAD_LIBTARGET)

$(TARGET): $(SOURCE) $(LIBTARGET)
	$(CC) $(CFLAGS) -o $@ $< $(SHARED_LIB) -ldl -Wl,-rpath,.

$(LIBTARGET): $(LIB)
	$(CC) $(LIBFLAGS) -g -o $@ $^

$(PRELOAD_LIBTARGET): $(PRELOAD_LIB) $(LIBTARGET)
	$(CC) $(LIBFLAGS) -g -ldl -lc -o $@ $^

run: all
	LD_LIBRARY_PATH=. LD_PRELOAD=./libsolver.so ./gotoku.local

clean:
	rm -f $(TARGET) $(LIBTARGET) $(PRELOAD_LIBTARGET)
