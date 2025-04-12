CC = gcc
CFLAGS = -Wall -O2 -fPIC
SHARED_FLAGS = -shared

all: libzpoline.so.1 libzpoline.so.2 libzpoline.so libex3hook.so
#all: libzpoline.so.1 libzpoline.so.2 libzpoline.so libex3hook.so logger.so

# 原始的 libzpoline.so.1 版本，供 ex1 測試
libzpoline.so.1: libzpoline1.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $^

# 原始的 libzpoline.so.2 版本，供 ex2 測試（例如 leet 轉換 hook）
libzpoline.so.2: libzpoline2.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $^ -lopcodes

# 最終整合版，將 libzpoline1.c（採用 -DINTEGRATED_VERSION 關閉其初始化）
# 與 libzpoline2.c 一起編譯、連結成 libzpoline.so
libzpoline.so: libzpoline1.c libzpoline2.c
	$(CC) $(CFLAGS) -DINTEGRATED_VERSION -c libzpoline1.c -o libzpoline1.o
	$(CC) $(CFLAGS) -c libzpoline2.c -o libzpoline2.o -lopcodes
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ libzpoline1.o libzpoline2.o -lopcodes

# 編譯 ex3hook.c 生成 libex3hook.so（供 ex3 測試 hook 庫使用）
libex3hook.so: ex3hook.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $^

# logger.so 由 logger.c 編譯生成
logger.so: logger.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $^

clean:
	rm -f *.so *.so.* *.o
