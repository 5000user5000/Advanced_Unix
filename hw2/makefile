# 編譯器與選項
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDFLAGS  := -lcapstone

# 來源檔
SRCS := sdb.cpp
OBJS := $(SRCS:.cpp=.o)

# 執行檔
TARGET := sdb

.PHONY: all clean

all: $(TARGET)

# 連結
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# C++ 檔編譯
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
