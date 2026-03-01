CXX     = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Iinclude

SRCDIR = src
SRCS   = $(wildcard $(SRCDIR)/*.cpp)
TARGET = app

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET)
