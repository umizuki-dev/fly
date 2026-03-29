# fly - Makefile
# Optimized for performance and standard Linux installation.

CXX = g++
CXXFLAGS = -Wall -O3 -std=c++17
LIBS = -lcurl -lpthread

TARGET = fly
PREFIX = /usr/local

all: $(TARGET)

$(TARGET): main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o $(TARGET) $(LIBS)

static: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o $(TARGET)-static $(LIBS) -static

install: $(TARGET)
	install -D -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all install uninstall clean
