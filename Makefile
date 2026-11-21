CC      := cc
CFLAGS  := -O2 -g -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS := 
LDLIBS  := -lmilter -lcrypto

TARGET  := build/mailermon-milter
SOURCE  := src/mailermon-milter.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE) | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDLIBS)

build:
	mkdir -p build

clean:
	rm -f $(TARGET)
