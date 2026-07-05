CC = gcc
CFLAGS = -O2 -Wall -Wextra
TARGET = wific
SRC = wific.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

help:
	@echo "make        - build wific"
	@echo "make clean  - remove binary"
	@echo "make install - install to /usr/local/bin"
	@echo "make uninstall - remove from system"

.PHONY: all clean install uninstall help
