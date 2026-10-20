CC       = gcc
CFLAGS   = -Wall -Wextra -O2
CPPFLAGS = -Iinclude
BIN      = arpspoof
SRC      = $(wildcard src/*.c)
OBJ      = $(patsubst src/%.c,build/%.o,$(SRC))

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ)

build/%.o: src/%.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build:
	mkdir -p $@

install: $(BIN)
	sudo install -m 755 $(BIN) /usr/local/bin/$(BIN)
	sudo setcap cap_net_raw+ep /usr/local/bin/$(BIN)

clean:
	rm -f $(BIN) $(OBJ)
	rmdir build 2>/dev/null || true

.PHONY: all install clean