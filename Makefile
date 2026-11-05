CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c17 -Wall -Wextra -Wformat=2 -Wvla
# Warnings are errors only when asked (CI does this), so a newer compiler
# with new warnings does not break a normal build.
ifeq ($(WERROR),1)
CFLAGS += -Werror
endif
CPPFLAGS += -Isrc
LDFLAGS ?=
LDLIBS ?=

BIN := husk
SRCS := src/main.c src/container.c src/userns.c src/cgroup.c src/security.c src/network.c src/util.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean check rootfs

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

src/%.o: src/%.c src/husk.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

rootfs:
	tests/make-rootfs.sh

check: $(BIN)
	tests/smoke.sh

clean:
	rm -f $(BIN) $(OBJS)
