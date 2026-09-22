CC ?= gcc
CFLAGS ?= -O2 -pipe
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -fno-pie -fstack-protector-strong
LDFLAGS += -static -no-pie -Wl,-z,relro,-z,now

.PHONY: all clean
all: reclaim-approval
reclaim-approval: player_gate.c ../include/reclaim_v4_uapi.h
	$(CC) $(CFLAGS) -I../include player_gate.c -o $@ $(LDFLAGS) -lcrypto
clean:
	rm -f reclaim-approval
