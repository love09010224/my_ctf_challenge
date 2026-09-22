CC ?= gcc
CFLAGS ?= -O2 -pipe
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -fno-pie -pthread
LDFLAGS += -static -no-pie -pthread
OFFICIAL_SHA256 := 4bf27c63ccf36a28e586765d7fcadf7617ce227425538be32bf3966dc298301d

.PHONY: all verify-official clean
all: exploit
exploit: exploit.c reclaim_v4_uapi.h
	$(CC) $(CFLAGS) exploit.c -o $@ $(LDFLAGS) -lcrypto
verify-official:
	@test -f exploit.official || { echo 'download reclaim-route-e-exploit from the GitHub Release as exploit.official' >&2; exit 1; }
	printf '%s  %s\n' '$(OFFICIAL_SHA256)' exploit.official | sha256sum -c -
clean:
	rm -f exploit
