CC ?= gcc
CFLAGS ?= -O2 -pipe
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -fno-pie -pthread
LDFLAGS += -static -no-pie -pthread
OFFICIAL_SHA256 := 063d9b4761e83ba2f26fbd03ad9593109e9bc48050798b81841b2de64a503729

.PHONY: all verify-official clean
all: exploit
exploit: exploit.c reclaim_v4_uapi.h kernel_offsets.h
	$(CC) $(CFLAGS) exploit.c -o $@ $(LDFLAGS)
verify-official:
	@test -f exploit.official || { echo 'download reclaim-route-a-exploit from the GitHub Release as exploit.official' >&2; exit 1; }
	printf '%s  %s\n' '$(OFFICIAL_SHA256)' exploit.official | sha256sum -c -
clean:
	rm -f exploit
