CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDLIBS ?= -lcrypto

ifneq (,$(findstring /ucrt64/,$(CC)))
CC_ENV = MSYSTEM=UCRT64 MSYSTEM_PREFIX=/ucrt64 PATH=/ucrt64/bin:/usr/bin:/bin
endif

library_tracker: library_tracker.c
	$(CC_ENV) $(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f library_tracker library_tracker.exe chain.dat library_private.pem
