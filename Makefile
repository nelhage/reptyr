CFLAGS=-Wall -Werror -D_GNU_SOURCE -g
STUB_CFLAGS=$(CFLAGS) -nostdlib -Wl,-r -fomit-frame-pointer

all: reptyr

reptyr: reptyr.o ptrace.o attach.o

stub.o: stub.c
	$(CC) -c $(STUB_CFLAGS) -o $@ $^
	! nm $@ | grep ' U '
