CFLAGS=-Wall -Werror
STUB_CFLAGS=$(CFLAGS) -nostdlib -Wl,-r -fomit-frame-pointer

all: reptyr stub.o

stub.o: stub.c
	$(CC) -c $(STUB_CFLAGS) -o $@ $^
	! nm $@ | grep ' U '
