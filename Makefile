CFLAGS=-Wall -Werror -D_GNU_SOURCE -g
OBJS=reptyr.o ptrace.o attach.o
STUB_CFLAGS=$(CFLAGS) -nostdlib -Wl,-r -fomit-frame-pointer

all: reptyr

reptyr: $(OBJS)

clean:
	rm -f reptyr $(OBJS)

stub.o: stub.c
	$(CC) -c $(STUB_CFLAGS) -o $@ $^
	! nm $@ | grep ' U '
