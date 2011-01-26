CFLAGS=-Wall -Werror -D_GNU_SOURCE -g
OBJS=reptyr.o ptrace.o attach.o


all: reptyr

reptyr: $(OBJS)

attach.o: reptyr.h ptrace.h
reptyr.o: reptyr.h
ptrace.o: ptrace.h $(wildcard arch/*.h)

clean:
	rm -f reptyr $(OBJS)
