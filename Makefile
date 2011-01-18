CFLAGS=-Wall -Werror -D_GNU_SOURCE -g
OBJS=reptyr.o ptrace.o attach.o

all: reptyr

reptyr: $(OBJS)

clean:
	rm -f reptyr $(OBJS)
